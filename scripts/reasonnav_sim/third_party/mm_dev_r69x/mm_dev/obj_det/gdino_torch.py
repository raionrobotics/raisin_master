"""Grounding DINO backend, interface-compatible with the OWL-ViT one.

Exposes the same small surface `mm_dev.obj_det.detection` uses, so the two are
swappable without touching the caller:

    Predictor(model_name).encode_text(texts) -> cached prompt
                         .predict(image, text, text_encodings, threshold)
                             -> OwlOutput(.labels, .boxes, .scores)
    draw_owl_output(image, output, text, draw_text=True) -> PIL.Image

Two things differ from OWL-ViT and are handled here rather than in the caller:

* Grounding DINO takes one period-separated prompt ("a person. a door.")
  instead of a list, and gives back the matched *text*, not an index into the
  list. `.labels` is mapped back to the query index so the caller's
  `text_queries[label_index]` keeps working.
* Its scores are calibrated differently -- box_threshold 0.25-0.35 is the usual
  operating range, where OWL-ViT wanted per-class values around 0.05-0.4. The
  per-query thresholds the caller passes are still applied, after a coarse
  prefilter at the lowest of them.
"""

import torch
from PIL import Image, ImageDraw
from transformers import AutoModelForZeroShotObjectDetection, AutoProcessor

from mm_dev.obj_det.owl_torch import OwlOutput, _COLORS

DEFAULT_MODEL = 'IDEA-Research/grounding-dino-base'


class GroundingDinoPredictor:
    def __init__(self, model_name=DEFAULT_MODEL, image_encoder_engine=None,
                 device=None, text_threshold=0.25):
        # image_encoder_engine is a NanoOWL/TensorRT concept; accepted and
        # ignored so the ROS parameter needs no special case.
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.processor = AutoProcessor.from_pretrained(model_name)
        self.model = AutoModelForZeroShotObjectDetection.from_pretrained(model_name)
        self.model = self.model.to(self.device).eval()
        self.text_threshold = text_threshold
        self._cache = {}

    def encode_text(self, text):
        """Build (and cache) the period-separated prompt Grounding DINO wants."""
        key = tuple(text)
        if key not in self._cache:
            queries = [t.strip().strip('.').lower() for t in text]
            self._cache[key] = (queries, '. '.join(queries) + '.')
        return self._cache[key]

    @torch.no_grad()
    def predict(self, image, text, text_encodings=None, threshold=0.25,
                pad_square=False):
        if text_encodings is None:
            text_encodings = self.encode_text(text)
        queries, prompt = text_encodings

        inputs = self.processor(images=image, text=prompt, return_tensors='pt')
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        outputs = self.model(**inputs)

        if isinstance(threshold, (int, float)):
            per_label, floor = None, float(threshold)
        else:
            per_label = [float(t) for t in threshold]
            floor = min(per_label) if per_label else 0.25

        results = self.processor.post_process_grounded_object_detection(
            outputs,
            input_ids=inputs['input_ids'],
            threshold=floor,
            text_threshold=self.text_threshold,
            target_sizes=[(image.height, image.width)],
        )[0]

        labels, boxes, scores = [], [], []
        for score, phrase, box in zip(results['scores'],
                                      results.get('text_labels', results.get('labels', [])),
                                      results['boxes']):
            idx = self._query_index(str(phrase), queries)
            if idx is None:
                continue
            if per_label is not None:
                if idx >= len(per_label) or float(score) < per_label[idx]:
                    continue
            labels.append(idx)
            boxes.append([float(v) for v in box.tolist()])
            scores.append(float(score))
        return OwlOutput(labels=labels, boxes=boxes, scores=scores)

    @staticmethod
    def _query_index(phrase, queries):
        """Map a matched phrase back to the index of the query that produced it.

        Grounding DINO returns whatever span of the prompt matched, which is
        often a fragment ("door" for "a door"), so fall back to substring
        containment either way round.
        """
        p = phrase.strip().strip('.').lower()
        if not p:
            return None
        for i, q in enumerate(queries):
            if p == q:
                return i
        for i, q in enumerate(queries):
            if p in q or q in p:
                return i
        return None


def draw_owl_output(image, output, text, draw_text=True):
    image = image.copy()
    draw = ImageDraw.Draw(image)
    for i in range(len(output.labels)):
        label = int(output.labels[i])
        box = output.boxes[i]
        color = _COLORS[label % len(_COLORS)]
        draw.rectangle(((box[0], box[1]), (box[2], box[3])), outline=color, width=3)
        if draw_text:
            name = text[label].strip() if label < len(text) else str(label)
            draw.text((box[0] + 4, max(0, box[1] - 12)),
                      f'{name} {output.scores[i]:.2f}', fill=color)
    return image
