"""PyTorch/transformers backend for OWL-ViT, replacing NanoOWL's TensorRT path.

NanoOWL exists to run OWL-ViT fast on Jetson via a prebuilt TensorRT image-encoder
engine. On a desktop/laptop RTX GPU that engine buys us little and costs a lot to
build (and Blackwell/sm_120 support in TensorRT is still awkward), so we run the
same `google/owlvit-base-patch32` weights directly in PyTorch.

This module mirrors the small slice of the NanoOWL API that
`mm_dev.obj_det.detection` actually uses:

    OwlPredictor(model_name, image_encoder_engine=None)
        .encode_text(texts)                     -> cached text embeddings
        .predict(image, text, text_encodings, threshold, pad_square) -> OwlOutput
    draw_owl_output(image, output, text, draw_text=True) -> PIL.Image

`OwlOutput` exposes `.labels` (index into the query list), `.boxes` (xyxy in pixel
coords) and `.scores`, which is exactly what the caller iterates over.
"""

from PIL import Image, ImageDraw

import torch
from transformers import OwlViTForObjectDetection, OwlViTProcessor


# Same palette NanoOWL's drawing helper uses, so visualisations look familiar.
_COLORS = [
    (255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0),
    (255, 0, 255), (0, 255, 255), (255, 128, 0), (128, 0, 255),
]


class OwlOutput:
    """Detection results, shaped like NanoOWL's OwlDecodeOutput."""

    def __init__(self, labels, boxes, scores):
        self.labels = labels
        self.boxes = boxes
        self.scores = scores

    def __len__(self):
        return len(self.labels)


class OwlPredictor:
    def __init__(self, model_name='google/owlvit-base-patch32',
                 image_encoder_engine=None, device=None):
        # image_encoder_engine is TensorRT-only; accepted and ignored so the
        # caller (and its ROS parameter) needs no change.
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.processor = OwlViTProcessor.from_pretrained(model_name)
        self.model = OwlViTForObjectDetection.from_pretrained(model_name)
        self.model = self.model.to(self.device).eval()
        self._text_cache = {}

    def encode_text(self, text):
        """Tokenise and cache the query list.

        NanoOWL returns reusable text embeddings here. Tokenisation is the cheap
        part for OWL-ViT and HF wants text+image together at forward time, so we
        cache the tokenised form and key predictions off it.
        """
        key = tuple(text)
        if key not in self._text_cache:
            self._text_cache[key] = list(text)
        return self._text_cache[key]

    @torch.no_grad()
    def predict(self, image, text, text_encodings=None, threshold=0.1,
                pad_square=False):
        """Run detection.

        `threshold` may be a scalar or a per-query list (the caller passes one
        threshold per search term); a list is applied per predicted label.
        """
        queries = list(text_encodings) if text_encodings is not None else list(text)

        inputs = self.processor(text=[queries], images=image, return_tensors='pt')
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        outputs = self.model(**inputs)

        target_sizes = torch.tensor([[image.height, image.width]], device=self.device)
        post = getattr(self.processor, 'post_process_grounded_object_detection', None)
        if post is None:  # older transformers
            post = self.processor.post_process_object_detection
        # Filter per-label below instead of here, so a list threshold works.
        results = post(outputs=outputs, target_sizes=target_sizes, threshold=0.0)[0]

        # A per-query threshold arrives from ROS as Float32MultiArray.data, i.e.
        # an array.array -- not a list -- so accept any indexable sequence.
        if isinstance(threshold, (int, float)):
            per_label = None
        else:
            per_label = [float(t) for t in threshold]

        labels, boxes, scores = [], [], []
        for score, label, box in zip(results['scores'], results['labels'], results['boxes']):
            idx = int(label)
            if per_label is not None:
                if idx >= len(per_label):
                    continue
                thr = per_label[idx]
            else:
                thr = float(threshold)
            if float(score) < thr:
                continue
            labels.append(idx)
            boxes.append([float(v) for v in box.tolist()])
            scores.append(float(score))

        return OwlOutput(labels=labels, boxes=boxes, scores=scores)


def draw_owl_output(image, output, text, draw_text=True):
    """Draw boxes/labels onto a copy of `image` and return it."""
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
