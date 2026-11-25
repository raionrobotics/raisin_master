"""Closed-vocabulary YOLO backend, shaped like the open-vocabulary ones.

ReasonNav is built around an open-vocabulary detector: nodes publish a query
string ("a person, a door, a directional sign") and the detector answers with
boxes labelled by *query index*. This module keeps that contract while running
a fixed three-class YOLO11s underneath (src/yolo_door_detector), trained on the
KAIST incubation-centre corridors this rig actually walks.

Why bother: OWL-ViT and Grounding DINO both hunt "a door" from a text prompt at
100-400 ms a frame. The YOLO checkpoint was distilled from Grounding DINO's own
labels on this building and then hand-corrected, so it is both faster and more
accurate *here* -- at the cost of only ever knowing these three classes.

The mapping from query text to class is the whole trick. A query the checkpoint
was never trained on ("a person") maps to nothing and simply returns no boxes,
rather than throwing: vlm_nav swaps the query set at runtime (default set, then
"a room label" while inspecting a door) and must not crash on the transition.
"""

import os
import re

import numpy as np
import torch

# Class order is fixed by the checkpoint -- see src/yolo_door_detector/README.md.
CLASSES = ['room_label', 'directional_sign', 'door']

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WEIGHTS = os.environ.get(
    'REASONNAV_YOLO_WEIGHTS',
    '/home/raion/tips_ws/src/yolo_door_detector/weights/door_detector_round2.pt')

# Training resolution. The README is explicit that shrinking this costs
# room_label recall, which is the class we can least afford to lose.
DEFAULT_IMGSZ = int(os.environ.get('REASONNAV_YOLO_IMGSZ', '960'))
DEFAULT_IOU = float(os.environ.get('REASONNAV_YOLO_IOU', '0.6'))

# Callers tuned their thresholds against open-vocabulary logit scales -- the
# room-label inspection step hardcodes 0.04, which is a sensible bar for OWL-ViT
# and pure noise for a trained detector's sigmoid confidence. Clamp up so a
# stale threshold cannot flood the landmark database.
MIN_CONF = float(os.environ.get('REASONNAV_YOLO_MIN_CONF', '0.15'))

# Query phrases -> class id. Keys are compared after lowercasing, stripping
# punctuation/whitespace and dropping a leading article, so "a door", "Door",
# " a  door " and "doors" all land on the same class.
_ALIASES = {
    'door': 2,
    'doorway': 2,
    'directional sign': 1,
    'direction sign': 1,
    'sign': 1,
    'exit sign': 1,
    'room label': 0,
    'room number': 0,
    'room sign': 0,
    'door number': 0,
    'room label sign': 0,
}

_COLORS = [
    (0, 0, 255),      # room_label
    (0, 200, 255),    # directional_sign
    (0, 255, 0),      # door
    (255, 0, 255),
    (255, 255, 0),
]


def _normalise(query):
    """Reduce a free-text query to a canonical phrase for alias lookup."""
    q = re.sub(r'[^a-z0-9 ]+', ' ', str(query).lower())
    q = re.sub(r'\s+', ' ', q).strip()
    for article in ('a ', 'an ', 'the '):
        if q.startswith(article):
            q = q[len(article):]
            break
    # "doors" -> "door", but leave "directional sign" alone.
    if q.endswith('s') and not q.endswith('ss'):
        singular = q[:-1]
        if singular in _ALIASES:
            return singular
    return q


def query_to_class(query):
    """Class id for a query, or None when the checkpoint cannot serve it."""
    q = _normalise(query)
    if q in _ALIASES:
        return _ALIASES[q]
    # Fall back to substring matching so "a glass door on the left" still works.
    for phrase, cid in sorted(_ALIASES.items(), key=lambda kv: -len(kv[0])):
        if phrase in q:
            return cid
    return None


class YoloOutput:
    """Detection results, shaped like NanoOWL's OwlDecodeOutput."""

    def __init__(self, labels, boxes, scores):
        self.labels = labels
        self.boxes = boxes
        self.scores = scores

    def __len__(self):
        return len(self.labels)


class YoloPredictor:
    def __init__(self, model_name=DEFAULT_WEIGHTS, image_encoder_engine=None,
                 device=None, imgsz=DEFAULT_IMGSZ, iou=DEFAULT_IOU):
        # image_encoder_engine is a NanoOWL/TensorRT concept; accepted and
        # ignored so the ROS parameter needs no special case.
        from ultralytics import YOLO

        # detection.py passes the OWL-ViT default through when nothing was set
        # explicitly; that is a HuggingFace repo id, not a checkpoint path.
        if not model_name or not str(model_name).endswith(('.pt', '.onnx', '.engine')):
            model_name = DEFAULT_WEIGHTS
        if not os.path.exists(model_name):
            raise FileNotFoundError(
                f'YOLO weights not found: {model_name}. Set '
                'REASONNAV_YOLO_WEIGHTS to the .pt file.')

        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = YOLO(model_name)
        self.imgsz = imgsz
        self.iou = iou
        self._cache = {}
        print(f'[yolo] {os.path.basename(model_name)} on {self.device} '
              f'imgsz={imgsz} classes={CLASSES}')

    def encode_text(self, text):
        """Resolve the query list to class ids once and cache it.

        Returns a list the same length as `text`, holding a class id or None
        per query. The open-vocabulary backends cache tokenised prompts here;
        this is the closed-vocabulary equivalent.
        """
        key = tuple(text)
        if key not in self._cache:
            self._cache[key] = [query_to_class(q) for q in text]
        return self._cache[key]

    @torch.no_grad()
    def predict(self, image, text, text_encodings=None, threshold=0.25,
                pad_square=False):
        """Run detection.

        `threshold` may be a scalar or one value per query, matching the other
        backends. Labels come back as indices into `text`, never as YOLO class
        ids, because detection.py names every detection with
        `text_queries[label_index]`.
        """
        queries = list(text)
        class_of_query = (list(text_encodings) if text_encodings is not None
                          else self.encode_text(queries))

        if isinstance(threshold, (int, float)):
            per_query = [float(threshold)] * len(queries)
        else:
            # Arrives from ROS as Float32MultiArray.data, i.e. an array.array.
            per_query = [float(t) for t in threshold]
            if len(per_query) < len(queries):
                per_query += [per_query[-1] if per_query else 0.25] * (
                    len(queries) - len(per_query))
        per_query = [max(MIN_CONF, t) for t in per_query]

        # One class can be asked for by several queries; keep the loosest
        # threshold per class for the NMS pass and re-filter per query after.
        wanted = {}
        for qi, cid in enumerate(class_of_query):
            if cid is None:
                continue
            wanted.setdefault(cid, []).append(qi)
        if not wanted:
            # Every query is outside this checkpoint's vocabulary (e.g. the
            # person-only query used by the HRI path). Nothing to run.
            return YoloOutput(labels=[], boxes=[], scores=[])

        floor = min(per_query[qi] for qis in wanted.values() for qi in qis)

        results = self.model.predict(
            source=image,
            imgsz=self.imgsz,
            conf=max(0.001, floor),
            iou=self.iou,
            device=self.device,
            classes=sorted(wanted.keys()),
            verbose=False,
        )[0]

        labels, boxes, scores = [], [], []
        if results.boxes is None or len(results.boxes) == 0:
            return YoloOutput(labels=labels, boxes=boxes, scores=scores)

        cls = results.boxes.cls.cpu().numpy().astype(int)
        conf = results.boxes.conf.cpu().numpy()
        xyxy = results.boxes.xyxy.cpu().numpy()

        for cid, score, box in zip(cls, conf, xyxy):
            for qi in wanted.get(int(cid), ()):
                if float(score) < per_query[qi]:
                    continue
                labels.append(qi)
                boxes.append([float(v) for v in box])
                scores.append(float(score))

        return YoloOutput(labels=labels, boxes=boxes, scores=scores)


def draw_owl_output(image, output, text, draw_text=True):
    """Draw boxes onto a PIL image, matching the other backends' signature."""
    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    for i in range(len(output.labels)):
        idx = int(output.labels[i])
        box = output.boxes[i]
        colour = _COLORS[idx % len(_COLORS)]
        draw.rectangle([box[0], box[1], box[2], box[3]], outline=colour, width=3)
        if draw_text:
            name = text[idx] if idx < len(text) else str(idx)
            score = output.scores[i] if i < len(output.scores) else 0.0
            draw.text((box[0] + 4, max(0.0, box[1] - 12)),
                      f'{str(name).strip()} {score:.2f}', fill=colour)
    return image
