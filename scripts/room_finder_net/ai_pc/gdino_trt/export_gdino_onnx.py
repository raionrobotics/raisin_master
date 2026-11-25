#!/usr/bin/env python3
"""Export Grounding DINO (HF transformers) to ONNX with the prompt and the image size baked in (static shapes for TensorRT).

    python export_gdino_onnx.py --out gdino_1280x800.onnx [--model IDEA-Research/grounding-dino-base] [--w 1280 --h 800]

The perception node always sends one fixed prompt and 1280x800 frames, so the text branch is a constant and the only
input is pixel_values [1,3,H',W'] (the processor's resize of WxH: shortest side 800, longest <= 1333).
Outputs: logits [1,900,256], pred_boxes [1,900,4] (cx,cy,w,h normalised) -- what post_process_grounded_object_detection reads.
Also writes <out>.meta.json (prompt, input_ids, processed size) for the TensorRT server."""
import argparse
import json

import numpy as np
import torch
from PIL import Image
from transformers import AutoModelForZeroShotObjectDetection, AutoProcessor

PROMPT = "a navigational sign. a directional sign with arrows. a room number plate."


def bool_constants_to_cast(path):
    """TensorRT 10.3 (JetPack 6) rejects Bool Constant nodes ("Constant does not support output type Bool"):
    store them as uint8 and Cast to BOOL instead.  Returns the number of nodes rewritten."""
    import onnx
    from onnx import helper, numpy_helper
    m = onnx.load(path)
    nodes, n = [], 0
    for nd in m.graph.node:
        if nd.op_type == "Constant" and nd.attribute and nd.attribute[0].name == "value" \
                and nd.attribute[0].t.data_type == onnx.TensorProto.BOOL:
            v = numpy_helper.to_array(nd.attribute[0].t).astype(np.uint8)
            tmp = nd.output[0] + "_u8"
            nodes.append(helper.make_node("Constant", [], [tmp], value=numpy_helper.from_array(v, nd.output[0] + "_u8_value")))
            nodes.append(helper.make_node("Cast", [tmp], [nd.output[0]], to=onnx.TensorProto.BOOL))
            n += 1
        else:
            nodes.append(nd)
    del m.graph.node[:]
    m.graph.node.extend(nodes)
    onnx.save(m, path, save_as_external_data=False)
    return n


class Fixed(torch.nn.Module):
    def __init__(self, model, text, pixel_mask):
        super().__init__()
        self.m = model
        for k, v in text.items():
            self.register_buffer(k, v, persistent=False)
        self.register_buffer("pixel_mask", pixel_mask, persistent=False)

    def forward(self, pixel_values):
        o = self.m(pixel_values=pixel_values, input_ids=self.input_ids, attention_mask=self.attention_mask,
                   token_type_ids=self.token_type_ids, pixel_mask=self.pixel_mask, return_dict=True)
        return o.logits, o.pred_boxes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="IDEA-Research/grounding-dino-base")
    ap.add_argument("--out", default="gdino.onnx")
    ap.add_argument("--w", type=int, default=1280)
    ap.add_argument("--h", type=int, default=800)
    ap.add_argument("--prompt", default=PROMPT)
    ap.add_argument("--opset", type=int, default=17)
    a = ap.parse_args()
    proc = AutoProcessor.from_pretrained(a.model)
    model = AutoModelForZeroShotObjectDetection.from_pretrained(a.model).eval()
    img = Image.fromarray(np.random.randint(0, 255, (a.h, a.w, 3), np.uint8))
    inp = proc(images=img, text=a.prompt, return_tensors="pt")
    text = {k: inp[k] for k in ("input_ids", "attention_mask", "token_type_ids")}
    pv = inp["pixel_values"]
    print("pixel_values", tuple(pv.shape), "input_ids", tuple(text["input_ids"].shape))
    w = Fixed(model, text, inp["pixel_mask"]).eval()
    with torch.no_grad():
        ref = w(pv)
        torch.onnx.export(w, (pv,), a.out, input_names=["pixel_values"], output_names=["logits", "pred_boxes"],
                          opset_version=a.opset, do_constant_folding=True, dynamo=False)
    print("bool constants rewritten:", bool_constants_to_cast(a.out))
    json.dump({"model": a.model, "prompt": a.prompt, "input_ids": text["input_ids"].tolist(),
               "pixel_values_shape": list(pv.shape), "image_size": [a.w, a.h]}, open(a.out + ".meta.json", "w"))
    np.savez(a.out + ".check.npz", pixel_values=pv.numpy(), logits=ref[0].numpy(), pred_boxes=ref[1].numpy())
    print("wrote", a.out)


if __name__ == "__main__":
    main()
