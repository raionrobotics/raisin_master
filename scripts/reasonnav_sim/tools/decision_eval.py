#!/usr/bin/env python3
"""Offline comparison of landmark-choice strategies on recorded finder decisions (no simulator needed).

    env -u OPENAI_API_KEY python3 decision_eval.py <trial.jsonl-tag> [--n 120] [--variants R,A,B,C] [--seed 0]

Every finder run writes finder/decisions/dNNN.{json,npz}: the candidate list (with the rule-based score), robot pose, registry,
map and the sign photos seen so far. For each snapshot the ground-truth plate of the target gives an oracle:
    regret(choice) = dist(choice, GT) - min over candidates dist(c, GT)      (0 = picked the candidate closest to the room)
Strategies:
    R  rule-based top-1 (what the finder does)
    A  VLM, all candidates, images only (map + sign photos), plain question
    B  VLM, all candidates, + program-computed range check + arrow table + step-by-step instructions
    C  VLM restricted to the rule-based top-3, prompt as B
The candidate order shown to the VLM is shuffled so that it cannot just follow the rule's ranking.
"""
import argparse, glob, json, math, os, random, sys, statistics as st

import cv2
import numpy as np

sys.path.insert(0, "/home/user/tips_ws/src/ReasonNav/src/mm_dev")
from mm_dev.room_finder import decide  # noqa: E402
from mm_dev.room_finder.vlm import VLM  # noqa: E402

WS = os.path.expanduser("~/raisin_ws")
G = json.load(open(f"{WS}/scripts/reasonnav_sim/gt/hospital_rooms.json"))
SP = G["spawn_xy"]


class Grid:
    def __init__(self, npz):
        d = np.load(npz)
        self.h, self.w = [int(v) for v in d["shape"]]
        n = self.h * self.w
        self.occ = np.unpackbits(d["occ"])[:n].reshape(self.h, self.w).astype(bool)
        self.free = np.unpackbits(d["free"])[:n].reshape(self.h, self.w).astype(bool)
        self.x0, self.y0, self.res = [float(v) for v in d["geo"]]


def gt_xy(room):
    x, y = G["rooms"][str(room)]["xy"]
    return x - SP[0], y - SP[1]


def load_snapshots(tag):
    snaps = []
    for l in open(f"{WS}/log/reasonnav_sim/trials/{tag}.jsonl"):
        row = json.loads(l)
        for j in sorted(glob.glob(row["logdir"] + "/finder/decisions/d*.json")):
            snaps.append((row, j))
    return snaps


def sign_images(rec, logdir, with_cues=True):
    out = []
    for s in rec["reg"]["signs"]:
        if with_cues and not s["cues"]:
            continue
        names = rec["sign_crops"].get(str(s["id"]), [])
        if not names:
            continue
        im = cv2.imread(f"{logdir}/perception/crops/{names[-1]}")
        if im is not None:
            out.append((s, im))
    # signs whose cues contain the target first, then the others; at most 2 photos
    T = int(rec["target"])
    out.sort(key=lambda si: not any(c.get("lo") is not None and c["lo"] <= T <= c["hi"] for c in si[0]["cues"]))
    return out[:2]


def run_variant(v, rec, grid, logdir, vlm, rng):
    top = rec["cands"]
    pool = top[:3] if v == "C" else top
    order = list(range(len(pool)))
    rng.shuffle(order)
    cands = [{"id": k + 1, "note": pool[i]["note"], "xy": tuple(pool[i]["xy"]), "kind": pool[i]["kind"], "i": i} for k, i in enumerate(order)]
    robot = rec["robot"]
    reg = rec["reg"]
    sims = sign_images(rec, logdir)
    ov = decide.render_overview(grid, reg, cands, robot, rec["target"])
    prompt = decide.build_prompt(rec["target"], cands, robot, reg, sims,
                                 check=(v != "A"), table=(v != "A"), steps=(v != "A"))
    ch, reason, raw = vlm.choose_landmark([ov] + [im for _, im in sims], prompt)
    pick = next((c["i"] for c in cands if c["id"] == ch), None)
    return pick, reason


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tag")
    ap.add_argument("--n", type=int, default=120)
    ap.add_argument("--variants", default="R,A,B,C")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    snaps = load_snapshots(a.tag)
    # informative snapshots: at least two candidates of different kinds, and at least one sign with cues for the VLM variants
    rng.shuffle(snaps)
    vlm = VLM() if any(v != "R" for v in a.variants.split(",")) else None
    res = {v: [] for v in a.variants.split(",")}
    if "P" in res:
        res.update({"P+%d" % w: [] for w in (25, 60)})
    FUSE = (10, 25, 50)       # rule score + w if the VLM (variant B) picked the candidate
    if "B" in res:
        res.update({"B+%d" % w: [] for w in FUSE})
    log = []
    done = 0
    for row, jpath in snaps:
        rec = json.load(open(jpath))
        if rec["rule_choice"] is None:
            continue
        logdir = row["logdir"]
        grid = Grid(jpath[:-5] + ".npz")
        gx, gy = gt_xy(int(rec["target"]))
        d = [math.hypot(c["xy"][0] - gx, c["xy"][1] - gy) for c in rec["cands"]]
        dmin = min(d)
        out = {"snap": jpath, "target": rec["target"], "d": [round(x, 1) for x in d]}
        for v in [x for x in res if "+" not in x]:
            pick = rec["rule_choice"] if v == "R" else None
            reason = ""
            if v == "P":      # paper style: text-only region prediction, then candidates inside the predicted half-plane are favoured
                try:
                    labs = [(l["number"], l["x"], l["y"]) for l in rec["reg"]["labels"] if l.get("number")]
                    gm_known = grid.occ | grid.free
                    rr, cc = np.nonzero(gm_known)
                    ext = (grid.x0 + cc.min() * grid.res, grid.x0 + cc.max() * grid.res, grid.y0 + rr.min() * grid.res, grid.y0 + rr.max() * grid.res)
                    raw = vlm.ask_text(decide.paper_prompt(rec["target"], labs, rec["robot"], ext), 500)
                    region = vlm._json(raw)["region"]
                except Exception as e:  # noqa: BLE001
                    print("error", repr(e)[:100]); continue
                inside = [decide.in_region(region, rec["robot"], c["xy"]) for c in rec["cands"]]
                for w in (25, 60):
                    sc = [c["score"] + (w if inside[i] else 0) for i, c in enumerate(rec["cands"])]
                    fp = max(range(len(sc)), key=lambda i: sc[i])
                    res["P+%d" % w].append((d[fp] - dmin, d[fp] == dmin, d[fp] - d[rec["rule_choice"]]))
                    out["P+%d" % w] = {"pick": fp, "regret": round(d[fp] - dmin, 1), "region": region}
                pool = [i for i in range(len(inside)) if inside[i]] or list(range(len(inside)))
                pick = min(pool, key=lambda i: math.hypot(rec["cands"][i]["xy"][0] - rec["robot"][0], rec["cands"][i]["xy"][1] - rec["robot"][1]))
                reason = "region=%s" % region
            elif v != "R":
                try:
                    pick, reason = run_variant(v, rec, grid, logdir, vlm, rng)
                except Exception as e:  # noqa: BLE001
                    print("error", repr(e)[:100]); continue
            if pick is None:
                continue
            res[v].append((d[pick] - dmin, d[pick] == dmin, d[pick] - d[rec["rule_choice"]]))
            out[v] = {"pick": pick, "regret": round(d[pick] - dmin, 1), "reason": reason[:300]}
            if v == "B":
                for w in FUSE:
                    sc = [c["score"] + (w if i == pick else 0) for i, c in enumerate(rec["cands"])]
                    fp = max(range(len(sc)), key=lambda i: sc[i])
                    res["B+%d" % w].append((d[fp] - dmin, d[fp] == dmin, d[fp] - d[rec["rule_choice"]]))
        log.append(out)
        done += 1
        if done >= a.n:
            break
    print(f"{done} snapshots\n")
    print("variant | n | mean regret m | median regret m | picked the closest candidate | within 5 m of the best")
    for v, r in res.items():
        if r:
            reg_ = [x[0] for x in r]
            print(f"{v} | {len(r)} | {st.mean(reg_):.1f} | {st.median(reg_):.1f} | {100 * sum(x[1] for x in r) / len(r):.0f}% | {100 * sum(x <= 5 for x in reg_) / len(r):.0f}%")
    json.dump(log, open(f"{WS}/log/reasonnav_sim/trials/decision_eval_{a.tag}.json", "w"), indent=1)


if __name__ == "__main__":
    main()
