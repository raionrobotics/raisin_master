#!/usr/bin/env python3
"""Aggregate the policy comparison (run_policy_matrix.sh) into a markdown table.

    python3 policy_report.py pm1 [--base full1]

Reads log/reasonnav_sim/trials/<prefix>_<condition>.jsonl for every condition found and prints, per condition, strict success,
room-found rate, time and path length (over found rooms), SPL-like efficiency and a per-room grid. --base adds the full1 result of the
same rooms (different VLM and 1200 s cap, shown for reference only).
"""
import argparse, glob, json, math, os, statistics as st

WS = os.path.expanduser("~/raisin_ws")
ORDER = ["rule", "belief", "belief_signs", "belief_vlm", "rn_ours", "rn"]
NAMES = {"rule": "rule-based (text-parsed signs)", "belief": "paper-style belief grid (no signs)",
         "belief_signs": "belief grid + signs (text prompt + cue wedges)", "belief_vlm": "belief grid, map picture + sign photos (all by the VLM)", "rn_ours": "modified ReasonNav (vlm_nav) with OUR detection + plate/sign reading", "rn": "modified ReasonNav (vlm_nav, OWL-ViT, 1280x960 front camera)"}


def load(path):
    return {r["target"]: r for r in map(json.loads, open(path))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prefix")
    ap.add_argument("--base", default="full1")
    a = ap.parse_args()
    conds = {}
    for c in ORDER:
        p = f"{WS}/log/reasonnav_sim/trials/{a.prefix}_{c}.jsonl"
        if os.path.exists(p):
            conds[c] = load(p)
    base = load(f"{WS}/log/reasonnav_sim/trials/{a.base}.jsonl") if os.path.exists(f"{WS}/log/reasonnav_sim/trials/{a.base}.jsonl") else {}
    rooms = sorted({t for d in conds.values() for t in d})
    out = [f"## Policy comparison `{a.prefix}` ({len(rooms)} rooms, 900 s cap, same VLM for all pipelines except ReasonNav)", "",
           "| condition | rooms done | strict success | room found | median s (found) | mean path m (found) | mean s incl. failures (cap 900) |", "|---|---|---|---|---|---|---|"]
    for c, d in conds.items():
        rows = list(d.values())
        ok = [r for r in rows if r.get("success")]
        found = [r for r in rows if r.get("claimed") and r.get("dist_label_to_gt") is not None and r["dist_label_to_gt"] < 3.0]
        t = [r["elapsed_s"] for r in found]
        pl = [r["path_len_m"] for r in found]
        allt = [r["elapsed_s"] if r.get("claimed") else 900.0 for r in rows]
        out.append(f"| {NAMES[c]} | {len(rows)} | {len(ok)} ({100 * len(ok) // max(1, len(rows))}%) | {len(found)} | "
                   f"{st.median(t):.0f} | {st.mean(pl):.0f} | {st.mean(allt):.0f} |" if t else
                   f"| {NAMES[c]} | {len(rows)} | {len(ok)} | 0 | - | - | {st.mean(allt):.0f} |")
    out += ["", "### Per room (result, seconds, path m)", "", "| room | " + " | ".join(conds) + (" | full1 (reference) |" if base else " |"),
            "|---|" + "---|" * (len(conds) + (1 if base else 0))]
    for t in rooms:
        cells = []
        for c, d in conds.items():
            r = d.get(t)
            cells.append("-" if r is None else (f"ok {r['elapsed_s']:.0f}s {r['path_len_m']:.0f}m" if r.get("success") else
                                                (f"claimed, far {r['elapsed_s']:.0f}s" if r.get("claimed") else f"fail {r['path_len_m']:.0f}m")))
        if base:
            r = base.get(t)
            cells.append("-" if r is None else (f"ok {r['elapsed_s']:.0f}s {r['path_len_m']:.0f}m" if r.get("success") else "fail"))
        out.append(f"| {t} | " + " | ".join(cells) + " |")
    print("\n".join(out))


if __name__ == "__main__":
    main()
