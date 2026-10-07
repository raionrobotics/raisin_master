#!/usr/bin/env python3
"""Summarise a full room-finding evaluation: python3 eval_summary.py <tag> [--out DIR]

Reads log/reasonnav_sim/trials/<tag>.jsonl (one row per room, written by run_trials.py) and writes
<out>/results.csv and <out>/summary.md with per-room results and statistics.

Two success definitions are reported, because the strict one mixes two things:
  strict  : claimed label within 3 m of the GT plate AND robot within 4 m of it   (the run_trials.py criterion)
  room ok : the finder claimed the right plate (label within 3 m of GT)           (did it find the room?)
"""
import argparse, csv, json, math, os, statistics as st

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.expanduser("~/raisin_ws")
REGIONS = (("west wing 3001-3013", 3001, 3013), ("middle 3014-3024", 3014, 3024), ("east 3025-3041", 3025, 3041))


def q(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(p * len(v)))] if v else float("nan")


def stats(rows, name):
    n = len(rows)
    strict = [r for r in rows if r.get("success")]
    room = [r for r in rows if r.get("dist_label_to_gt") is not None and r["dist_label_to_gt"] < 3.0 and r.get("claimed")]
    t = [r["elapsed_s"] for r in room]
    d = [r["path_len_m"] for r in room]
    line = f"| {name} | {n} | {len(strict)} ({100 * len(strict) / max(n, 1):.0f}%) | {len(room)} ({100 * len(room) / max(n, 1):.0f}%) |"
    if t:
        line += f" {st.median(t):.0f} | {st.mean(t):.0f} | {q(t, .25):.0f}-{q(t, .75):.0f} | {max(t):.0f} | {st.median(d):.0f} |"
    else:
        line += " - | - | - | - | - |"
    return line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tag")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    src = f"{WS}/log/reasonnav_sim/trials/{a.tag}.jsonl"
    rows = [json.loads(l) for l in open(src)]
    out = a.out or f"{WS}/log/reasonnav_sim/full_eval/{a.tag}"
    os.makedirs(out, exist_ok=True)
    rows.sort(key=lambda r: int(r["target"]))
    with open(f"{out}/results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["room", "strict_success", "claimed", "elapsed_s", "path_len_m", "label_err_m", "robot_err_m", "n_labels", "n_doors", "video"])
        for r in rows:
            w.writerow([r["target"], r.get("success"), r.get("claimed"), r.get("elapsed_s"), r.get("path_len_m"), r.get("dist_label_to_gt"),
                        r.get("dist_robot_to_gt"), r.get("n_labels"), r.get("n_doors"), r.get("video", "")])
    md = [f"# Room finding evaluation `{a.tag}`", "",
          f"{len(rows)} rooms, every trial started from a clean stack (robot at the spawn pose, empty maps, empty registries).", "",
          "| group | rooms | strict success | room found (label < 3 m) | median s | mean s | IQR s | max s | median path m |",
          "|---|---|---|---|---|---|---|---|---|", stats(rows, "all")]
    for name, lo, hi in REGIONS:
        md.append(stats([r for r in rows if lo <= int(r["target"]) <= hi], name))
    fails = [r for r in rows if not r.get("success")]
    md += ["", "Times and path lengths are over the rooms that were found (label < 3 m). Strict success additionally needs the robot within 4 m of the plate.", ""]
    md += ["## Not strictly successful", ""]
    if not fails:
        md.append("none")
    for r in fails:
        why = ("did not claim a room" if not r.get("claimed") else
               f"claimed, label {r['dist_label_to_gt']:.1f} m / robot {r['dist_robot_to_gt']:.1f} m from the plate")
        md.append(f"- {r['target']}: {why} ({r.get('elapsed_s', 0):.0f} s, {r.get('path_len_m', 0):.0f} m)" +
                  ("  [wrong label]" if r.get("claimed") and r.get("dist_label_to_gt") and r["dist_label_to_gt"] >= 3.0 else ""))
    md += ["", "## Per room", "", "| room | result | time s | path m | label err m | robot err m | video |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        res = "ok" if r.get("success") else ("room ok, stopped far" if r.get("claimed") and r.get("dist_label_to_gt") is not None and r["dist_label_to_gt"] < 3.0 else
                                              ("WRONG" if r.get("claimed") else "not found"))
        md.append(f"| {r['target']} | {res} | {r.get('elapsed_s', 0):.0f} | {r.get('path_len_m', 0):.0f} | "
                  f"{'-' if r.get('dist_label_to_gt') is None else format(r['dist_label_to_gt'], '.1f')} | "
                  f"{'-' if r.get('dist_robot_to_gt') is None else format(r['dist_robot_to_gt'], '.1f')} | {os.path.basename(r.get('video', '') or '')} |")
    open(f"{out}/summary.md", "w").write("\n".join(md) + "\n")
    print("\n".join(md[:14]))
    print("written", out)


if __name__ == "__main__":
    main()
