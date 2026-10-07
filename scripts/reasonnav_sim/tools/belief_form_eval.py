#!/usr/bin/env python3
"""Compare ways of asking the LLM where the goal room is (offline, on finder decision snapshots).
   dir8 : pick one of 8 compass directions relative to the robot (what the belief policy uses now)
   xy   : estimate the map position (x, y) of the room by extrapolating the numbering pattern
   near : no LLM; position of the already read plate whose number is closest to the target
Metric: distance (m) between the predicted position and the target's GT plate (dir8: angular error converted to the distance
at the true range, to be comparable)."""
import glob, json, math, os, random, re, statistics as st, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "/home/user/tips_ws/src/ReasonNav/src/mm_dev")
from mm_dev.room_finder import belief as bel, decide, vlm as vm  # noqa: E402

WS = os.path.expanduser("~/raisin_ws")
G = json.load(open(f"{WS}/scripts/reasonnav_sim/gt/hospital_rooms.json")); SP = G["spawn_xy"]
GT = {k: (v["xy"][0] - SP[0], v["xy"][1] - SP[1]) for k, v in G["rooms"].items()}


def prompt_xy(target, labels, robot):
    rows = "\n".join("  room %s at x=%.0f, y=%.0f" % (n, x, y) for n, x, y in sorted(labels))
    return (f"A robot searches a hospital floor for room {target}. Map coordinates in metres: x grows east, y grows north.\n"
            f"Robot position: x={robot[0]:.0f}, y={robot[1]:.0f}.\nRoom numbers read so far (number and position):\n{rows}\n\n"
            "Work out the numbering pattern (which way numbers increase along each corridor, odd/even sides, where numbering wraps around) "
            f"and extrapolate the map position of room {target}. Each room is about 3-4 m from its neighbours along a corridor.\n"
            'Answer with JSON only: {"reasoning": "...", "patterns": "...", "x": <number>, "y": <number>}')


def main():
    model = sys.argv[1] if len(sys.argv) > 1 else "gpt-4.1"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    os.environ["ROOM_FINDER_VLM"] = model
    v = vm.VLM(model)
    rng = random.Random(1)
    snaps = []
    for l in open(f"{WS}/log/reasonnav_sim/trials/full1.jsonl"):
        t = json.loads(l)
        js = sorted(glob.glob(t["logdir"] + "/finder/decisions/d*.json"))
        for j in js[3::6][:3]:
            rec = json.load(open(j))
            labs = [(x["number"], x["x"], x["y"]) for x in rec["reg"]["labels"] if x.get("number")]
            if len(labs) >= 3:
                snaps.append((rec, labs))
    rng.shuffle(snaps); snaps = snaps[:n]

    def one(item):
        rec, labs = item
        g = GT[str(rec["target"])]; r = rec["robot"]; T = int(rec["target"])
        out = {}
        # near baseline
        nb = min(labs, key=lambda l: abs(int(l[0]) - T))
        out["near"] = math.hypot(nb[1] - g[0], nb[2] - g[1])
        try:  # xy
            raw = v.ask_text(prompt_xy(rec["target"], labs, r), 600)
            j = vm.VLM._json(raw)
            out["xy"] = math.hypot(float(j["x"]) - g[0], float(j["y"]) - g[1])
        except Exception:  # noqa: BLE001
            out["xy"] = None
        try:  # dir8
            raw = v.ask_text(decide.paper_prompt(rec["target"], labs, r, (-45, 25, -8, 38), regions=bel.DIRS), 600)
            reg = vm.VLM._json(raw)["region"].strip().lower()
            true = math.atan2(g[1] - r[1], g[0] - r[0])
            e = abs((true - bel.ANG[reg] + math.pi) % (2 * math.pi) - math.pi)
            out["dir8"] = 2 * math.hypot(g[0] - r[0], g[1] - r[1]) * math.sin(min(e, math.pi) / 2)   # chord at the true range
            out["dir8_deg"] = math.degrees(e)
        except Exception:  # noqa: BLE001
            out["dir8"] = None
        return out
    with ThreadPoolExecutor(6) as ex:
        res = list(ex.map(one, snaps))
    print(f"model {model}, {len(res)} snapshots")
    for k in ("near", "xy", "dir8"):
        xs = [r[k] for r in res if r.get(k) is not None]
        print(f"  {k:5s} n={len(xs):2d} median error {st.median(xs):5.1f} m  mean {st.mean(xs):5.1f} m  within 5 m {100*sum(x<=5 for x in xs)/len(xs):3.0f}%  within 10 m {100*sum(x<=10 for x in xs)/len(xs):3.0f}%")
    d = [r["dir8_deg"] for r in res if r.get("dir8_deg") is not None]
    print(f"  dir8 angular error median {st.median(d):.0f} deg, within 45 deg {100*sum(x<=45 for x in d)/len(d):.0f}%")


main()
