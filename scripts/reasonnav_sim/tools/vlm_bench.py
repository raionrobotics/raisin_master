#!/usr/bin/env python3
"""Benchmark VLMs on the three queries the room finder makes, using crops and snapshots saved by the full1 evaluation.

    env -u OPENAI_API_KEY python3 vlm_bench.py [--models a,b,c] [--n-plate 70] [--n-neg 50] [--n-sign 36] [--n-belief 36] [--tag name]

Tasks (ground truth in brackets)
  plate  : room-number plate crops          [number of the GT plate within 1.2 m of the crop's projected position; <= 3 m away]
  empty  : crops with no plate in view      [no GT plate within 4 m of the projected position -> the right answer is null]
  sign   : directional-sign crops of the 4 real signs  [the printed entries and arrows of sign_*.png, read from the textures]
  belief : text-only prediction of the goal direction (paper style) [compass direction from the robot to the target's GT plate]
Latency is wall time of one call. Tokens are the API's usage numbers (reasoning tokens included).
"""
import argparse, base64, collections, glob, json, math, os, random, re, statistics as st, sys, time
from concurrent.futures import ThreadPoolExecutor

import cv2

sys.path.insert(0, "/home/user/tips_ws/src/ReasonNav/src/mm_dev")
from mm_dev.room_finder import belief as bel, decide, vlm as vlmmod  # noqa: E402

WS = os.path.expanduser("~/raisin_ws")
G = json.load(open(f"{WS}/scripts/reasonnav_sim/gt/hospital_rooms.json")); SP = G["spawn_xy"]
GT = {k: (v["xy"][0] - SP[0], v["xy"][1] - SP[1]) for k, v in G["rooms"].items()}
SIGNS_POS = {"consultation": (-38.81, 14.33), "public_service": (-25.85, 6.12), "waiting": (-12.62, 0.96), "examination": (10.12, 11.07)}
U, R, L, D = "straight", "right", "left", "back"
SIGN_GT = {   # keyword -> (digits, direction) as printed on sign_*.png (up = straight, down = back)
    "examination": {"examination": ("30253039", U), "reception": ("", R), "restroom": ("30403041", R), "support": ("30153024", D),
                    "waiting": ("", D), "public": ("3014", D), "consultation": ("30013013", D), "exit": ("", R)},
    "waiting": {"public": ("3014", U), "consultation": ("30013013", U), "support": ("30153024", R), "examination": ("30253039", D),
                "restroom": ("30403041", D), "stair": ("", D), "exit": ("", L)},
    "public_service": {"waiting": ("", U), "reception": ("", U), "support": ("30153024", U), "examination": ("30253039", U),
                       "restroom": ("30403041", U), "stair": ("", L), "consultation": ("30013013", D), "exit": ("", R)},
    "consultation": {"public": ("3014", R), "support": ("30153024", R), "waiting": ("", R), "reception": ("", R),
                     "examination": ("30253039", R), "restroom": ("30403041", R), "stair": ("", D), "exit": ("", D)},
}
KEYS = ("examination", "reception", "restroom", "support", "waiting", "public", "consultation", "exit", "stair")


def d2(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


# ---------------------------------------------------------------- model call with per-family parameters
def call(client, model, images, prompt):
    reasoning = model.startswith(("gpt-5", "o3", "o4"))
    content = [{"type": "text", "text": prompt}] + [
        {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + base64.b64encode(cv2.imencode(".jpg", im, [cv2.IMWRITE_JPEG_QUALITY, 90])[1]).decode(), "detail": "high"}}
        for im in images]
    kw = dict(model=model, messages=[{"role": "user", "content": content}])
    if reasoning:
        kw["max_completion_tokens"] = 4000
    else:
        kw.update(max_completion_tokens=800, temperature=0)
    efforts = ["minimal", "low", None] if (model.startswith("gpt-5") or model.startswith("o")) else [None]
    t0 = time.time()
    last = None
    for eff in efforts:
        try:
            k = dict(kw)
            if eff and reasoning:
                k["reasoning_effort"] = eff
            r = client.chat.completions.create(**k)
            u = r.usage
            return (r.choices[0].message.content or "").strip(), time.time() - t0, (u.total_tokens if u else 0), eff
        except Exception as e:  # noqa: BLE001
            last = e
            if "reasoning_effort" not in str(e) and "Unsupported" not in str(e) and "unsupported" not in str(e):
                break
    return "ERROR " + repr(last)[:160], time.time() - t0, 0, None


# ---------------------------------------------------------------- datasets from the full1 logs
def trials():
    return [json.loads(l) for l in open(f"{WS}/log/reasonnav_sim/trials/full1.jsonl")]


def crop_img(logdir, name):
    return cv2.imread(f"{logdir}/perception/crops/{name}") if name else None


def plate_sets(rng, n_pos, n_neg):
    pos, neg = [], []
    for t in trials():
        for l in open(t["logdir"] + "/perception/events.jsonl"):
            e = json.loads(l)
            if e["kind"] != "plate_read" or not e.get("crop") or e["dist"] > 3.0:
                continue
            near = min(GT, key=lambda k: d2(e["xy"], GT[k]))
            dn = d2(e["xy"], GT[near])
            if e["source"] == "plate" and dn < 1.2:
                pos.append((t["logdir"], e["crop"], near))
            elif dn > 4.0:
                neg.append((t["logdir"], e["crop"], None))
    rng.shuffle(pos); rng.shuffle(neg)
    # one sample per (logdir, crop); spread over rooms
    seen, out_pos = collections.Counter(), []
    for p in pos:
        if seen[p[2]] < 3:
            out_pos.append(p); seen[p[2]] += 1
    return out_pos[:n_pos], neg[:n_neg]


def sign_set(rng, n):
    by = collections.defaultdict(list)
    for t in trials():
        js = sorted(glob.glob(t["logdir"] + "/finder/decisions/d*.json"))
        if not js:
            continue
        reg = json.load(open(js[-1]))["reg"]
        ev = [json.loads(l) for l in open(t["logdir"] + "/perception/events.jsonl")]
        pos = {s["id"]: min(SIGNS_POS, key=lambda k: d2((s["x"], s["y"]), SIGNS_POS[k])) for s in reg["signs"]
               if min(d2((s["x"], s["y"]), v) for v in SIGNS_POS.values()) < 2.5}
        for e in ev:
            if e["kind"] == "sign_read" and e.get("crop") and e["sign"] in pos and e.get("head_on", 99) <= 60:
                by[pos[e["sign"]]].append((t["logdir"], e["crop"], pos[e["sign"]]))
    out = []
    per = max(1, n // 4)
    for k, v in by.items():
        rng.shuffle(v); out += v[:per]
    return out[:n], {k: len(v) for k, v in by.items()}


def belief_set(rng, n):
    out = []
    for t in trials():
        js = sorted(glob.glob(t["logdir"] + "/finder/decisions/d*.json"))
        for j in js[3::6][:3]:
            rec = json.load(open(j))
            labs = [(l["number"], l["x"], l["y"]) for l in rec["reg"]["labels"] if l.get("number")]
            if len(labs) >= 3:
                out.append((rec, labs))
    rng.shuffle(out)
    return out[:n]


# ---------------------------------------------------------------- scoring
def norm_dir(d):
    d = str(d).lower().strip()
    return vlmmod.SYNONYMS.get(d, d)


def score_sign(raw, truth):
    try:
        j = vlmmod.VLM._json(raw)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(j, list):
        return None
    gt = SIGN_GT[truth]
    found = place = dirok = 0
    used = set()
    for c in j:
        if not isinstance(c, dict):
            continue
        txt = str(c.get("place", "")).lower()
        k = next((k for k in KEYS if k in txt), None)
        if k is None or k in used:
            continue
        key = "public" if k == "public" else k
        if key not in gt:
            continue
        used.add(k)
        found += 1
        digits = "".join(re.findall(r"\d", txt))
        place += int(digits == gt[key][0] or (gt[key][0] == "" ))
        dirok += int(norm_dir(c.get("direction")) == gt[key][1])
    return {"n_gt": len(gt), "found": found, "place_ok": place, "dir_ok": dirok}


COMP = bel.DIRS


def region_ok(region, rec):
    region = str(region).strip().lower()
    if region not in COMP:
        return None
    r = rec["robot"]; g = GT[str(rec["target"])]
    true = math.atan2(g[1] - r[1], g[0] - r[0])
    pred = bel.ANG[region]
    e = abs((true - pred + math.pi) % (2 * math.pi) - math.pi)
    return e


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="gpt-4.1,gpt-4.1-mini,gpt-4.1-nano,gpt-4o,gpt-4o-mini,gpt-5-mini,gpt-5-nano,gpt-5.4-mini,gpt-5.4-nano,gpt-5.4,o4-mini")
    ap.add_argument("--n-plate", type=int, default=70); ap.add_argument("--n-neg", type=int, default=50)
    ap.add_argument("--n-sign", type=int, default=36); ap.add_argument("--n-belief", type=int, default=36)
    ap.add_argument("--workers", type=int, default=6); ap.add_argument("--tag", default="bench1")
    a = ap.parse_args()
    rng = random.Random(0)
    pos, neg = plate_sets(rng, a.n_plate, a.n_neg)
    signs, avail = sign_set(rng, a.n_sign)
    bel_set = belief_set(rng, a.n_belief)
    print(f"plate+ {len(pos)}  empty {len(neg)}  sign {len(signs)} (available per sign {avail})  belief {len(bel_set)}", flush=True)
    vm = vlmmod.VLM()
    client = vm.client
    out = {}
    for model in a.models.split(","):
        res = {"plate": [], "empty": [], "sign": [], "belief": [], "lat": collections.defaultdict(list), "tok": collections.defaultdict(list), "err": 0}

        def run(task, item):
            if task in ("plate", "empty"):
                logdir, name, label = item
                raw, lat, tok, _ = call(client, model, [crop_img(logdir, name)], vlmmod.PLATE_PROMPT)
                try:
                    num = vlmmod.VLM._json(raw).get("number")
                    num = None if num in (None, "null", "") else str(num)
                except Exception:  # noqa: BLE001
                    num, raw = "PARSE", raw
                return task, (num, label, raw), lat, tok
            if task == "sign":
                logdir, name, truth = item
                raw, lat, tok, _ = call(client, model, [crop_img(logdir, name)], vlmmod.SIGN_PROMPT)
                return task, (score_sign(raw, truth), truth, raw), lat, tok
            rec, labs = item
            prompt = decide.paper_prompt(rec["target"], labs, rec["robot"], (-45, 25, -8, 38), regions=bel.DIRS)
            raw, lat, tok, _ = call(client, model, [], prompt)
            try:
                reg = vlmmod.VLM._json(raw)["region"]
            except Exception:  # noqa: BLE001
                reg = None
            return task, (region_ok(reg, rec), reg, raw), lat, tok
        jobs = [("plate", p) for p in pos] + [("empty", n) for n in neg] + [("sign", s) for s in signs] + [("belief", b) for b in bel_set]
        t0 = time.time()
        with ThreadPoolExecutor(a.workers) as ex:
            for task, payload, lat, tok in ex.map(lambda j: run(*j), jobs):
                res[task].append(payload); res["lat"][task].append(lat); res["tok"][task].append(tok)
                if str(payload[-1]).startswith("ERROR"):
                    res["err"] += 1
        # aggregate
        s = {"model": model, "wall_s": round(time.time() - t0), "errors": res["err"]}
        P = res["plate"]
        s["plate_correct"] = round(100 * sum(1 for n, l, _ in P if n == l) / max(1, len(P)))
        s["plate_wrong_number"] = round(100 * sum(1 for n, l, _ in P if n not in (None, l)) / max(1, len(P)))
        s["plate_null"] = round(100 * sum(1 for n, l, _ in P if n is None) / max(1, len(P)))
        E = res["empty"]
        s["empty_false_number"] = round(100 * sum(1 for n, l, _ in E if n is not None) / max(1, len(E)))
        S = [x for x in res["sign"] if x[0]]
        ng = sum(x[0]["n_gt"] for x in S)
        s["sign_entries_found"] = round(100 * sum(x[0]["found"] for x in S) / max(1, ng))
        s["sign_digits_ok"] = round(100 * sum(x[0]["place_ok"] for x in S) / max(1, ng))
        s["sign_dir_ok_of_all"] = round(100 * sum(x[0]["dir_ok"] for x in S) / max(1, ng))
        s["sign_unparsed"] = len(res["sign"]) - len(S)
        B = [x[0] for x in res["belief"] if x[0] is not None]
        s["belief_within_45deg"] = round(100 * sum(1 for e in B if e <= math.pi / 4 + 1e-6) / max(1, len(res["belief"])))
        s["belief_exact_dir"] = round(100 * sum(1 for e in B if e <= math.pi / 8 + 1e-6) / max(1, len(res["belief"])))
        for task in ("plate", "sign", "belief"):
            v = sorted(res["lat"][task])
            s[f"lat_{task}_med"] = round(st.median(v), 2) if v else None
            s[f"lat_{task}_p90"] = round(v[int(.9 * (len(v) - 1))], 2) if v else None
            s[f"tok_{task}"] = round(st.mean(res["tok"][task])) if res["tok"][task] else None
        out[model] = s
        print(json.dumps(s), flush=True)
        os.makedirs(f"{WS}/log/reasonnav_sim/vlm_bench", exist_ok=True)
        json.dump(out, open(f"{WS}/log/reasonnav_sim/vlm_bench/{a.tag}.json", "w"), indent=1)


if __name__ == "__main__":
    main()
