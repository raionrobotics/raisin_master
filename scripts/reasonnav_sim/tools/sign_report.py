#!/usr/bin/env python3
"""Report of the sign comparison (prefixes s1, s2, ...; conditions img4 = no signs, steer4 = sign cues steer / exclude, vlm4 = sign photos to the VLM).

  python3 sign_report.py [prefix-glob]      markdown on stdout
Per condition success / time / path, per-room paired deltas (rooms where signs help or hurt), whether the sign cues pointed the right way,
time per goal kind, door registry quality."""
import collections, glob, json, math, os, re, statistics as st, sys

WS = os.path.expanduser("~/raisin_ws")
T = f"{WS}/log/reasonnav_sim/trials"
CAP = 900.0
CONDS = [("img4", "표지판 없음 (신뢰격자)"), ("steer4", "표지판 방향 유도·배제 (신뢰격자)"), ("vlm4", "표지판 사진을 VLM에 전달 (신뢰격자)")]
GT = {k: (v["xy"][0] - 1.0, v["xy"][1]) for k, v in json.load(open(f"{WS}/scripts/reasonnav_sim/gt/hospital_rooms.json"))["rooms"].items()}


def load(pattern):
    data = {c: [] for c, _ in CONDS}
    for f in sorted(glob.glob(f"{T}/{pattern}_*.jsonl")):
        pref, cond = os.path.basename(f)[:-6].split("_", 1)
        if cond not in data:
            continue
        for l in open(f):
            r = json.loads(l)
            if "success" in r and "logdir" in r:
                r["rep"] = pref
                r["trapped"] = trapped(r)
                data[cond].append(r)
    return data


def trapped(r):
    """The robot got physically stuck (10+ 'stuck' events in the finder log): a simulation artefact, not a property of the method."""
    try:
        return sum(1 for ln in open(r["logdir"] + "/finder/finder.log") if "stuck near" in ln) >= 10
    except Exception:  # noqa: BLE001
        return False


def tm(r):
    return r["elapsed_s"] if r.get("success") else CAP


def table(data):
    print("| 조건 | 실행 | 성공 | 평균 시간(실패=900초) | 성공 시 시간 중앙값 | 성공 시 평균 이동(m) |\n|---|---|---|---|---|---|")
    for c, name in CONDS:
        rows = data[c]
        if not rows:
            continue
        ok = [r for r in rows if r["success"]]
        print(f"| {name} | {len(rows)} | {len(ok)} ({100 * len(ok) // len(rows)}%) | {st.mean(tm(r) for r in rows):.0f} | "
              f"{st.median(r['elapsed_s'] for r in ok) if ok else float('nan'):.0f} | {st.mean(r['path_len_m'] for r in ok) if ok else float('nan'):.0f} |")


def per_room(data):
    rooms = sorted({r["target"] for rows in data.values() for r in rows})
    print("| 방 | " + " | ".join(f"{c} 성공/평균시간" for c, _ in CONDS) + " | steer−img (초) | vlm−img (초) | 판정 |\n|---|" + "---|" * (len(CONDS) + 3))
    eff = []
    for room in rooms:
        cell, mean = [], {}
        for c, _ in CONDS:
            rr = [r for r in data[c] if r["target"] == room]
            if rr:
                mean[c] = st.mean(tm(r) for r in rr)
                cell.append(f"{sum(r['success'] for r in rr)}/{len(rr)} · {mean[c]:.0f}초")
            else:
                cell.append("-")
        d1 = mean["steer4"] - mean["img4"] if "steer4" in mean and "img4" in mean else None
        d2 = mean["vlm4"] - mean["img4"] if "vlm4" in mean and "img4" in mean else None
        verdict = "-"
        if d1 is not None:
            verdict = "표지판 유도 효과 (빠름)" if d1 <= -60 else "표지판 유도 악화 (느림)" if d1 >= 60 else "차이 작음"
            eff.append((room, d1, verdict))
        print(f"| {room} | " + " | ".join(cell) + f" | {'-' if d1 is None else f'{d1:+.0f}'} | {'-' if d2 is None else f'{d2:+.0f}'} | {verdict} |")
    return eff


def paired(data):
    import random
    random.seed(1)
    print("| 비교 | 쌍 수 | 평균 시간 차이(초) | 95% 구간(부트스트랩) | 중앙값 차이 | 표지판 쪽이 빨랐던 쌍 | 성공 차이 |\n|---|---|---|---|---|---|---|")
    for c, name in CONDS[1:]:
        d, sc = [], 0
        for r in data[c]:
            o = [x for x in data["img4"] if x["target"] == r["target"] and x["rep"] == r["rep"]]
            if o:
                d.append(tm(r) - tm(o[0])); sc += int(r["success"]) - int(o[0]["success"])
        if not d:
            continue
        bs = sorted(st.mean(random.choices(d, k=len(d))) for _ in range(2000))
        print(f"| {c} − img4 | {len(d)} | {st.mean(d):+.0f} | {bs[50]:+.0f} ~ {bs[1949]:+.0f} | {st.median(d):+.0f} | {sum(x < 0 for x in d)}/{len(d)} | {sc:+d} |")


def bearing(a, b):
    return math.atan2(b[1] - a[1], b[0] - a[0])


def adiff(a, b):
    d = abs(a - b) % (2 * math.pi)
    return min(d, 2 * math.pi - d)


def cue_quality(rows):
    """For each run: the signs read, which entries list the target, and whether their arrows point at the target (45 deg)."""
    out = []
    for r in rows:
        try:
            res = json.load(open(r["logdir"] + "/finder/result.json"))
        except Exception:  # noqa: BLE001
            continue
        tnum = int(r["target"])
        tgt = GT[r["target"]]
        for s in res.get("signs", []):
            for c in s.get("cues", []):
                if c.get("bearing") is None or c.get("lo") is None:
                    continue
                sx, sy = (s["xy"] if "xy" in s else (s["x"], s["y"]))
                err = math.degrees(adiff(c["bearing"], bearing((sx, sy), tgt)))
                out.append({"room": r["target"], "sign": s["id"], "lists": c["lo"] <= tnum <= c["hi"], "err": err, "place": c["place"]})
    return out


def sign_quality(data):
    cq = cue_quality(data["steer4"] + data["vlm4"])
    lists = [c for c in cq if c["lists"]]
    other = [c for c in cq if not c["lists"]]
    print(f"- 읽힌 표지판 항목 {len(cq)}개 중 찾는 방 번호를 포함하는 항목 {len(lists)}개.")
    if lists:
        good = sum(c["err"] <= 45 for c in lists)
        print(f"- 포함 항목의 화살표가 정답 방향(표지판 → 방, 직선 방위 기준 45° 이내)을 가리킨 비율: {good}/{len(lists)} ({100 * good // len(lists)}%). "
              "직선 방위라서 복도가 꺾이면 맞는 안내도 틀린 것으로 셉니다.")
    if other:
        bad = sum(c["err"] <= 22.5 for c in other)
        print(f"- 방 번호를 포함하지 않는 항목 {len(other)}개 중 화살표가 정답 방향 ±22.5° 안을 가리켜 잘못 배제될 수 있는 것: {bad}개 ({100 * bad // len(other)}%).")


def time_breakdown(data):
    print("| 조건 | 실행당 시간(초) | 프런티어 | 문 읽기 | 번호판 확인 | 표지판 읽기 | 표지판 읽기 목표/실행 |\n|---|---|---|---|---|---|---|")
    for c, _ in CONDS:
        agg, n, sg = collections.defaultdict(float), 0, 0
        for r in data[c]:
            ev = []
            try:
                for ln in open(r["logdir"] + "/finder/finder.log"):
                    m = re.match(r"\[\s*(\d+)s\] -> (read sign|read door|verify label|frontier)", ln)
                    if m:
                        ev.append((int(m.group(1)), m.group(2)))
            except Exception:  # noqa: BLE001
                continue
            for i, (t, k) in enumerate(ev):
                agg[k] += max(0, (ev[i + 1][0] if i + 1 < len(ev) else r["elapsed_s"]) - t)
                sg += k == "read sign"
            n += 1
        if n:
            tot = sum(agg.values())
            print(f"| {c} | {tot / n:.0f} | {agg['frontier'] / n:.0f} | {agg['read door'] / n:.0f} | {agg['verify label'] / n:.0f} | {agg['read sign'] / n:.0f} | {sg / n:.1f} |")


def door_quality(data):
    print("| 조건 | 등록된 문 | 문이 아닌 곳 | 같은 방 중복 문 | 번호판이 읽힌 방 |\n|---|---|---|---|---|")
    for c, _ in CONDS:
        tot = far = dup = rooms = n = 0
        for r in data[c]:
            fs = sorted(glob.glob(r["logdir"] + "/finder/decisions/d*.json"))
            if not fs:
                continue
            reg = json.load(open(fs[-1]))["reg"]
            near = collections.defaultdict(int)
            for d in reg["doors"]:
                k = min(GT, key=lambda k: math.hypot(GT[k][0] - d["x"], GT[k][1] - d["y"]))
                if math.hypot(GT[k][0] - d["x"], GT[k][1] - d["y"]) < 2.5:
                    near[k] += 1
                else:
                    far += 1
            tot += len(reg["doors"]); dup += sum(v - 1 for v in near.values()); rooms += len({l["number"] for l in reg["labels"] if l.get("number")}); n += 1
        if n:
            print(f"| {c} | {tot / n:.0f} | {far / n:.0f} | {dup / n:.1f} | {rooms / n:.0f} |")


def apply_reruns(data, pat="r[0-9]"):
    """A run in which the robot got stuck is replaced by the rerun (prefix r1, r2 ...) of the same room and condition."""
    rr = load(pat)
    n = 0
    for c in data:
        for i, r in enumerate(data[c]):
            if r["trapped"]:
                alt = [x for x in rr.get(c, []) if x["target"] == r["target"] and not x["trapped"]]
                if alt:
                    alt[0]["rep"] = r["rep"]
                    alt[0]["rerun"] = True
                    data[c][i] = alt[0]
                    n += 1
    return n


def main():
    pat = sys.argv[1] if len(sys.argv) > 1 else "s[0-9]"
    data = load(pat)
    nre = apply_reruns(data)
    if nre:
        print(f"(끼임 실행 {nre}건은 같은 방·조건의 재실행으로 교체했습니다.)\n")
    n = sum(len(v) for v in data.values())
    print(f"## 표지판 사용 비교 ({pat}; 실행 {n}건; 900초 제한)\n")
    table(data)
    tr = [(c, r["target"], r["rep"]) for c in data for r in data[c] if r["trapped"]]
    if tr:
        print(f"\n끼임 실행 {len(tr)}건 (로봇이 한 자리에 막혀 실패): " + ", ".join(f"{c} {t} {rp}" for c, t, rp in tr) + ". 아래 '끼임 제외' 표는 이 실행과 같은 방·반복의 쌍을 뺀 결과입니다.")
    print("\n### 같은 방·같은 반복 쌍 비교 (표지판 없음 기준)\n")
    paired(data)
    if tr:
        ex = {(t, rp) for _, t, rp in tr}
        print("\n끼임 제외:\n")
        paired({c: [r for r in rows if (r["target"], r["rep"]) not in ex] for c, rows in data.items()})
    print("\n### 방별 결과 (같은 방 반복 평균)\n")
    eff = per_room(data)
    print("\n### 표지판 유도(steer)의 효과가 나타난 방\n")
    better = [e for e in eff if e[1] <= -60]
    worse = [e for e in eff if e[1] >= 60]
    print("- 빨라진 방: " + (", ".join(f"{r} ({d:+.0f}초)" for r, d, _ in sorted(better, key=lambda e: e[1])) or "없음"))
    print("- 느려진 방: " + (", ".join(f"{r} ({d:+.0f}초)" for r, d, _ in sorted(worse, key=lambda e: -e[1])) or "없음"))
    print("\n### 표지판 정보의 정확도\n")
    sign_quality(data)
    print("\n### 시간 구성\n")
    time_breakdown(data)
    print("\n### 문 등록 품질\n")
    door_quality(data)


if __name__ == "__main__":
    main()
