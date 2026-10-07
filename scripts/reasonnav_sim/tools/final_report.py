#!/usr/bin/env python3
"""Aggregate the final comparison (prefixes f1, f2, ...; conditions img4 / vlm4 / lm) and the earlier studies into markdown tables."""
import glob, json, math, os, statistics as st, sys

WS = os.path.expanduser("~/raisin_ws")
T = f"{WS}/log/reasonnav_sim/trials"
CONDS = [("img4", "신뢰 격자 (지도·신뢰격자 그림, 표지판 없음)"), ("vlm4", "신뢰 격자 + 표지판 (크롭 사진 + 촬영 위치·방향)"), ("lm", "랜드마크 맵 (ReasonNav 방식, 우리 검출·읽기)")]
CAP = 900.0


def runs(cond, prefixes):
    out = []
    for p in prefixes:
        f = f"{T}/{p}_{cond}.jsonl"
        if os.path.exists(f):
            out += [dict(json.loads(l), rep=p) for l in open(f)]
    return out


def summary(rows):
    n = len(rows)
    ok = [r for r in rows if r.get("success")]
    t_all = [r["elapsed_s"] if r.get("success") else CAP for r in rows]
    t_ok = [r["elapsed_s"] for r in ok]
    p_ok = [r["path_len_m"] for r in ok]
    return n, len(ok), (st.mean(t_all) if t_all else None), (st.median(t_ok) if t_ok else None), (st.mean(p_ok) if p_ok else None), (st.pstdev(t_all) if len(t_all) > 1 else None)


def main():
    prefixes = sorted({os.path.basename(f).split("_")[0] for f in glob.glob(f"{T}/f[0-9]_*.jsonl")})
    print(f"## 최종 비교 (반복 {len(prefixes)}회: {', '.join(prefixes)}; 방 6개; 900초 제한)\n")
    print("| 조건 | 실행 수 | 성공 | 평균 시간(실패=900초) | 성공 시 시간 중앙값 | 성공 시 평균 이동(m) | 시간 표준편차 |\n|---|---|---|---|---|---|---|")
    data = {}
    for c, name in CONDS:
        rows = runs(c, prefixes)
        data[c] = rows
        if not rows:
            continue
        n, k, ta, tm, pm, sd = summary(rows)
        print(f"| {name} | {n} | {k} ({100 * k // n}%) | {ta:.0f} | {'-' if tm is None else f'{tm:.0f}'} | {'-' if pm is None else f'{pm:.0f}'} | {'-' if sd is None else f'{sd:.0f}'} |")
    print("\n실패한 실행 중 로봇이 정답 번호판 4 m 이내에서 시간이 끝난 비율 (시간 부족 vs 헤맨 실패 구분):")
    for c, name in CONDS:
        fails = [r for r in data.get(c, []) if not r.get("success")]
        if fails:
            close = [r for r in fails if r.get("dist_robot_to_gt") is not None and r["dist_robot_to_gt"] <= 4.0]
            print(f"  {c}: 실패 {len(fails)}건 중 정답 4 m 이내 {len(close)}건")
    rooms = sorted({r['target'] for rows in data.values() for r in rows})
    print("\n방별 (반복마다: 시간/이동 또는 실패):\n")
    print("| 방 | " + " | ".join(c for c, _ in CONDS) + " |\n|---|" + "---|" * len(CONDS))
    for room in rooms:
        cells = []
        for c, _ in CONDS:
            rr = [r for r in data[c] if r["target"] == room]
            cells.append(", ".join((f"{r['elapsed_s']:.0f}s/{r['path_len_m']:.0f}m" if r.get("success") else "실패") for r in rr) or "-")
        print(f"| {room} | " + " | ".join(cells) + " |")
    # paired comparison img4 vs vlm4 on the same room and repetition
    pairs = []
    for r in data.get("vlm4", []):
        o = [x for x in data.get("img4", []) if x["target"] == r["target"] and x["rep"] == r["rep"]]
        if o:
            a = o[0]["elapsed_s"] if o[0].get("success") else CAP
            b = r["elapsed_s"] if r.get("success") else CAP
            pairs.append(b - a)
    if pairs:
        print(f"\n표지판 있음 − 없음 (같은 방·같은 반복, 시간 차이): 평균 {st.mean(pairs):+.0f}초, 중앙값 {st.median(pairs):+.0f}초, "
              f"표지판이 더 빨랐던 쌍 {sum(p < 0 for p in pairs)}/{len(pairs)}")


if __name__ == "__main__":
    main()
