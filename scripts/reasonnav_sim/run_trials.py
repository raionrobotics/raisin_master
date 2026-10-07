#!/usr/bin/env python3
"""Run fresh-start room-finding trials and score them against the ground truth.

    run_trials.py 3018 3005 3030 [--max-time 1200] [--tag name]

Every trial restarts the whole stack (robot back at the spawn pose, empty maps and registries), waits for the finder
to write result.json, and scores it: a trial succeeds when the room the finder claims is the target AND both the claimed
plate position and the robot's final position are within `tol` metres of the target's ground-truth plate.
Results are appended to log/reasonnav_sim/trials/<tag>.jsonl.
"""
import re, argparse, json, math, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.expanduser("~/raisin_ws")
GT = json.load(open(os.path.join(HERE, "gt", "hospital_rooms.json")))
SPAWN = GT["spawn_xy"]


def gt_xy(num):
    x, y = GT["rooms"][str(num)]["xy"]
    return x - SPAWN[0], y - SPAWN[1]


def run(cmd, **kw):
    return subprocess.run(cmd, shell=True, **kw)


def save_video(logdir, target, video_dir):
    """wait for the recorder to finalise search.mp4, re-encode it as h264 (plays in browsers) and drop the raw file"""
    raw, rec_log = f"{logdir}/search.mp4", f"{logdir}/recorder.log"
    for _ in range(40):
        if os.path.exists(rec_log) and "saved" in open(rec_log).read():
            break
        time.sleep(1)
    if not os.path.exists(raw):
        return ""
    os.makedirs(video_dir, exist_ok=True)
    dst = f"{video_dir}/{target}.mp4"
    ok = run(f"ffmpeg -v error -y -i {raw} -c:v libx264 -crf 27 -preset veryfast -pix_fmt yuv420p -movflags +faststart {dst}").returncode == 0
    if ok:
        os.remove(raw)
        return dst
    return raw


def trial(target, max_time, tol, env_extra="", video_dir=None, extra=""):
    run(f"{HERE}/run_reasonnav_sim.sh --kill > /dev/null 2>&1")
    # the previous sim must be fully gone: a lingering process keeps the livox UDP ports and the next lidar fails to bind
    for _ in range(30):
        if run("pgrep -f '[r]aisin_raibo2_node|[r]aisin_bridge_node|[r]aisin_gui' > /dev/null").returncode != 0:
            break
        run("pkill -f '[r]aisin_raibo2_node'; pkill -f '[r]aisin_bridge_node'; pkill -f '[r]aisin_gui'; sleep 2")
    time.sleep(8)
    t0 = time.time()
    rec_flag = "--record" if video_dir else ""
    run(f"cd {WS} && FINDER_MAX_TIME={max_time} {env_extra} {HERE}/run_reasonnav_sim.sh --goal {target} --no-gui --no-rviz {rec_flag} {extra} "
        f"< /dev/null > /dev/null 2>&1")
    stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(t0 - 5))
    fresh = sorted(d for d in os.listdir(f"{WS}/log/reasonnav_sim") if d[:2] == "20" and d >= stamp)
    if not fresh:     # the launcher did not create a log directory for this run (not executable, tmux session left over ...)
        print(json.dumps({"target": str(target), "FINDER_CRASH": "launcher did not start a new run"}), flush=True)
        sys.exit(3)
    logdir = f"{WS}/log/reasonnav_sim/{fresh[-1]}"
    res_path = f"{logdir}/finder/result.json"
    while not os.path.exists(res_path) and time.time() - t0 < max_time + 240:
        time.sleep(5)
        fl = f"{logdir}/finder.log"
        if time.time() - t0 < 300 and os.path.exists(fl) and "Traceback" in open(fl).read():
            print(json.dumps({"target": str(target), "FINDER_CRASH": open(fl).read().strip().splitlines()[-1][:200]}), flush=True)
            run(f"{HERE}/run_reasonnav_sim.sh --kill > /dev/null 2>&1")
            sys.exit(3)
    row = {"target": str(target), "logdir": logdir, "gt_xy": [round(v, 2) for v in gt_xy(target)]}
    if not os.path.exists(res_path):
        row.update(found=False, success=False, reason="no result (timeout or crash)")
        return row
    r = None
    for _ in range(12):       # the finder may still be writing the file (it is killed right after finishing)
        try:
            r = json.load(open(res_path))
            break
        except ValueError:
            time.sleep(5)
    if r is None:
        gave_up = re.search(r"GAVE UP on room \d+ after (\d+) s, (\d+) m", open(f"{logdir}/finder.log").read() if os.path.exists(f"{logdir}/finder.log") else "")
        row.update(found=False, success=False, claimed=False, elapsed_s=float(gave_up.group(1)) if gave_up else max_time, path_len_m=float(gave_up.group(2)) if gave_up else 0.0,
                   dist_label_to_gt=None, dist_robot_to_gt=None, reason="result.json unreadable; reconstructed from the finder log")
        return row
    if video_dir:
        row["video"] = save_video(logdir, target, video_dir)
    row.update(claimed=r["found"], elapsed_s=r["elapsed_s"], path_len_m=r["path_len_m"], label_xy=r["label_xy"],
               robot_xy=r["robot_xy"], n_labels=r["n_labels"], n_doors=r["n_doors"])
    gx, gy = gt_xy(target)
    d_lab = math.hypot(r["label_xy"][0] - gx, r["label_xy"][1] - gy) if r["label_xy"] else None
    d_rob = math.hypot(r["robot_xy"][0] - gx, r["robot_xy"][1] - gy) if r["robot_xy"] else None
    row.update(dist_label_to_gt=None if d_lab is None else round(d_lab, 2), dist_robot_to_gt=None if d_rob is None else round(d_rob, 2))
    row["success"] = bool(r["found"] and d_lab is not None and d_lab < tol and d_rob is not None and d_rob < tol + 1.0)
    return row


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--max-time", type=float, default=1200.0)
    ap.add_argument("--tol", type=float, default=3.0)
    ap.add_argument("--tag", default=time.strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--record", action="store_true", help="save a video of every search to log/reasonnav_sim/full_eval/<tag>/videos/")
    ap.add_argument("--extra", default="", help="extra launcher flags, e.g. --rn for the ReasonNav vlm_nav stack")
    ap.add_argument("--env", default="", help="extra VAR=value words for the launcher environment")
    a = ap.parse_args()
    os.makedirs(f"{WS}/log/reasonnav_sim/trials", exist_ok=True)
    out = f"{WS}/log/reasonnav_sim/trials/{a.tag}.jsonl"
    for tgt in a.targets:
        vdir = f"{WS}/log/reasonnav_sim/full_eval/{a.tag}/videos" if a.record else None
        row = trial(tgt, a.max_time, a.tol, a.env, vdir, a.extra)
        for _ in range(2):   # the robot never moved: the stack did not come up (SLAM / bring-up race), not a search failure
            if (row.get("path_len_m") or 0.0) >= 20.0 or row.get("claimed"):   # < 20 m and no claim = the robot never really moved (stack / waypoint service stalled)
                break
            print(json.dumps({"target": str(tgt), "retry": "stack did not start"}), flush=True)
            row = trial(tgt, a.max_time, a.tol, a.env, vdir, a.extra)
        row["tag"] = a.tag
        open(out, "a").write(json.dumps(row) + "\n")
        print(json.dumps({k: row.get(k) for k in ("target", "success", "claimed", "elapsed_s", "path_len_m", "dist_label_to_gt", "dist_robot_to_gt")}), flush=True)
    run(f"{HERE}/run_reasonnav_sim.sh --kill > /dev/null 2>&1")
