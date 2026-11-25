# A1 r2 (C1) sim repro snapshot

Snapshot of the 2026-11-13 A1 ablation run ("a1c2") on branch `wip/a1-repro-snapshot`, based on
`feature/reasonnav-room-finder-sim` @ ce2d429. Raisim + raisin sim with the real-robot room_finder code; not habitat.

## Contents
- `third_party/mm_dev_r69x/`: room_finder as used (adds `room_finder.sign_neg_strip_w`, `room_finder.sign_route_aisle`).
- `third_party/raibo2_resource/`: worlds `jinri_1f_clutter_sp_rs(_c1)` + raisim_config xml, `modules/oak_mast`,
  `sensors/oakd_pro_w_sim.xml`. Copy into `install/resource/raisin_raibo2/resource/` (same relative paths);
  `run_net_sim.sh` links them into raibo2_properties. The C1 world can be regenerated with
  `tools/make_jinri_sp.py --variant clutter --signs real --c1`.
- `room_finder_assets/weights/doordetect_oi/best.pt`: YOLO door detector (ultralytics, custom-trained). `ai_main_r7f.py`
  picks it up automatically from `$MMDEV/../../room_finder_assets`.
- `gt/jinri_1f_clutter_sp_rs_c1_rooms.json`: plate ground truth.

## Not included
- OpenAI key: put `OPENAI_API_KEY=...` in `third_party/mm_dev_r69x/config/.env` (a shell variable is ignored unless `--env-key`).
- raisim license, built TensorRT engines, GroundingDINO weights (HF `IDEA-Research/grounding-dino-base`, downloaded on first use).
- In sim, GDINO runs as the torch server `mm_dev/room_finder/gdino_server.py`; `run_net_sim.sh` starts it with
  `/home/user/yolo_ws/.venv_autolabel/bin/python` - change that line to your python.

## Environment used
Ubuntu 22.04.5, RTX 4070 (driver 550.163.01), system python 3.10.12, torch 2.9.0, ultralytics 8.3.219,
transformers 4.38.2, tensorrt 10.15.1.29, openai 1.109.1, numpy 1.26.4. raisin_ws built with plain cmake/ninja.

## Run
    scripts/reasonnav_sim/repro/a1c2.sh 1 ours T110     # one check run, ~5 min
    scripts/reasonnav_sim/repro/a1c2.sh 1               # 5 targets x 3 variants, ~3 h
Results: `log/reasonnav_sim/trials/a1c2_<cfg>_r<n>.jsonl` (success, elapsed_s, path_len_m) and per-run
`log/reasonnav_sim/<timestamp>/` (ai.log, finder/finder.log, finder/decisions/).

Reference (round 1, 2026-11-13): ours 5/5 mean 442 s (T110 224 s / 99 m), ignore 4/5 516 s, excl 0/5.
In ours T110 the log shows around 159 s: `S25 'T112~T126' makes the corridor 89 deg from (50.1, 0.7) unlikely`.
Single runs vary by +-50 s or more (VLM answers, sim timing).
