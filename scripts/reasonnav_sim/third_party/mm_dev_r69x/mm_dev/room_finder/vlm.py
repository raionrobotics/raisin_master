"""Thin OpenAI vision client for the room finder: room-number plates and navigational signs."""
import base64
import json
import os
import re
import time

import cv2
import numpy as np

from mm_dev.room_finder import roomno

_MODEL = os.environ.get("ROOM_FINDER_VLM", "gpt-5-mini")   # chosen by tools/vlm_bench.py (2026-10-01): best plate accuracy, no false plates, fast

DIRECTIONS = ("straight", "left", "right", "back", "straight-left", "straight-right", "back-left", "back-right",
              "left-then-straight", "right-then-straight", "straight-then-left", "straight-then-right")   # the last four: bent arrows
SYNONYMS = {"down": "back", "backward": "back", "backwards": "back", "behind": "back", "up": "straight", "forward": "straight",
            "ahead": "straight", "up-left": "straight-left", "up-right": "straight-right", "down-left": "back-left",
            "down-right": "back-right", "straight ahead": "straight"}

PLATE_PROMPT = """The image is a crop of an indoor wall around one door. Parts of the scene far from the door were blanked out.
Find the room number plate that belongs to this door (a small permanent plate on the door or on the wall next to or above it) and read it.
Room numbers in this building have 3 to 5 digits, optionally with a letter prefix (for example 3018 or T138). Transcribe only characters you can actually make out and keep the letters; never guess a plausible number.
Answer with JSON only: {"number": "<letters and digits as printed, e.g. T138, or null>", "confidence": <0..1>}.
Use null when there is no plate or its characters are not legible.
A range of rooms (e.g. T131~T150) or text with an arrow is a directional sign, not a room plate: answer null for it.
Numbers that are not room numbers: answer null for a phone number or a part of one (e.g. the 0119 of 042-350-0119), an emergency number
(119, 112), a year or a date (e.g. 2026), and any number on a sticker, poster, notice or flyer, a mailbox, a locker or a piece of equipment."""

# an OCR read that looks like a room number, on the frame around it (11-10: '2026' on a poster and the 0119 of an emergency phone
# sticker next to a door became rooms). The OCR's text is not in the prompt: told it, the VLM confirmed a Korean nameplate as '1010'.
VERIFY_PROMPT = """The image is a part of a camera frame taken by a robot walking through a building. A text reader found a number that may be a room number inside the red box.
Is the boxed text the room number of a room, printed on that room's number plate or nameplate (mounted on a door or on the wall right next to a door)?
It is NOT a room number when the boxed text is, for example: a phone number or a part of one (e.g. the 0119 of 042-350-0119), an emergency number (119, 112),
a year or a date (e.g. 2026), text on a poster, notice, flyer, sticker or bulletin board, a building directory listing many rooms, a range of rooms or
a number next to an arrow on a directional sign, a floor number, a mailbox, locker, equipment or asset label.
First read the boxed text yourself.
Decide from what the box is on and from the text around it, not from the digits alone.
Answer with JSON only: {"text": "<the boxed text as you read it>", "room_number": true or false, "what": "<a few words: what the boxed text is on>"}"""

# Following "Sign Language: Towards Sign Understanding for Robot Autonomy" (Agrawal, Loo, Zimmerman, Hsu):
# the VLM is told to (i) extract place text, (ii) extract directional symbols, (iii) associate them and
# (iv) emit the cues as (place, form, direction) tuples with directions from a fixed set of eight.
SIGN_PROMPT = """The image is a crop of a navigational sign, photographed roughly head-on. Parse it in four steps:
1. Extract every location / place text on the sign (room ranges such as 3001~3013 or T101~T113 belong to the text of the place).
2. Extract every directional symbol (arrows) on the sign.
3. Associate each place with the arrow that belongs to it (usually the arrow on the same line).
4. Output the navigational cues.
Directions are expressed as seen by a person standing in front of the sign, looking at it. Use exactly one of:
"straight" (arrow points up), "left", "right", "back" (arrow points down), "straight-left", "straight-right", "back-left", "back-right" (diagonal arrows),
"left-then-straight", "right-then-straight", "straight-then-left", "straight-then-right" (bent, L-shaped arrows); use "none" for a place without an arrow.
Read a bent arrow from its tail to its head: a shaft that first runs to the left and then turns up into the head is "left-then-straight"
(go left, then straight ahead); a shaft that first runs up and then turns left into the head is "straight-then-left".
Answer with JSON only: a list of {"place": "<text exactly as printed, keep numbers and ranges>", "form": "text", "direction": "<one of the directions>"}.
Transcribe only what you can read; if the sign is not legible answer []."""


class VLM:
    def __init__(self, model=_MODEL):
        from openai import OpenAI
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            from dotenv import load_dotenv
            for cand in (os.environ.get("REASONNAV_ENV"),
                         os.path.expanduser("~/tips_ws/src/ReasonNav/src/mm_dev/config/.env")):
                if cand and os.path.exists(cand):
                    load_dotenv(cand, override=True)
            key = os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.client = OpenAI(api_key=key, timeout=30.0, max_retries=1)
        self.calls = 0
        self._bad_efforts = set()

    @staticmethod
    def _jpeg(img, quality=92):
        ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, quality])
        return "data:image/jpeg;base64," + base64.b64encode(buf).decode()

    def _complete(self, content, max_tokens):
        """one chat completion; reasoning models (gpt-5*, o3, o4*) take no temperature and spend tokens on thinking"""
        kw = dict(model=self.model, messages=[{"role": "user", "content": content}])
        if self.model.startswith(("gpt-5", "o3", "o4")):
            kw["max_completion_tokens"] = max(4000, max_tokens * 4)
            # gpt-5.1 and later reject "minimal" (400): each call paid an extra round trip before falling back to "low"
            efforts = [e for e in ["minimal", "low", None] if e not in self._bad_efforts]
        else:
            kw.update(max_completion_tokens=max_tokens, temperature=0)
            efforts = [None]
        last = None
        for eff in efforts:
            try:
                k = dict(kw)
                if eff:
                    k["reasoning_effort"] = eff
                r = self.client.chat.completions.create(**k)
                return (r.choices[0].message.content or "").strip()
            except Exception as e:  # noqa: BLE001
                last = e
                if "reasoning_effort" not in str(e) and "nsupported" not in str(e):
                    break
                if eff:
                    self._bad_efforts.add(eff)
        raise last

    def ask(self, img, prompt, max_tokens=500):
        self.calls += 1
        return self._complete([{"type": "text", "text": prompt},
                               {"type": "image_url", "image_url": {"url": self._jpeg(img), "detail": "high"}}], max_tokens)

    def ask_multi(self, images, prompt, max_tokens=500):
        """one question with several images as context (the images are sent as they are, in order)"""
        self.calls += 1
        content = [{"type": "text", "text": prompt}] + [{"type": "image_url", "image_url": {"url": self._jpeg(im, 85), "detail": "high"}} for im in images]
        return self._complete(content, max_tokens)

    def ask_text(self, prompt, max_tokens=500):
        self.calls += 1
        return self._complete(prompt, max_tokens)

    def choose_landmark(self, images, prompt):
        """-> (candidate number | None, reason str, raw text)"""
        raw = self.ask_multi(images, prompt, 600)
        try:
            j = self._json(raw)
            return int(j["choice"]), str(j.get("reason", "")), raw
        except Exception:  # noqa: BLE001
            return None, "", raw

    @staticmethod
    def _json(text):
        text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
        m = re.search(r"(\{.*\}|\[.*\])", text, re.S)
        return json.loads(m.group(1)) if m else None

    def read_plate(self, crop):
        """-> (number str | None, confidence float, raw text)"""
        raw = self.ask(crop, PLATE_PROMPT, 100)
        try:
            j = self._json(raw)
            num = j.get("number") if isinstance(j, dict) else None
            conf = float(j.get("confidence", 0.5)) if isinstance(j, dict) else 0.0
        except Exception:  # noqa: BLE001
            return None, 0.0, raw
        if num is not None:
            # "T133~T146" / "T135-T146" / an arrow is a direction strip: its first number taken as the plate claimed the wrong room
            strip = len(re.findall(r"\d{3,5}", str(num))) > 1 or re.search(r"[~\u2190-\u21ff<>]", str(num))
            num = None if strip else roomno.norm(num)
            if num is None or not (3 <= len(re.sub(r"\D", "", num)) <= 5):
                num = None
        return num, conf, raw

    def verify_room_number(self, img, text):
        """-> (True | False | None, what str, raw text): is the OCR text `text`, boxed in red in `img`, a room's number plate?
        True needs the VLM's own reading of the box to carry the OCR's digits, or one digit swapped when both carry the same letter
        prefix (it read T106 as T105 once). Any other reading (a Korean nameplate OCR'd as '1010' was read '0101' and '101') or an
        answer that does not parse gives None: not settled, check again later."""
        raw = self.ask(img, VERIFY_PROMPT, 150)
        try:
            j = self._json(raw)
            ok = j.get("room_number") if isinstance(j, dict) else None
            if isinstance(ok, str):
                ok = {"true": True, "yes": True, "false": False, "no": False}.get(ok.strip().lower())
        except Exception:  # noqa: BLE001
            return None, "", raw
        if ok is None:
            return None, "", raw
        what = str(j.get("what", ""))[:80]
        if ok and not _same_number(str(j.get("text", "")), str(text)):
            return None, "read %r: %s" % (str(j.get("text", ""))[:16], what), raw
        return bool(ok), what, raw

    def parse_sign(self, crop):
        """-> (cues list, raw text); cues = [{place, direction, lo, hi}] with numeric room ranges extracted"""
        raw = self.ask(crop, SIGN_PROMPT, 700)
        try:
            j = self._json(raw)
        except Exception:  # noqa: BLE001
            return [], raw
        cues = []
        for c in (j if isinstance(j, list) else []):
            if not isinstance(c, dict) or not c.get("place"):
                continue
            place = str(c["place"])
            d = str(c.get("direction", "none")).lower().strip().replace("_", "-").replace(" then ", "-then-").replace(" ", "-")
            d = d.replace("-then-up", "-then-straight").replace("up-then-", "straight-then-").replace("-then-forward", "-then-straight")
            d = SYNONYMS.get(d, d)   # the VLM sometimes names the arrow instead of the direction ("down" = back)
            d = d if d in DIRECTIONS else ("none" if d in ("none", "null", "") else d)
            pre, nums = roomno.range_in(place)
            cues.append({"place": place, "direction": d, "pre": pre,
                         "lo": min(nums) if nums else None, "hi": max(nums) if nums else None})
        return cues, raw


def _same_number(vlm_text, ocr_text):
    """the same digits, or one digit swapped under the same letter prefix ('T105' read for 'T106')"""
    da, db = re.sub(r"[^0-9]", "", vlm_text), re.sub(r"[^0-9]", "", ocr_text)
    if da == db:
        return bool(da)
    pa, pb = re.sub(r"[^A-Z]", "", vlm_text.upper()), re.sub(r"[^A-Z]", "", ocr_text.upper())
    return bool(pa) and pa == pb and len(da) == len(db) and sum(x != y for x, y in zip(da, db)) == 1


def direction_offset(direction):
    """Signed turn (rad, CCW positive) from the viewing direction for a sign direction, None for 'none'. A bent arrow: its first leg."""
    return {"straight": 0.0, "left": np.pi / 2, "right": -np.pi / 2, "back": np.pi,
            "straight-left": np.pi / 4, "straight-right": -np.pi / 4,
            "back-left": 3 * np.pi / 4, "back-right": -3 * np.pi / 4,
            "left-then-straight": np.pi / 2, "right-then-straight": -np.pi / 2,
            "straight-then-left": 0.0, "straight-then-right": 0.0}.get(direction)


def direction_turn(direction):
    """A bent arrow's second leg (rad from the viewing direction, CCW positive); None for every other direction."""
    return {"left-then-straight": 0.0, "right-then-straight": 0.0,
            "straight-then-left": np.pi / 2, "straight-then-right": -np.pi / 2}.get(direction)
