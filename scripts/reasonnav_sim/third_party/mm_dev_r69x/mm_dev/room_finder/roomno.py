"""Room numbers with an optional letter prefix: 3018, T138, ER1203.  The letters are the *series*: numeric reasoning
(ranges on signs, interpolation along a corridor, number plausibility) only compares numbers of the same series."""
import re

_RE = re.compile(r"^([A-Z]{0,2})(\d{1,5})([A-Z]?)$")
_IN_TEXT = re.compile(r"(?<![A-Za-z])([A-Za-z]{1,2})?\s?(\d{3,5})(?!\d)")


def norm(s):
    """'t 138' -> 'T138'; None when it is not a room number"""
    t = re.sub(r"[\s\-]", "", str(s)).upper()
    return t if _RE.match(t) else None


def parse(s):
    """-> (prefix letters, number, suffix letter) or None"""
    t = norm(s)
    if t is None:
        return None
    m = _RE.match(t)
    return m.group(1), int(m.group(2)), m.group(3)


def key(n):
    """prefix letters + first two digits ('T13' for 'T138'): the building / floor part used to weigh reads"""
    return re.match(r"[A-Z]*\d{0,2}", str(n)).group(0)


def range_in(text):
    """room numbers printed in a sign entry, e.g. '3001~3013', 'T101~T113', 'T101-113' -> (series, [numbers of that series])"""
    toks = [(l.upper(), int(d)) for l, d in _IN_TEXT.findall(str(text))]
    series = next((l for l, _ in toks if l), "")
    return series, [d for l, d in toks if (l or series) == series]
