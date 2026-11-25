"""MJPEG http stream of room_perception's /room_finder/debug_image (left | front | right with the detection boxes, 2 Hz).

  http://<AI PC>:<port>/            page with the live image
  http://<AI PC>:<port>/stream      multipart MJPEG
  http://<AI PC>:<port>/snapshot.jpg

The perception thread only hands over the latest message; JPEG encoding happens on the first http request that needs it."""
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np

log = logging.getLogger("debug_stream")

PAGE = b"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Room finder detections</title><style>body{margin:0;background:#111;color:#ccc;font:14px sans-serif}
img{display:block;width:100%;height:auto}p{margin:6px 10px}</style></head>
<body><img src="/stream" alt="waiting for /room_finder/debug_image"><p>left | front | right, 2 Hz.
green door, orange sign, magenta plate</p></body></html>"""


class DebugStream:
    def __init__(self, port, host="0.0.0.0", quality=80):
        self.quality = quality
        self.cv = threading.Condition()
        self.msg, self.seq, self.jpg, self.jpg_seq = None, 0, None, -1
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/":
                    self._send(200, "text/html; charset=utf-8", PAGE)
                elif path == "/snapshot.jpg":
                    seq, jpg = srv.latest(-1, 5.0)
                    self._send(200, "image/jpeg", jpg) if jpg else self._send(503, "text/plain", b"no image yet")
                elif path == "/stream":
                    self.send_response(200)
                    self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    seq = -1
                    try:
                        while True:
                            seq, jpg = srv.latest(seq, 10.0)
                            if jpg is None:
                                continue
                            self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n" % len(jpg))
                            self.wfile.write(jpg + b"\r\n")
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                else:
                    self._send(404, "text/plain", b"not found")

            def _send(self, code, ctype, body):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer((host, port), H)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        log.info("detection stream: http://%s:%d" % (host, port))

    def on_image(self, m):
        """router callback (perception thread): keep only the latest message"""
        with self.cv:
            self.msg, self.seq = m, self.seq + 1
            self.cv.notify_all()

    def latest(self, after_seq, timeout):
        """(seq, jpeg) of the newest image newer than after_seq; (after_seq, None) on timeout"""
        import cv2
        end = time.monotonic() + timeout
        with self.cv:
            while self.seq <= after_seq or self.msg is None:
                left = end - time.monotonic()
                if left <= 0:
                    return after_seq, None
                self.cv.wait(left)
            if self.jpg_seq != self.seq:
                m = self.msg
                im = np.frombuffer(m.data, np.uint8).reshape(m.height, m.width, 3)
                ok, buf = cv2.imencode(".jpg", im, [cv2.IMWRITE_JPEG_QUALITY, self.quality])
                if ok:
                    self.jpg, self.jpg_seq = buf.tobytes(), self.seq
            return self.seq, self.jpg

    def close(self):
        self.httpd.shutdown()
