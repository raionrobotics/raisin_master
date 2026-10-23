#!/usr/bin/env python3
"""Plain TCP port forwarder, so machines on the robot's wifi reach a service on the AI PC's subnet.

  port_forward.py 8082 192.168.1.77:8082      -> http://<robot PC>:8082 shows the AI PC's detection stream
"""
import argparse
import logging
import socket
import threading


def pump(src, dst):
    try:
        while True:
            b = src.recv(65536)
            if not b:
                break
            dst.sendall(b)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("listen_port", type=int)
    ap.add_argument("target", help="host:port")
    ap.add_argument("--listen-host", default="0.0.0.0")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s port_forward: %(message)s")
    th, tp = a.target.rsplit(":", 1)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((a.listen_host, a.listen_port))
    ls.listen(16)
    logging.info("%s:%d -> %s" % (a.listen_host, a.listen_port, a.target))
    while True:
        c, addr = ls.accept()
        try:
            u = socket.create_connection((th, int(tp)), timeout=3)
            u.settimeout(None)
        except OSError as e:
            logging.warning("%s: target %s unreachable: %s" % (addr[0], a.target, e))
            c.close()
            continue
        for s, d in ((c, u), (u, c)):
            threading.Thread(target=pump, args=(s, d), daemon=True).start()


if __name__ == "__main__":
    main()
