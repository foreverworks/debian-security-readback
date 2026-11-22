"""Downloads against a local HTTP server that misbehaves on purpose. Plain http is allowed here only
through the `schemes` argument; the command itself takes https and file only."""

import http.server
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import ClassVar

from debian_security_readback.download import download, fetch, redirect_allowed
from debian_security_readback.model import ReadbackError

HTTP = ("http", "https", "file")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/drip":
            self.send_response(200)
            self.send_header("Content-Length", "100000")
            self.end_headers()
            try:
                for _ in range(100000):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                pass
        elif self.path == "/big-declared":
            self.send_response(200)
            self.send_header("Content-Length", str(10 << 20))
            self.end_headers()
        elif self.path == "/big-chunked":
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for _ in range(64):
                    self.wfile.write(b"y" * 65536)
            except OSError:
                pass
        elif self.path == "/to-file":
            self.send_response(302)
            self.send_header("Location", "file:///etc/hostname")
            self.end_headers()
        elif self.path == "/to-ok":
            self.send_response(301)
            self.send_header("Location", "/ok")
            self.end_headers()
        elif self.path == "/ok":
            body = b"good data\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        pass


class Download(unittest.TestCase):
    server: ClassVar[http.server.ThreadingHTTPServer]
    base: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.daemon_threads = True
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.dest = str(self.dir / "file")

    def fetch(self, path: str, deadline: float = 10, max_bytes: int = 1 << 20) -> tuple[str, str]:
        return fetch(self.base + path, self.dest, lambda p: None, 0, deadline, max_bytes, HTTP)

    def test_a_slow_server_cannot_stretch_the_deadline(self) -> None:
        start = time.monotonic()
        with self.assertRaisesRegex(ReadbackError, "deadline"):
            self.fetch("/drip", deadline=1)
        self.assertLess(time.monotonic() - start, 3)

    def test_size_caps(self) -> None:
        with self.assertRaisesRegex(ReadbackError, "allowed"):
            self.fetch("/big-declared", max_bytes=1 << 20)
        with self.assertRaisesRegex(ReadbackError, "allowed"):
            self.fetch("/big-chunked", max_bytes=1 << 20)

    def test_redirects(self) -> None:
        with self.assertRaisesRegex(ReadbackError, "refused a redirect"):
            self.fetch("/to-file")
        self.assertEqual(self.fetch("/to-ok"), (self.dest, ""))
        self.assertEqual(Path(self.dest).read_bytes(), b"good data\n")
        self.assertFalse(redirect_allowed("https://a.example/x", "http://a.example/x", HTTP))
        self.assertTrue(redirect_allowed("https://a.example/x", "https://b.example/y", HTTP))
        self.assertFalse(redirect_allowed("https://a.example/x", "ftp://a.example/x", HTTP))

    def test_http_errors_and_schemes(self) -> None:
        with self.assertRaisesRegex(ReadbackError, "HTTP 404"):
            self.fetch("/missing")
        with self.assertRaisesRegex(ReadbackError, "only https and file"):
            fetch(self.base + "/ok", self.dest, lambda p: None, 0, 10, 1 << 20)

    def test_a_failed_check_keeps_the_old_copy_and_leaves_no_temporary_file(self) -> None:
        Path(self.dest).write_text("old copy\n", encoding="utf-8")
        os.utime(self.dest, (time.time() - 7200, time.time() - 7200))

        def refuse(path: str) -> None:
            self.assertTrue(Path(path).read_bytes().startswith(b"good"))
            raise ReadbackError("not the real thing")

        path, note = fetch(self.base + "/ok", self.dest, refuse, 0, 10, 1 << 20, HTTP)
        self.assertEqual(Path(path).read_text(encoding="utf-8"), "old copy\n")
        self.assertIn("could not be refreshed (not the real thing): using a copy 2 h old", note)
        for path_ in ("/drip", "/big-chunked", "/missing"):
            fetch(self.base + path_, self.dest, lambda p: None, 0, 1, 1 << 20, HTTP)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["file"])
        self.assertEqual(Path(self.dest).read_text(encoding="utf-8"), "old copy\n")

    def test_no_copy_at_all_fails(self) -> None:
        with self.assertRaisesRegex(ReadbackError, "no cached copy"):
            self.fetch("/missing")

    def test_file_urls_and_their_cap(self) -> None:
        src = self.dir / "src"
        src.write_bytes(b"z" * 5000)
        with open(self.dir / "out", "wb") as out:
            download(src.as_uri(), out, 10, 5000)
        self.assertEqual((self.dir / "out").read_bytes(), b"z" * 5000)
        with open(self.dir / "out", "wb") as out, self.assertRaisesRegex(ReadbackError, "allowed"):
            download(src.as_uri(), out, 10, 4999)


if __name__ == "__main__":
    unittest.main()
