"""
The OTA update server (localhost only).

    python server/ota_server.py --release releases/1.1.0 --port 8000
        [--tamper]          # act as a man-in-the-middle: flip bytes in firmware.bin
        [--cut-at BYTES]    # drop the connection after BYTES of firmware.bin

Endpoints:
    GET /manifest.json   -> the signed manifest of the release
    GET /firmware.bin    -> the firmware image

The server is deliberately "dumb" and untrusted: it holds no secrets (the
private key never leaves the signing machine). Security comes entirely from
the device verifying the signature and hash. That is why --tamper can be
implemented right here: whether bytes are changed by the server or by
someone on the network makes no difference to the device.

The demo and the tests start the server in a background thread via
running_server(); the command line above is for manual experiments.
"""

from __future__ import annotations

import argparse
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402

SEND_CHUNK = 4096
TAMPER_OFFSET = 1000   # where the MITM starts flipping bytes
TAMPER_COUNT = 16      # how many bytes it flips


def tamper_bytes(data: bytes) -> bytes:
    """Return a copy of `data` with a few bytes inverted (simulated MITM modification)."""
    modified = bytearray(data)
    start = min(TAMPER_OFFSET, max(0, len(modified) - TAMPER_COUNT))
    for i in range(start, min(start + TAMPER_COUNT, len(modified))):
        modified[i] ^= 0xFF
    return bytes(modified)


class OTARequestHandler(BaseHTTPRequestHandler):
    """Handles GET /manifest.json and GET /firmware.bin. Everything else is 404."""

    server: "OTAServer"

    def do_GET(self) -> None:  # noqa: N802 (name required by http.server)
        """Dispatch a GET request."""
        if self.path == "/manifest.json":
            log.log("SERVER", f"GET /manifest.json -> {len(self.server.manifest)} bytes")
            self._send_headers(200, "application/json", len(self.server.manifest))
            self.wfile.write(self.server.manifest)
        elif self.path == "/firmware.bin":
            self._send_firmware()
        else:
            log.warn("SERVER", f"GET {self.path} -> 404")
            self.send_error(404, "Not Found")

    def _send_headers(self, status: int, content_type: str, length: int) -> None:
        """Send the status line and the basic headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.end_headers()

    def _send_firmware(self) -> None:
        """Stream the firmware, optionally tampered with or cut short."""
        data = self.server.firmware
        if self.server.tamper:
            data = tamper_bytes(data)
            log.warn("ATTACK", f"MITM: flipped {TAMPER_COUNT} bytes at offset {TAMPER_OFFSET} of firmware.bin")

        # Content-Length always announces the FULL size, like a real server
        # whose connection then breaks half-way.
        self._send_headers(200, "application/octet-stream", len(data))
        limit = len(data)
        if self.server.cut_at is not None and self.server.cut_at < len(data):
            limit = self.server.cut_at
        log.log("SERVER", f"GET /firmware.bin -> sending {limit} of {len(data)} bytes")

        for offset in range(0, limit, SEND_CHUNK):
            self.wfile.write(data[offset : min(offset + SEND_CHUNK, limit)])

        if limit < len(data):
            log.warn("SERVER", f"Connection dropped after {limit} bytes (simulated network failure)")
            self.close_connection = True

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        """Silence http.server's default stderr logging (we log ourselves)."""


class OTAServer(ThreadingHTTPServer):
    """An HTTP server bound to localhost that serves one release directory."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        release_dir: Path,
        port: int = 8000,
        tamper: bool = False,
        cut_at: int | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        """Load the release files and bind the socket.

        Use port=0 to let the operating system choose a free port.
        """
        release_dir = Path(release_dir)
        self.manifest = (release_dir / "manifest.json").read_bytes()
        self.firmware = (release_dir / "firmware.bin").read_bytes()
        self.tamper = tamper
        self.cut_at = cut_at
        super().__init__((host, port), OTARequestHandler)

    @property
    def url(self) -> str:
        """Base URL of this server, e.g. http://127.0.0.1:8000"""
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"

    def handle_error(self, request, client_address) -> None:
        """Log client disconnects briefly instead of printing a full traceback."""
        exc = sys.exc_info()[1]
        log.warn("SERVER", f"connection error with client: {exc!r}")


@contextmanager
def running_server(
    release_dir: Path,
    port: int = 0,
    tamper: bool = False,
    cut_at: int | None = None,
) -> Iterator[OTAServer]:
    """Run an OTAServer in a background thread for the duration of a `with` block.

    Example:
        with running_server(Path("releases/1.1.0")) as srv:
            device.check_update(srv.url)
    """
    server = OTAServer(release_dir, port=port, tamper=tamper, cut_at=cut_at)
    # A short poll interval makes shutdown() return quickly between scenarios.
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, name="ota-server", daemon=True
    )
    thread.start()
    flags = []
    if tamper:
        flags.append("TAMPER")
    if cut_at is not None:
        flags.append(f"CUT-AT={cut_at}")
    extra = f" [{', '.join(flags)}]" if flags else ""
    log.log("SERVER", f"Serving {Path(release_dir).name} at {server.url}{extra}")
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        log.log("SERVER", "Stopped")


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point: serve a release until Ctrl+C."""
    parser = argparse.ArgumentParser(description="Serve a signed release over HTTP (localhost).")
    parser.add_argument("--release", type=Path, required=True, help="release dir, e.g. releases/1.1.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--tamper", action="store_true", help="flip bytes in firmware.bin (MITM)")
    parser.add_argument("--cut-at", type=int, default=None, metavar="BYTES", help="drop connection after BYTES")
    args = parser.parse_args(argv)

    server = OTAServer(args.release, port=args.port, tamper=args.tamper, cut_at=args.cut_at)
    log.log("SERVER", f"Serving {args.release} at {server.url} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        log.log("SERVER", "Stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
