"""Local preview of the split deployment (8.4).

`python -m http.server` cannot preview a split site, and the reason is worth
recording rather than working around silently: once the data lives on its own
origin every fetch for it is cross-origin, so the data host has to send
`Access-Control-Allow-Origin`. GitHub Pages sends `*` on everything, which is
why the split works there without any configuration. Object storage does not --
Cloudflare R2 serves no CORS headers until a policy is attached -- so that is a
migration step, not a detail, and a preview that omitted the header would hide
exactly the thing that breaks first.

Two threaded servers, because the single-threaded one stalls: the page asks for
a manifest and hundreds of type bodies, and serving them one connection at a
time turned a page load into minutes.
"""

from __future__ import annotations

import functools
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _Handler(SimpleHTTPRequestHandler):
    """Static files, plus the headers a real host would send."""

    cors = False

    def end_headers(self) -> None:
        if self.cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        # Pages pins this; matching it here keeps a stale-cache surprise in the
        # preview rather than in production.
        self.send_header("Cache-Control", "max-age=600")
        super().end_headers()

    def log_message(self, *args) -> None:  # pragma: no cover - quiet preview
        pass


def _server(root: Path, port: int, cors: bool) -> ThreadingHTTPServer:
    handler = functools.partial(
        type("Handler", (_Handler,), {"cors": cors}), directory=str(root)
    )
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


def serve(site: Path, data: Path | None, port: int, data_port: int) -> None:
    servers = [(_server(site, port, cors=False), site, port)]
    if data is not None:
        servers.append((_server(data, data_port, cors=True), data, data_port))

    for server, root, bound in servers:
        print(f"  http://127.0.0.1:{bound}/  <- {root}")
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print("\nCtrl-C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print()
    finally:
        for server, _, _ in servers:
            server.shutdown()
