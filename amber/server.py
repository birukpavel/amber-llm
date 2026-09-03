"""Локальный веб-интерфейс. Запуск: python3 -m amber.server

Только stdlib. Результаты приходят потоком (SSE), чтобы было видно
каждый пробник в момент выполнения, а не общий итог в конце.
"""

from __future__ import annotations

import argparse
import json
import webbrowser
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .client import LLMClient
from .evolve.genome import RISK_TITLES, RISKS, STYLE_TITLES, STYLES
from .evolve.loop import search
from .probes import OWASP_TITLES, PROBES, SECRET, SYSTEM_PROMPT
from .runner import iter_scan, summarize

WEB_DIR = Path(__file__).parent / "web"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # тише в консоли
        return

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        route = urlparse(self.path)

        if route.path in ("/", "/index.html"):
            self._send(200, (WEB_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
            return

        if route.path == "/app.js":
            self._send(200, (WEB_DIR / "app.js").read_bytes(), "text/javascript; charset=utf-8")
            return

        if route.path == "/api/catalog":
            payload = {
                "system_prompt": SYSTEM_PROMPT,
                "secret": SECRET,
                "probes": [asdict(p) for p in PROBES],
                "owasp_titles": OWASP_TITLES,
            }
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
            return

        if route.path == "/api/health":
            params = parse_qs(route.query)
            url = params.get("url", ["http://localhost:1234"])[0]
            alive = LLMClient(url, "probe").ping()
            self._send(200, json.dumps({"alive": alive, "url": url}).encode(), "application/json")
            return

        if route.path == "/api/scan":
            self._stream_scan(parse_qs(route.query))
            return

        if route.path == "/api/grid":
            payload = {
                "risks": RISKS, "styles": STYLES,
                "risk_titles": RISK_TITLES, "style_titles": STYLE_TITLES,
            }
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
            return

        if route.path == "/api/evolve":
            self._stream_evolve(parse_qs(route.query))
            return

        self._send(404, b"not found", "text/plain")

    def _stream_scan(self, params: dict[str, list[str]]) -> None:
        url = params.get("url", ["http://localhost:1234"])[0]
        model = params.get("model", ["local-model"])[0]
        categories = params.get("category", [])

        probes = [p for p in PROBES if not categories or p.category in categories]

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(event: str, data: dict) -> None:
            chunk = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            self.wfile.write(chunk.encode("utf-8"))
            self.wfile.flush()

        emit("start", {"total": len(probes), "model": model, "endpoint": url})

        client = LLMClient(url, model)
        results = []
        try:
            for index, result in enumerate(iter_scan(client, probes), start=1):
                results.append(result)
                emit("result", {"index": index, **asdict(result)})
            emit("done", summarize(results, model, url))
        except (BrokenPipeError, ConnectionResetError):
            return


    def _stream_evolve(self, params: dict[str, list[str]]) -> None:
        url = params.get("url", ["http://localhost:1234"])[0]
        model = params.get("model", ["local-model"])[0]
        gens = int(params.get("generations", ["60"])[0])
        seed = int(params.get("seed", ["0"])[0])

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(event: str, data: dict) -> None:
            chunk = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            self.wfile.write(chunk.encode("utf-8"))
            self.wfile.flush()

        client = LLMClient(url, model)
        try:
            for ev in search(client, gens, seed):
                emit("done" if ev["kind"] == "done" else "candidate", ev)
        except (BrokenPipeError, ConnectionResetError):
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="amber — локальный веб-интерфейс")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--no-open", action="store_true", help="не открывать браузер")
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    address = f"http://127.0.0.1:{args.port}"
    print(f"Интерфейс сканера: {address}\nCtrl+C — остановить")
    if not args.no_open:
        webbrowser.open(address)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nостановлен")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
