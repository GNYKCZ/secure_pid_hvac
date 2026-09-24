"""Client 本机只读 Dashboard：有界事件桥和固定路由，不进入控制线程。"""

from __future__ import annotations

import json
import re
import threading
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from secure_control.experiments.artifacts import ExperimentRecord, load_artifacts
from secure_control.experiments.telemetry_replay import replay_events
from secure_control.simulation.telemetry import (
    BoundedPublisher,
    PublicEvent,
    SessionEnded,
    SessionStarted,
    public_event_json,
)

_RUN_PATH = re.compile(r"\A/api/runs/([0-9]{8}T[0-9]{12}Z-[0-9a-f]{12})/events\Z")
_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


class _Subscriber:
    """每个页面独立有界缓冲；慢读只会丢它自己的 sample。"""

    def __init__(self, capacity: int = 32) -> None:
        self._capacity = capacity
        self._pending: deque[tuple[str, str]] = deque()
        self._condition = threading.Condition()
        self._closed = False
        self.dropped_samples = 0

    def put(self, kind: str, encoded: str) -> None:
        with self._condition:
            if self._closed:
                return
            if len(self._pending) >= self._capacity:
                index = next(
                    (i for i, item in enumerate(self._pending) if item[0] == "sample"), None
                )
                if index is None:
                    if kind == "sample":
                        self.dropped_samples += 1
                        return
                    # 每个会话只有 start/fault/end 三种生命周期事件。
                    self._pending.popleft()
                else:
                    del self._pending[index]
                    self.dropped_samples += 1
            self._pending.append((kind, encoded))
            self._condition.notify()

    def next(self) -> tuple[str, str] | None:
        with self._condition:
            if not self._pending and not self._closed:
                self._condition.wait(timeout=2)
            return self._pending.popleft() if self._pending else None

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()


class DashboardState:
    """只保存允许公开的状态及 CLI 预先选择的 verified run 路径。"""

    def __init__(self, *, max_subscribers: int = 4) -> None:
        self._lock = threading.Lock()
        self._subscribers: set[_Subscriber] = set()
        self._max_subscribers = max_subscribers
        self._stream_slots = threading.BoundedSemaphore(max_subscribers)
        self._bridge_dropped_total = 0
        self._header: str | None = None
        self._terminal: str | None = None
        self._session_id: str | None = None
        self._runs: dict[str, tuple[Path, dict[str, Any]]] = {}
        self._publication = "not_started"
        self.publisher: BoundedPublisher | None = None

    def publish(self, event: PublicEvent) -> None:
        """A07 派发线程上的白名单序列化；控制线程只做 BoundedPublisher 入队。"""
        encoded = public_event_json(event)
        kind = json.loads(encoded)["kind"]
        with self._lock:
            if isinstance(event, SessionStarted):
                self._header = encoded
                self._terminal = None
                self._session_id = event.session_id
                if self._publication == "not_started":
                    self._publication = "running"
            elif isinstance(event, SessionEnded):
                self._terminal = encoded
                if self._publication == "running":
                    self._publication = "saving" if event.status == "completed" else "unavailable"
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            subscriber.put(kind, encoded)

    def subscribe(self) -> _Subscriber | None:
        """晚加入者先得当前 header；已结束会话再给终态，不能补造中间样本。"""
        with self._lock:
            if len(self._subscribers) >= self._max_subscribers:
                return None
            subscriber = _Subscriber()
            if self._header is not None:
                subscriber.put("session_started", self._header)
            if self._terminal is not None:
                subscriber.put("session_ended", self._terminal)
            self._subscribers.add(subscriber)
            return subscriber

    def acquire_stream(self) -> bool:
        """直播与回放共用连接上限，避免慢请求无限占用线程和内存。"""
        return self._stream_slots.acquire(blocking=False)

    def release_stream(self) -> None:
        """任何正常结束、失败或断连都归还一个 SSE 连接槽。"""
        self._stream_slots.release()

    def unsubscribe(self, subscriber: _Subscriber) -> None:
        with self._lock:
            if subscriber in self._subscribers:
                self._subscribers.remove(subscriber)
                self._bridge_dropped_total += subscriber.dropped_samples
        subscriber.close()

    def register_run(self, run_dir: str | Path, *, live_session_id: str | None = None) -> str:
        """仅在 canonical reader 复验后开放回放；不向浏览器暴露本地路径。"""
        record: ExperimentRecord = load_artifacts(run_dir)
        if (
            live_session_id is not None
            and record.provenance.get("public_telemetry_session_id") != live_session_id
        ):
            raise ValueError("正式 run 与公开直播 session ID 不一致")
        entry = {
            "run_id": record.run_id,
            "scenario": record.metadata.name,
            "backend": record.provenance.get("backend", "single_process"),
            "fractional_bits": record.effective_config.get("fractional_bits"),
            "reference_used": record.effective_config.get("reference_used", True),
            "raw_equals_applied": record.effective_config.get("raw_equals_applied", False),
            "live_session_id": live_session_id,
        }
        with self._lock:
            self._runs[record.run_id] = (Path(run_dir), entry)
            if live_session_id is not None:
                self._publication = "verified"
            elif self._publication == "not_started":
                self._publication = "saved_only"
        return record.run_id

    def publication_failed(self) -> None:
        """正式写入或 reader 失败时不留下可回放链接。"""
        with self._lock:
            self._publication = "unavailable"

    def run_path(self, run_id: str) -> Path | None:
        with self._lock:
            value = self._runs.get(run_id)
            return None if value is None else value[0]

    def status(self) -> dict[str, Any]:
        """状态响应只包含公开身份、投递计数和经验证的 run 摘要。"""
        with self._lock:
            runs = [entry.copy() for _, entry in self._runs.values()]
            dropped = self._bridge_dropped_total + sum(
                item.dropped_samples for item in self._subscribers
            )
            session_id, publication = self._session_id, self._publication
            subscriber_count = len(self._subscribers)
        delivery = self.publisher.status if self.publisher is not None else {}
        return {
            "session_id": session_id,
            "publication": publication,
            "runs": runs,
            "subscribers": subscriber_count,
            "bridge_dropped_samples": dropped,
            "publisher_dropped_samples": delivery.get("dropped_samples", 0),
            "publisher_delivery_failed": delivery.get("delivery_failed", False),
        }


class _Handler(BaseHTTPRequestHandler):
    """固定只读 HTTP 路由；Host、路径与请求方法均失败关闭。"""

    server: _HTTPServer

    def log_message(self, format: str, *args: object) -> None:
        # 标准 handler 会记录原始请求路径；不把用户提供的路径写入公开日志。
        return

    def _headers(self, content_type: str, length: int | None = None) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; "
            "style-src 'self'; connect-src 'self'; img-src 'self'; "
            "object-src 'none'; base-uri 'none'",
        )
        if length is not None:
            self.send_header("Content-Length", str(length))

    def _body(self, content: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self._headers(content_type, len(content))
        self.end_headers()
        self.wfile.write(content)

    def _sse_event(self, encoded: str) -> None:
        self.wfile.write(b"data: " + encoded.encode("utf-8") + b"\n\n")
        self.wfile.flush()

    def do_GET(self) -> None:
        host = self.headers.get("Host")
        if host not in (
            f"127.0.0.1:{self.server.server_port}",
            f"localhost:{self.server.server_port}",
        ):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        path = parsed.path
        if path in _ASSETS:
            filename, content_type = _ASSETS[path]
            resource = files("secure_control.experiments").joinpath("dashboard_assets", filename)
            self._body(resource.read_bytes(), content_type)
            return
        if path == "/api/status":
            content = json.dumps(
                self.server.state.status(), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
            self._body(content, "application/json; charset=utf-8")
            return
        if path == "/api/events":
            if not self.server.state.acquire_stream():
                self.send_error(HTTPStatus.SERVICE_UNAVAILABLE)
                return
            subscriber = self.server.state.subscribe()
            if subscriber is None:
                self.server.state.release_stream()
                self.send_error(HTTPStatus.SERVICE_UNAVAILABLE)
                return
            try:
                self.send_response(HTTPStatus.OK)
                self._headers("text/event-stream; charset=utf-8")
                self.end_headers()
                self.connection.settimeout(2)
                try:
                    while True:
                        item = subscriber.next()
                        if item is None:
                            self.wfile.write(b": waiting\n\n")
                            self.wfile.flush()
                        else:
                            self._sse_event(item[1])
                except (BrokenPipeError, ConnectionError, OSError):
                    pass
            finally:
                self.server.state.unsubscribe(subscriber)
                self.server.state.release_stream()
            return
        match = _RUN_PATH.fullmatch(path)
        if match is not None:
            run_path = self.server.state.run_path(match.group(1))
            if run_path is None:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if not self.server.state.acquire_stream():
                self.send_error(HTTPStatus.SERVICE_UNAVAILABLE)
                return
            try:
                try:
                    events = replay_events(run_path)
                except (OSError, ValueError, TypeError):
                    self.send_error(HTTPStatus.CONFLICT)
                    return
                self.send_response(HTTPStatus.OK)
                self._headers("text/event-stream; charset=utf-8")
                self.end_headers()
                self.connection.settimeout(2)
                try:
                    for event in events:
                        self._sse_event(public_event_json(event))
                except (BrokenPipeError, ConnectionError, OSError):
                    pass
            finally:
                self.server.state.release_stream()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, state: DashboardState, port: int) -> None:
        self.state = state
        super().__init__(("127.0.0.1", port), _Handler)


class DashboardServer:
    """只在 Client loopback 启动固定资源和 SSE 的服务生命周期。"""

    def __init__(self, state: DashboardState, *, port: int = 0) -> None:
        self._http = _HTTPServer(state, port)
        self._thread = threading.Thread(
            target=self._http.serve_forever, name="dashboard-http", daemon=True
        )

    @property
    def url(self) -> str:
        """只向本机浏览器给出 loopback 地址。"""
        return f"http://127.0.0.1:{self._http.server_port}/"

    def start(self) -> None:
        """服务请求线程与控制线程完全分离。"""
        self._thread.start()

    def close(self) -> None:
        """退出 CLI 时停止接收页面连接。"""
        self._http.shutdown()
        self._http.server_close()
        self._thread.join(timeout=3)
