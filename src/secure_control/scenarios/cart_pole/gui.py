"""倒立摆专用 Tk Client；主线程只显示公开快照和接收外力请求。"""

from __future__ import annotations

import math
import queue
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from typing import Any

from secure_control.execution.lan_config import load_lan_config
from secure_control.experiments.cart_pole_evidence import load_verified_cart_pole_run
from secure_control.experiments.lan_continuous_profile import load_interactive_cart_pole_experiment
from secure_control.experiments.lan_runner import _run_prepared_client

from .interactive import InteractiveSession


class CartPoleWindow:
    """网络与正式写入在工作线程；画面从已提交状态或正式 reader 来。"""

    def __init__(self, root: tk.Tk, config_path: Path) -> None:
        self.root = root
        self.messages: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self._frame_lock = threading.Lock()
        self._latest_frame: dict[str, Any] | None = None
        self.session = InteractiveSession(notify=self._notify)
        self.config = load_lan_config(config_path, "Client")
        if self.config.experiment_config is None:
            raise ValueError("专用倒立摆 Client 缺少 experiment profile。")
        self.prepared = load_interactive_cart_pole_experiment(
            self.config.experiment_config, self.session
        )
        self._result: tuple[object, dict[str, object], Path] | None = None
        self._closing = False
        self._worker: threading.Thread | None = None
        initial = tuple(self.prepared.effective_config["plant_contract"]["initial_state"])
        self._track_limit_m = float(
            self.prepared.effective_config["plant_contract"]["track_center_limit_m"]
        )
        root.title("Cart-pole secure Client · near-upright simulation")
        root.geometry("860x650")
        self.phase = tk.StringVar(value="初态 / 待连接")
        self.values = tk.StringVar(
            value=f"初态 t=0.00 s · p={initial[0]:+.4f} m · "
                  f"θ={initial[2]:+.4f} rad / {math.degrees(initial[2]):+.2f}°"
        )
        self.detail = tk.StringVar(value="控制力 0 N · 外力 0 N · 目标 p=0 m, θ=0 rad")
        tk.Label(root, textvariable=self.phase, font=("Arial", 15, "bold")).pack(pady=8)
        self.canvas = tk.Canvas(root, width=820, height=340, bg="white")
        self.canvas.pack()
        tk.Label(root, textvariable=self.values).pack(pady=3)
        tk.Label(root, textvariable=self.detail, wraplength=820).pack(pady=3)
        controls = tk.Frame(root)
        controls.pack(pady=8)
        tk.Button(controls, text="← −1 N / 20 ms", command=lambda: self._request(-1.0)).pack(
            side="left", padx=12
        )
        tk.Button(controls, text="+1 N / 20 ms →", command=lambda: self._request(1.0)).pack(
            side="left", padx=12
        )
        self.replay = tk.Scale(root, from_=0, to=self.prepared.sample_count,
                               orient="horizontal", label="正式结果回放：控制步",
                               command=self._replay_step, state="disabled", length=760)
        self.replay.pack()
        self.charts = tk.Button(root, text="查看正式控制图与运动图", state="disabled",
                                command=self._open_charts)
        self.charts.pack(pady=4)
        root.bind("<Left>", lambda _event: self._request(-1.0))
        root.bind("<Right>", lambda _event: self._request(1.0))
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._draw(initial)

    def _notify(self, kind: str, value: object) -> None:
        if kind == "frame":
            with self._frame_lock:
                self._latest_frame = value
        else:
            self.messages.put((kind, value))

    def _request(self, force_n: float) -> None:
        if self._result is None and not self._closing and not self.session.request(force_n):
            self.detail.set("外力请求未排队：已取消或队列已满")

    def _draw(self, state: tuple[float, ...]) -> None:
        p, _, theta, _ = state
        self.canvas.delete("all")
        center = 410
        track_y = 260
        cart_x = center + 330 * p / self._track_limit_m
        self.canvas.create_line(80, track_y + 30, 740, track_y + 30, width=4)
        self.canvas.create_line(center, 80, center, track_y + 50, fill="#888", dash=(4, 4))
        self.canvas.create_rectangle(cart_x - 40, track_y - 18, cart_x + 40, track_y + 20,
                                     fill="#2b75b8")
        self.canvas.create_oval(cart_x - 27, track_y + 15, cart_x - 13, track_y + 29,
                                fill="black")
        self.canvas.create_oval(cart_x + 13, track_y + 15, cart_x + 27, track_y + 29,
                                fill="black")
        self.canvas.create_line(cart_x, track_y - 18,
                                cart_x - 155 * math.sin(theta),
                                track_y - 18 - 155 * math.cos(theta),
                                fill="#c55a28", width=8)
        self.canvas.create_text(center, 320, text="轨道中心 / 目标 p=0 m, θ=0 rad")

    def _replay_step(self, value: str) -> None:
        if self._result is None:
            return
        _record, sidecar, _run_dir = self._result
        step = int(float(value))
        secure = sidecar["branches"]["secure"]
        ideal = sidecar["branches"]["ideal"]
        state = tuple(secure["observations"][step])
        self._draw(state)
        self.values.set(
            f"正式回放 t={sidecar['time_s'][step]:.2f} s · step={step} · "
            f"p={state[0]:+.4f} m · θ={state[2]:+.4f} rad / {math.degrees(state[2]):+.2f}° · "
            f"{secure['statuses'][step]}"
        )
        if step > 0:
            self.detail.set(
                f"上一区间 controller applied={_record.result.control_secure[step - 1, 0]:+.3f} N · "
                f"外力={sidecar['disturbance_force_n'][step - 1]:+.1f} N · "
                f"ideal−secure p={ideal['observations'][step][0] - state[0]:+.3e} m · "
                f"θ={ideal['observations'][step][2] - state[2]:+.3e} rad · "
                f"u={_record.result.control_ideal[step - 1, 0] - _record.result.control_secure[step - 1, 0]:+.3e} N"
            )

    def _open_charts(self) -> None:
        if self._result is not None:
            run_dir = self._result[2]
            for name in ("control.png", "cart_pole_motion.png"):
                webbrowser.open((run_dir / name).resolve().as_uri())

    def _run_worker(self) -> None:
        try:
            result = _run_prepared_client(
                self.config, self.prepared,
                phase=lambda value: self._notify("phase", value),
                cancelled=self.session.cancelled,
                publication_guard=self.session.publication_guard,
            )
            record, sidecar = load_verified_cart_pole_run(result["run_dir"])
            self._notify("complete", (record, sidecar, Path(result["run_dir"])))
        except Exception as error:  # noqa: BLE001 - UI 不展示异常载荷或协议秘密
            category = "cancelled" if self.session.cancelled.is_set() else type(error).__name__
            self._notify("failed", category)
        finally:
            self.session.stop_accepting()

    def start(self) -> None:
        self._worker = threading.Thread(target=self._run_worker, name="cart-pole-client")
        self._worker.start()
        self.root.after(40, self._poll)

    def _poll(self) -> None:
        with self._frame_lock:
            frame, self._latest_frame = self._latest_frame, None
        if frame is not None and self._result is None and not self._closing:
            self._draw(frame["state"])
            self.values.set(
                f"已提交 step={frame['step']} · 仿真 t={frame['time_s']:.2f} s · "
                f"p={frame['state'][0]:+.4f} m · θ={frame['state'][2]:+.4f} rad / "
                f"{math.degrees(frame['state'][2]):+.2f}° · {frame['status']}"
            )
            self.detail.set(
                f"上一控制区间 applied={frame['applied_force_n']:+.3f} N · "
                f"外力={frame['disturbance_force_n']:+.1f} N · 目标 0"
            )
        while not self.messages.empty():
            kind, value = self.messages.get_nowait()
            if kind == "phase" and not self._closing:
                labels = {"connecting": "连接中", "connected": "双方已连接 / 已确认离线材料",
                          "running": "安全控制运行中", "replaying": "普通支确定性重放中",
                          "verifying": "验证与保存中"}
                self.phase.set(labels.get(value, str(value)))
            elif kind == "queued":
                self.detail.set(f"已排队 {value:+.1f} N；等待下一可用控制步")
            elif kind == "rejected":
                self.detail.set(f"外力请求被拒绝：{value}")
            elif kind == "complete" and not self._closing:
                self._result = value
                self.phase.set("完成：正式结果已验证；可拖动滑块回放")
                self.replay.configure(state="normal")
                self.charts.configure(state="normal")
                self.replay.set(self.prepared.sample_count)
            elif kind == "failed":
                self.phase.set(f"失败 / 取消：{value}；未确认正式成功")
        if self._closing and self._worker is not None and not self._worker.is_alive():
            self.root.destroy()
        else:
            self.root.after(40, self._poll)

    def _on_close(self) -> None:
        if self._result is not None or self._worker is None or not self._worker.is_alive():
            self.root.destroy()
            return
        self._closing = True
        self.session.close()
        self.phase.set("取消中：等待当前网络超时或安全边界关闭")


def run_window(config_path: Path) -> None:
    """配置和 Tk 创建均在拨号前完成；没有窗口时直接失败。"""
    root = tk.Tk()
    try:
        window = CartPoleWindow(root, config_path)
    except Exception:
        root.destroy()
        raise
    window.start()
    root.mainloop()
