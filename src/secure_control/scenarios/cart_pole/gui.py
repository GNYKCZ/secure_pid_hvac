"""倒立摆专用 Tk Client；主线程只显示公开快照和接收外力请求。"""

from __future__ import annotations

import math
import threading
import tkinter as tk
import webbrowser
from collections import deque
from pathlib import Path
from typing import Any

from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import RunControl
from secure_control.experiments.cart_pole_evidence import load_verified_cart_pole_run
from secure_control.experiments.cart_pole_segmented_evidence import (
    open_verified_cart_pole_segmented_run,
    run_cart_pole_segmented,
)
from secure_control.experiments.lan_continuous_profile import (
    load_interactive_cart_pole_experiment,
    load_segmented_experiment,
)
from secure_control.experiments.lan_runner import _run_prepared_client

from .interactive import InteractiveSession


class CartPoleWindow:
    """网络与正式写入在工作线程；画面从已提交状态或正式 reader 来。"""

    def __init__(self, root: tk.Tk, config_path: Path, *, segment_steps=400,
                 mode="segmented") -> None:
        if mode not in ("segmented", "finite"):
            raise ValueError("窗口模式无效。")
        self.mode, self.segment_steps = mode, segment_steps
        self.root = root
        self.messages: deque[tuple[str, object]] = deque(maxlen=64)
        self._frame_lock = threading.Lock()
        self._latest_frame: dict[str, Any] | None = None
        self._latest_phase = self._terminal = self._seek_result = None
        self._seek_request = None
        self._seek_generation = 0
        self._seek_worker = None
        self._seek_wake = threading.Event()
        self.session = InteractiveSession(notify=self._notify)
        self.control = RunControl()
        self.control.bind_stop(self.session.reject_new)
        self._stop_requested = False
        self.config = load_lan_config(config_path, "Client")
        if self.config.experiment_config is None:
            raise ValueError("专用倒立摆 Client 缺少 experiment profile。")
        self.prepared = (
            load_segmented_experiment(self.config.experiment_config, segment_steps, self.session)
            if mode == "segmented" else
            load_interactive_cart_pole_experiment(self.config.experiment_config, self.session)
        )
        self._result: tuple[object, dict[str, object], Path] | None = None
        self._verified = None
        self._final_count = None
        self._closing = False
        self._worker: threading.Thread | None = None
        initial = tuple(self.prepared.effective_config["plant_contract"]["initial_state"])
        self._track_limit_m = float(
            self.prepared.effective_config["plant_contract"]["track_center_limit_m"]
        )
        root.title("Cart-pole secure Client · near-upright simulation")
        root.geometry("860x720")
        self.phase = tk.StringVar(value="初态 / 待连接")
        self.values = tk.StringVar(
            value=f"初态 t=0.00 s · p={initial[0]:+.4f} m · "
                  f"θ={initial[2]:+.4f} rad / {math.degrees(initial[2]):+.2f}°"
        )
        self.detail = tk.StringVar(value="初态尚无控制区间 · 目标 p=0 m, θ=0 rad")
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
        self.stop = tk.Button(controls, text="停止并保存", command=self._request_stop,
                              state="normal" if mode == "segmented" else "disabled")
        self.stop.pack(side="left", padx=12)
        self.replay = tk.Scale(root, from_=0, to=0,
                               orient="horizontal", label="正式结果回放：观测索引",
                               command=self._replay_step, state="disabled", length=760)
        self.replay.pack()
        self.seek_value = tk.StringVar(value="0")
        seek_controls = tk.Frame(root)
        seek_controls.pack()
        self.seek_entry = tk.Entry(seek_controls, textvariable=self.seek_value, width=14,
                                   state="disabled")
        self.seek_entry.pack(side="left")
        self.seek_button = tk.Button(seek_controls, text="跳转到观测", state="disabled",
                                     command=self._seek_exact)
        self.seek_button.pack(side="left")
        self.charts = tk.Button(root, text="查看正式控制图与运动图", state="disabled",
                                command=self._open_charts)
        self.charts.pack(pady=4)
        self.location = tk.StringVar(value="结果目录：尚未发布")
        tk.Label(root, textvariable=self.location, wraplength=820).pack(pady=4)
        root.bind("<Left>", lambda _event: self._request(-1.0))
        root.bind("<Right>", lambda _event: self._request(1.0))
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._draw(initial)

    def _notify(self, kind: str, value: object) -> None:
        """显示槽可合并，终态单独保留；正式段不经过 UI 邮箱。"""
        with self._frame_lock:
            if kind == "frame":
                self._latest_frame = value
            elif kind == "phase":
                self._latest_phase = value
            elif kind in ("complete", "failed"):
                self._terminal = (kind, value)
            elif kind == "seek":
                self._seek_result = value
            else:
                self.messages.append((kind, value))

    def _request_stop(self) -> None:
        """仅提交正常停止；保留已确认画面，最终 N 由后端确定。"""
        if self._stop_requested or self._closing or self._final_count is not None:
            return
        self._stop_requested = True
        self.control.request_stop()
        self.stop.configure(state="disabled")
        self.phase.set("停止请求已接纳：等待当前安全边界及双方回执")

    def _request(self, force_n: float) -> None:
        if self._final_count is None and not self._closing and not self.session.request(force_n):
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
        if self._verified is not None:
            self._queue_seek(int(float(value)))
            return
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
        else:
            self.detail.set("初态尚无控制区间")

    def _seek_exact(self) -> None:
        try:
            k = int(self.seek_value.get())
            if self._final_count is None or not 0 <= k <= self._final_count:
                raise ValueError
        except ValueError:
            self.detail.set("请输入 0 到实际 N 之间的整数观测索引")
            return
        self.replay.set(k)
        self._replay_step(str(k))

    def _queue_seek(self, k: int) -> None:
        with self._frame_lock:
            self._seek_generation += 1
            self._seek_request = (self._seek_generation, k)
        self._seek_wake.set()

    def _read_seek(self) -> None:
        """至多一个在读请求及一个最新请求；旧 generation 不覆盖新选择。"""
        while not self.session.cancelled.is_set():
            self._seek_wake.wait()
            self._seek_wake.clear()
            if self.session.cancelled.is_set():
                return
            with self._frame_lock:
                request, self._seek_request = self._seek_request, None
            if request is None:
                continue
            generation, k = request
            try:
                observation = self._verified.observation_at(
                    k, check=self._seek_check
                )
                self._notify("seek", (generation, observation, None))
            except Exception as error:  # noqa: BLE001 - 回放失败仅报告类别
                self._notify("seek", (generation, None, type(error).__name__))

    def _seek_check(self) -> None:
        if self.session.cancelled.is_set():
            raise RuntimeError("窗口已关闭。")

    def _show_seek(self, observation) -> None:
        state, ideal = observation["state"], observation["ideal_state"]
        self._draw(state)
        self.seek_value.set(str(observation["step"]))
        self.values.set(
            f"正式回放 step={observation['step']} · t={observation['time_s']:.2f} s · "
            f"p={state[0]:+.4f} m · θ={state[2]:+.4f} rad / "
            f"{math.degrees(state[2]):+.2f}° · {observation['status']}"
        )
        if observation["applied_force_n"] is None:
            self.detail.set("初态尚无控制区间")
        else:
            self.detail.set(
                f"上一区间 controller applied={observation['applied_force_n']:+.3f} N · "
                f"外力={observation['disturbance_force_n']:+.1f} N · "
                f"ideal−secure p={ideal[0]-state[0]:+.3e} m · θ={ideal[2]-state[2]:+.3e} rad · "
                f"u={observation['control_error_n']:+.3e} N"
            )

    def _open_charts(self) -> None:
        if self._verified is not None or self._result is not None:
            run_dir = self._verified.path if self._verified is not None else self._result[2]
            for name in ("control.png", "cart_pole_motion.png"):
                webbrowser.open((run_dir / name).as_uri())

    def _run_worker(self) -> None:
        try:
            if self.mode == "segmented":
                result = run_cart_pole_segmented(
                    self.config, prepared=self.prepared, control=self.control,
                    session=self.session, segment_steps=self.segment_steps,
                    phase=lambda value: self._notify("phase", value),
                    on_step=self._confirmed_frame,
                )
                if result["status"] != "complete":
                    self._notify("failed", result["status"])
                    return
                verified = open_verified_cart_pole_segmented_run(result["run_dir"],
                                                                  check=self._seek_check)
                self._notify("complete", verified)
                return
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

    def _confirmed_frame(self, record) -> None:
        """只显示 runner 在物理确认后交付的快照，不另外推进 plant。"""
        snapshot = record.snapshot
        self._notify("frame", {
            "step": record.protocol.global_step + 1, "time_s": snapshot.t_after_s,
            "state": snapshot.observation_after, "status": snapshot.observed_status,
            "applied_force_n": snapshot.applied_force_n,
            "disturbance_force_n": snapshot.disturbance_force_n,
        })

    def start(self) -> None:
        self._worker = threading.Thread(target=self._run_worker, name="cart-pole-client")
        self._worker.start()
        self.root.after(40, self._poll)

    def _poll(self) -> None:
        with self._frame_lock:
            frame, self._latest_frame = self._latest_frame, None
            phase, self._latest_phase = self._latest_phase, None
            terminal, self._terminal = self._terminal, None
            seek, self._seek_result = self._seek_result, None
            messages = tuple(self.messages)
            self.messages.clear()
        if frame is not None and self._final_count is None and not self._closing:
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
        if phase is not None and self._final_count is None and not self._closing:
            labels = {
                "CONNECTING": "连接中", "CONNECTING_NEXT": "下一段握手中",
                "RUNNING": "安全控制运行中", "INPUT": "准备下一控制步",
                "ROUND_IN_FLIGHT": "安全在线轮处理中", "AWAITING_PLANT": "确认物理步中",
                "RECORDING_STEP": "记录已确认步", "ENDING_SEGMENT": "等待双方段尾回执",
                "RECORDING_SEGMENT": "暂存已确认段", "STOPPING": "等待双方停止回执",
                "BACKEND_STOPPED": "后端已正常停止，处理结果中", "REPLAYING": "独立对照重放中",
                "VERIFYING": "验证结果中", "PLOTTING": "保存分桶概要图中",
                "PUBLISHING": "发布完整结果中", "COMPLETE": "完整结果已发布，打开回放中",
                "connecting": "连接中", "connected": "双方已连接 / 已确认离线材料",
                "running": "安全控制运行中", "replaying": "普通支确定性重放中",
                "verifying": "验证与保存中",
            }
            text = labels.get(phase, str(phase))
            if self._stop_requested and phase in (
                "RUNNING", "INPUT", "ROUND_IN_FLIGHT", "AWAITING_PLANT", "RECORDING_STEP",
                "CONNECTING", "CONNECTING_NEXT", "ENDING_SEGMENT", "RECORDING_SEGMENT",
            ):
                text = "停止处理中 · " + text
            self.phase.set(text)
        for kind, value in messages:
            if kind == "queued":
                self.detail.set(f"已排队 {value:+.1f} N；等待下一可用控制步")
            elif kind == "rejected":
                self.detail.set(f"外力请求被拒绝：{value}")
        if terminal is not None:
            kind, value = terminal
            self.stop.configure(state="disabled")
            if kind == "complete" and not self._closing:
                if self.mode == "segmented":
                    self._verified = value
                    self._final_count = value.metadata["N"]
                    status = value.metadata["termination"]["observed_status"]
                    self.phase.set(f"用户停止；结果已验证；N={self._final_count}；停止时 {status}")
                    self._seek_worker = threading.Thread(target=self._read_seek,
                                                          name="cart-pole-replay")
                    self._seek_worker.start()
                else:
                    self._result = value
                    self._final_count = self.prepared.sample_count
                    self.phase.set("完成：正式有限结果已验证；可回放")
                self.replay.configure(state="normal", to=self._final_count)
                self.seek_entry.configure(state="normal")
                self.seek_button.configure(state="normal")
                self.charts.configure(state="normal")
                run_dir = self._verified.path if self._verified is not None else self._result[2]
                self.location.set(f"已验证结果目录：{run_dir}")
                self.replay.set(self._final_count)
                self._replay_step(str(self._final_count))
            elif kind == "failed":
                self.phase.set(f"失败 / 取消：{value}；未确认正式成功")
        if seek is not None and not self._closing:
            generation, observation, error = seek
            if generation == self._seek_generation:
                if error is None:
                    self._show_seek(observation)
                else:
                    self.detail.set(f"回放验证失败：{error}")
        if (self._closing and (self._worker is None or not self._worker.is_alive())
                and (self._seek_worker is None or not self._seek_worker.is_alive())):
            self.root.destroy()
        else:
            self.root.after(40, self._poll)

    def _on_close(self) -> None:
        if self._worker is None:
            self.session.close()
            self.root.destroy()
            return
        self._closing = True
        self.session.close()
        self._seek_wake.set()
        self.phase.set("取消中：等待当前网络超时或安全边界关闭")


def run_window(config_path: Path, *, segment_steps=400, mode="segmented") -> None:
    """配置和 Tk 创建均在拨号前完成；没有窗口时直接失败。"""
    root = tk.Tk()
    try:
        window = CartPoleWindow(root, config_path, segment_steps=segment_steps, mode=mode)
    except Exception:
        root.destroy()
        raise
    window.start()
    root.mainloop()
