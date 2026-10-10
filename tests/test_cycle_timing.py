"""绝对截止、施力事实与有界库存的短契约测试，不进行默认性能长跑。"""

from dataclasses import dataclass
from types import SimpleNamespace

import numpy as np
import pytest
from test_cart_pole_lan import OBSERVER_PROFILE
from test_two_party_protocol import make_stack

from secure_control.core import ControllerSpec
from secure_control.execution.cycle_timing import (
    AbsoluteCycleClock,
    CycleDeadlineExceeded,
    CycleTiming,
    check_deadline,
    network_deadline,
    remaining_seconds,
)
from secure_control.execution.lan_runtime import (
    LanLifecycleSnapshot,
    RunControl,
    _OnlineResourcePool,
)
from secure_control.experiments import lan_runner
from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
from secure_control.protocol import ControllerRangeContract
from secure_control.scenarios.cart_pole.interactive import InteractiveSession


def test_absolute_clock_keeps_initial_epoch_and_records_oversleep():
    clock_time = [100]
    def sleep(seconds):
        clock_time[0] += round(seconds * 1e9) + 3
    clock = AbsoluteCycleClock(.02, now=lambda: clock_time[0], sleep=sleep)
    assert clock.wait(0) == (100, 20_000_100)
    assert clock.wait(1) == (20_000_100, 40_000_100)
    assert clock_time[0] == 20_000_103
    clock_time[0] = 200_000_100
    assert clock.wait(2) == (40_000_100, 60_000_100)
    with pytest.raises(CycleDeadlineExceeded):
        check_deadline(60_000_100, "sample", now=lambda: clock_time[0])
    with pytest.raises(ValueError):
        CycleTiming("r", None, None, 0, 0, None, 20, 100, True, 120)


def test_transport_deadlines_keep_legacy_clock_and_use_qpc_for_new_cycles(monkeypatch):
    from secure_control.execution import cycle_timing, lan_transport, localhost_transport
    monkeypatch.setattr(cycle_timing.time, "monotonic", lambda: 100.)
    monkeypatch.setattr(cycle_timing.time, "perf_counter_ns", lambda: 1_000_000_000)
    assert remaining_seconds(100.1) == pytest.approx(.1)
    deadline = network_deadline(.01, 2_000_000_000)
    assert lan_transport._remaining(deadline) == pytest.approx(.01)
    sock = SimpleNamespace(settimeout=lambda value: setattr(sock, "remaining", value))
    localhost_transport._set_remaining_timeout(sock, deadline)
    assert sock.remaining == pytest.approx(.01)
    early_cycle = network_deadline(30, 1_005_000_000)
    assert lan_transport._remaining(early_cycle) == pytest.approx(.005)
    monkeypatch.setattr(cycle_timing.time, "perf_counter_ns", lambda: 1_005_000_000)
    with pytest.raises(lan_transport.LanTimeoutError):
        lan_transport._remaining(early_cycle)
    with pytest.raises(localhost_transport.LocalhostTransportTimeout):
        localhost_transport._set_remaining_timeout(sock, early_cycle)


@dataclass
class _Segment:
    index: int


@pytest.mark.parametrize("late_phase", ["before_device", "after_device", "maintenance"])
def test_unique_runner_rejects_late_command_and_keeps_applied_fact(monkeypatch, late_phase):
    time_ns = [0]
    control, session = RunControl(), InteractiveSession()
    applied, timings = [], []

    class Runtime:
        def __init__(self, *args, **kwargs):
            self.phase = "RUNNING"
            self.confirmed_step_count = self.protocol_committed_count = 0
            self.run_id = "public-run"
            self.resource_counts = {}
            self.public_setup = None
            self.cycle_phase_ns = {}
            self.cycle_queue_levels = {}

        def snapshot(self):
            return LanLifecycleSnapshot(self.phase, self.run_id, "public-session", "epoch",
                                        0, 0, 0, "round", self.protocol_committed_count,
                                        self.confirmed_step_count, 0, 0, 0)

        @property
        def segment_full(self):
            return late_phase == "maintenance" and self.confirmed_step_count == 1

        def step(self, value, **kwargs):
            assert kwargs["deadline_ns"] == 20_000_000
            self.protocol_committed_count += 1
            self.phase = "AWAITING_PLANT"
            time_ns[0] += 21_000_000 if late_phase == "before_device" else 5_000_000
            return SimpleNamespace(global_step=0, raw_control=(1.,), round_id="round")

        def confirm_applied(self, identity):
            self.confirmed_step_count += 1
            self.phase = "RUNNING"

        def end_segment(self, **kwargs):
            self.phase = "CONNECTING_NEXT"
            time_ns[0] += 21_000_000
            return _Segment(0)

        def close(self):
            self.phase = "FAILED"

    def advance(step, raw, *, deadline_ns=None):
        applied.append(step)
        time_ns[0] += 21_000_000 if late_phase == "after_device" else 1_000_000
        return {}

    monkeypatch.setattr(lan_runner, "LanSegmentedRuntime", Runtime)
    monkeypatch.setattr(lan_runner, "perf_counter_ns", lambda: time_ns[0])
    monkeypatch.setattr(lan_runner, "AbsoluteCycleClock", lambda period: AbsoluteCycleClock(
        period, now=lambda: time_ns[0], sleep=lambda seconds: None,
    ))
    monkeypatch.setattr(lan_runner, "check_deadline", lambda deadline, phase: check_deadline(
        deadline, phase, now=lambda: time_ns[0],
    ))
    experiment = SimpleNamespace(
        spec=SimpleNamespace(state_dimension=4), context=None, contract=None,
        security_parameter=8, evidence=None, segment_capacity=1, recheck_sources=lambda: None,
        scene=SimpleNamespace(period=.02, controller_input=lambda: [0], advance=advance),
    )
    report = lan_runner._run_prepared_segmented(
        None, experiment, control=control, session=session, realtime=True,
        material_slots=0, on_cycle=timings.append,
    )
    assert report["status"] == "failed"
    assert len(timings) == 1 and timings[0].global_step == 0
    assert timings[0].protocol_committed_count == 1
    assert applied == ([] if late_phase == "before_device" else [0])
    assert timings[0].physically_confirmed_count == len(applied)
    assert timings[0].status == ("miss_before_apply" if not applied else "miss_after_apply")
    assert timings[0].cycle_completed_ns is None


def test_material_pool_shortage_never_generates_on_control_thread_and_close_burns(monkeypatch):
    client, _, _, _, distribution = make_stack()
    pool = _OnlineResourcePool(client, distribution, start=0, slots=4)
    try:
        with pool._condition:
            pool._stop = True
            pool._condition.notify_all()
        pool._thread.join(timeout=5)
        tokens = [pool.take(step) for step in range(4)]
        assert len({token.p1_resources.plan.round_id for token in tokens}) == 4
        with pytest.raises(RuntimeError, match="短缺"):
            pool.take(4)
        assert not client._issued_rounds
        assert pool.snapshot()["material_reserved_bytes"] <= 8 * 1024 * 1024
        for token in tokens:
            pool.owner.discard(token)
            assert token.p1_resources.aborted_count == 11
    finally:
        pool.close()
    # 公开计划本身已超过编码预留时，必须在任何 crypto 创建前拒绝。
    large = client.distribute_controller(
        ControllerSpec(A=.5 * np.eye(16), B=np.zeros((16, 1)), C=np.zeros((1, 16)),
                       D=np.zeros((1, 1)), x0=np.zeros(16)),
        ControllerRangeContract(state_payload_bounds=(256,) * 16, input_payload_bounds=(64,)),
    )
    owner = client._material_owner(large)
    monkeypatch.setattr(owner, "create", lambda *args, **kwargs: pytest.fail("material was created"))
    with pytest.raises(ValueError, match="编码预算"):
        _OnlineResourcePool(client, large, start=0, slots=4)


def test_scene_rechecks_deadline_immediately_before_device_signal(monkeypatch):
    """advance 内部工作耗尽预算时，真正的 send_control 仍不能发出。"""
    from secure_control.execution import cycle_timing
    scene = load_segmented_experiment(OBSERVER_PROFILE, 8, InteractiveSession()).scene
    scene.controller_input()
    time_ns, sent = [0], []
    monkeypatch.setattr(cycle_timing.time, "perf_counter_ns", lambda: time_ns[0])
    monkeypatch.setattr(scene.device, "request_disturbance",
                        lambda *args: time_ns.__setitem__(0, 21_000_000))
    monkeypatch.setattr(scene.device, "send_control", sent.append)
    with pytest.raises(CycleDeadlineExceeded) as caught:
        scene.advance(0, [0], deadline_ns=20_000_000)
    assert caught.value.phase == "BEFORE_DEVICE_SIGNAL" and not sent
    assert scene._step == 0
