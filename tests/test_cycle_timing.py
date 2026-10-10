"""绝对截止、施力事实与有界库存的短契约测试，不进行默认性能长跑。"""

from dataclasses import dataclass, replace
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
    startup = []

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
    def clock(period):
        assert startup == ["collected"]
        startup.append("clock")
        return AbsoluteCycleClock(period, now=lambda: time_ns[0], sleep=lambda seconds: None)

    def collect(generation):
        assert generation == 2
        startup.append("collected")
        return 3

    monkeypatch.setattr(lan_runner.gc, "collect", collect)
    monkeypatch.setattr(lan_runner, "AbsoluteCycleClock", clock)
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
    assert startup == ["collected", "clock"]
    assert report["startup_gc"] == {"duration_ns": 0, "collected": 3}


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


def test_material_pool_budget_uses_public_maxima_and_covers_step_digit_growth(monkeypatch):
    from secure_control.crypto import AdditiveShare
    from secure_control.execution import lan_runtime
    from secure_control.protocol.messages import (
        InputShareMessage,
        PartyOnlineMaterial,
        PartyOnlineRound,
    )

    client, _, _, _, distribution = make_stack()
    encode = lan_runtime.encode_wire_value
    seen = []
    q = client.fixed_point.modulus

    def public_bound(value):
        # 预算必须在任何新鲜随机材料创建前，使用公开 q-1（包括输入向量）。
        assert all(np.all(np.asarray(share.value) == q - 1) for item in value.product_resources
                   for share in (item.a, item.b, item.c))
        assert all(np.all(np.asarray(share.value) == q - 1) for item in value.state_truncation_resources
                   for share in (item.r, item.r_prime))
        assert np.all(np.asarray(value.input_message.value.value) == q - 1)
        seen.append(value)
        return encode(value)

    create = client._material_owner(distribution).create
    def fresh(step):
        assert len(seen) == 1
        return create(step)

    monkeypatch.setattr(lan_runtime, "encode_wire_value", public_bound)
    monkeypatch.setattr(client._material_owner(distribution), "create", fresh)
    pool = _OnlineResourcePool(client, distribution, start=99, slots=4)
    try:
        with pool._condition:
            pool._stop = True
            pool._condition.notify_all()
        pool._thread.join(timeout=5)
        total = 0
        for step in range(99, 103):
            prepared = pool.take(step)
            online = client.bind_online_input(distribution, prepared, [.25], step=step)
            length = sum(len(encode(PartyOnlineMaterial.from_round(PartyOnlineRound(inp, resources))))
                         for inp, resources in ((online.p1_input, online.p1_resources),
                                                (online.p2_input, online.p2_resources)))
            assert length <= pool._encoded_bound(step)
            # 实际输入份额可能取到最大 residue，预算不得使用零占位缩小这部分。
            plan = online.p1_resources.plan
            material = PartyOnlineMaterial.from_round(PartyOnlineRound(online.p1_input, online.p1_resources))
            largest = AdditiveShare(q - 1)
            worst = replace(
                material,
                input_message=InputShareMessage(0, plan.session_id, plan.round_id, step,
                                  AdditiveShare(np.full(plan.input_shape, q - 1, dtype=object))),
                product_resources=tuple(replace(item, a=largest, b=largest, c=largest)
                                        for item in material.product_resources),
                state_truncation_resources=tuple(replace(item, r=largest, r_prime=largest)
                                                 for item in material.state_truncation_resources),
            )
            assert 2 * len(encode(worst)) <= pool._encoded_bound(step)
            total += pool._encoded_bound(step)
            client.abort_round(online)
            pool.owner.discard(prepared)
        assert pool.snapshot()["material_encoded_bound_high_water"] == total
        assert len(seen) == 1
    finally:
        pool.close()


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


def test_control_and_batch_writer_imports_defer_rendering_dependencies():
    """冷启动的控制/记录路径不能提前加载停止后才使用的画布。"""
    import subprocess
    import sys

    subprocess.run([
        sys.executable, "-c",
        ("import sys; from secure_control.experiments import lan_runner, cart_pole_segmented_evidence; "
         "assert 'matplotlib' not in sys.modules; "
         "from secure_control.experiments import EvidenceReportArtifacts; "
         "from secure_control.experiments.evidence_reporting import EvidenceReportArtifacts as actual; "
         "assert EvidenceReportArtifacts is actual"),
    ], check=True, timeout=30)
