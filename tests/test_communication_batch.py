"""#116：批量计划只使用公开拓扑与原有资源次序。"""

import random
import socket
import time
from dataclasses import replace
from fractions import Fraction
from queue import Queue
from threading import Thread
from types import SimpleNamespace

import pytest

from secure_control.crypto import AdditiveShare
from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
from secure_control.execution.localhost_codec import (
    SCHEMA_VERSION,
    LanHelloPayload,
    LocalhostCodecError,
    ScalarFrameV3,
    ScalarLayerPayloadV1,
    WireEnvelope,
    decode_envelope,
    encode_envelope,
    encode_scalar_frame_v3,
)
from secure_control.execution.localhost_transport import (
    LocalhostTransportProtocolError,
    send_envelope,
    send_frame,
)
from secure_control.protocol import P1, P2
from secure_control.protocol.arithmetic import (
    ScalarGate,
    ScalarPartyExecutor,
    ScalarProgram,
    build_scalar_layer_plan,
    prepare_scalar_round,
)
from secure_control.protocol.coordinator import (
    LocalProtocol3PartyEndpoint,
    Protocol3Orchestrator,
    rehydrate_offline_material,
    rehydrate_online_material,
    stage_protocol3_batch,
)
from secure_control.protocol.messages import (
    PartyOfflineMaterial,
    PartyOnlineMaterial,
    PartyOnlineRound,
    ProductMaskPayload,
    Protocol3BatchPayload,
    public_step_plan_sha256,
)


def test_encoded_material_matches_original_codec_and_rejects_copied_capabilities():
    """逐字节比较原 wire；复制/错步/跨Client/重复领取不能签发输出。"""
    from copy import copy

    import numpy as np
    from test_two_party_protocol import make_stack

    from secure_control.execution.localhost_codec import (
        _encode_online_fragment,
        _EncodedOnlinePayload,
    )
    from secure_control.protocol.messages import InputShareMessage

    client, _, _, _, distribution = make_stack()
    owner = client._material_owner(distribution)
    source = object()
    owner.open_encoded_source(source)
    prepared = owner.create(999, rng=random.Random(31))
    plan = prepared.p1_resources.plan
    fragments = tuple(_encode_online_fragment(v, client.fixed_point.modulus)
                      for v in (prepared.p1_resources, prepared.p2_resources))
    cap = owner.register_encoded(source, plan, fragments)
    assert not client._issued_rounds
    for invalid, step in ((copy(cap), 999), (cap, 998)):
        with pytest.raises(ValueError, match="原始"):
            client._bind_encoded_input(distribution, invalid, [.25], step=step)
    other, _, _, _, other_distribution = make_stack()
    with pytest.raises(ValueError, match="原始"):
        other._bind_encoded_input(other_distribution, cap, [.25], step=999)
    with pytest.raises(ValueError, match="input_payload_bounds"):
        client._bind_encoded_input(distribution, cap, [1000.], step=999)
    current = client._bind_encoded_input(distribution, cap, [.25], step=999)
    with pytest.raises(ValueError, match="原始"):
        client._bind_encoded_input(distribution, cap, [.25], step=999)
    for party, resources, inp, fragment in zip((0, 1),
        (prepared.p1_resources, prepared.p2_resources), (current.p1_input, current.p2_input), fragments, strict=True):
        # 额外覆盖 q-1/0 输入、UTF-8转义、序列位宽，静态材料来自受限类型。
        for sequence in (0, 999999):
            for share in (inp.value, AdditiveShare(np.array([client.fixed_point.modulus - 1], dtype=object)),
                          AdditiveShare(np.array([2**256 - 1], dtype=object)), AdditiveShare(np.array([0], dtype=object))):
                input_message = InputShareMessage(party, plan.session_id, plan.round_id, plan.step, share)
                original = WireEnvelope(SCHEMA_VERSION, "request", "Client", f"P{party + 1}",
                    sequence, "online", plan.session_id, plan.round_id, plan.step, None,
                    PartyOnlineMaterial.from_round(PartyOnlineRound(input_message, resources)))
                encoded = replace(original, payload=_EncodedOnlinePayload(input_message, plan, fragment))
                assert encode_envelope(original) == encode_envelope(encoded)
                assert decode_envelope(encode_envelope(encoded)).payload.plan == plan
                with pytest.raises(LocalhostCodecError, match="关联"):
                    replace(encoded, step=998)
    client.abort_round(current)
    assert not client._issued_rounds
    owner.discard(prepared)
    # 独立受限类型的转义身份，避免模板拼接只对ASCII随机ID等价。
    from secure_control.protocol.roles import Client, _create_resource_pair
    escaped = Client._resource_plan(owner.layout, 'session-"汉\\', 'round-"汉\\', 1000)
    for resources in _create_resource_pair(escaped, client.multiplier, client.truncation, rng=random.Random(39)):
        inp = InputShareMessage(resources.recipient, escaped.session_id, escaped.round_id, 1000,
                                AdditiveShare(np.array([0], dtype=object)))
        original = WireEnvelope(SCHEMA_VERSION, "request", "Client", f"P{resources.recipient + 1}", 33,
            "online", escaped.session_id, escaped.round_id, 1000, None,
            PartyOnlineMaterial.from_round(PartyOnlineRound(inp, resources)))
        fast = replace(original, payload=_EncodedOnlinePayload(inp, escaped,
                                    _encode_online_fragment(resources, client.fixed_point.modulus)))
        assert encode_envelope(fast) == encode_envelope(original)
        assert decode_envelope(encode_envelope(fast)).payload.plan == escaped


@pytest.mark.parametrize(("dimensions", "ell", "shift"), (((1, 2, 1), 0, 0), ((2, 1, 3), 7, 0), ((4, 2, 1), 32, 32)))
def test_s19_public_plan_digest_matches_independent_old_bytes_for_every_field(monkeypatch, dimensions, ell, shift):
    """旧asdict/JSON/domain/SHA独立oracle；逐字段及资源次序变化都必须参与。"""
    import hashlib
    import json
    from copy import copy
    from dataclasses import asdict, fields, is_dataclass

    from secure_control.protocol import Client, messages

    ledger = messages.ControllerScaleLedger(ell, ell, shift, shift, ell+1, ell+1,
        ell+shift, shift, 2*ell+1, 2*ell+1)
    plan = Client._resource_plan(messages.ControllerLayout(*dimensions, ledger),
        '会话"\\\n', '轮次\\"\t', 2**80+3)
    recorded = []
    def digest(encoded):
        recorded.append(encoded)
        return hashlib.sha256(encoded)
    monkeypatch.setattr(messages, "sha256", digest)
    def check(value):
        expected = b"control-batch-v1-plan\0"+json.dumps(asdict(value), sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        assert messages.public_step_plan_sha256(value) == hashlib.sha256(expected).hexdigest()
        assert recorded.pop() == expected
        return expected
    original = check(plan)
    def changes(value):
        if is_dataclass(value):
            for item in fields(value):
                for child in changes(getattr(value, item.name)):
                    changed = copy(value)
                    # 摘要原本不再验证ledger；独立改变每一字段检查是否被遗漏。
                    object.__setattr__(changed, item.name, child)
                    yield changed
        elif isinstance(value, tuple):
            for i, child in enumerate(value):
                for changed in changes(child):
                    yield value[:i]+(changed,)+value[i+1:]
            if len(value)>1 and value != value[::-1]:
                yield value[::-1]
        else:
            yield value+1 if type(value) is int else value+"变" if type(value) is str else 0
    for changed in changes(plan):
        assert check(changed) != original


def test_s19_plan_digest_avoids_recursive_copy_but_preserves_failure_types(monkeypatch):
    import hashlib
    import json
    from dataclasses import asdict

    from test_two_party_protocol import make_stack

    from secure_control.protocol import Client, messages

    _, _, _, _, distribution = make_stack()
    plan = Client._resource_plan(distribution.p1.layout, "会话", "round", 0)
    expected = hashlib.sha256(b"control-batch-v1-plan\0"+json.dumps(asdict(plan), sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    def forbidden(value):
        pytest.fail("摘要不得先递归深复制整棵计划")
    monkeypatch.setattr(messages, "asdict", forbidden)
    assert messages.public_step_plan_sha256(plan) == expected
    for invalid in (None, {}, messages.StepResourcePlan, SimpleNamespace()):
        with pytest.raises(TypeError, match="StepResourcePlan"):
            messages.public_step_plan_sha256(invalid)
    cyclic = []
    cyclic.append(cyclic)
    for invalid in (replace(plan, step=float("nan")), replace(plan, round_id=object()),
                    replace(plan, scale_ledger=messages.ControllerScaleLedger), replace(plan, state_shape=cyclic)):
        try:
            json.dumps(asdict(invalid), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as old_error:
            with pytest.raises(type(old_error)):
                messages.public_step_plan_sha256(invalid)
        else:
            pytest.fail("非法fixture必须被旧oracle拒绝")


def test_worker_take_shortage_never_waits_for_ipc_or_creates_material():
    from collections import deque
    from threading import Condition

    from secure_control.execution._material_worker import _MaterialWorkerPool

    pool = _MaterialWorkerPool.__new__(_MaterialWorkerPool)
    pool._condition, pool._queue = Condition(), deque()
    pool._stop, pool._error = False, None
    pool._process = SimpleNamespace(is_alive=lambda: True)
    # 没有通道/工厂/等待接口，短缺路径仍立即明确失败。
    with pytest.raises(RuntimeError, match="库存短缺"):
        pool.take(0)


def test_worker_close_discards_taken_unbound_capability_and_start_error_is_public(monkeypatch):
    import multiprocessing as mp

    from test_two_party_protocol import make_stack

    from secure_control.execution._material_worker import _MaterialWorkerPool

    client, _, _, _, distribution = make_stack()
    pool = _MaterialWorkerPool(client, distribution, run_id="run", epoch="epoch", slots=2)
    cap = pool.take(0)
    with pytest.raises(RuntimeError, match="尚未绑定"):
        pool.take(1)
    pool.close()
    with pytest.raises(ValueError, match="原始"):
        client._bind_encoded_input(distribution, cap, [.25], step=0)
    assert not client._issued_rounds and not pool.snapshot()["cleanup_failed"]
    def failed_start(process):
        raise OSError("private test startup error")
    monkeypatch.setattr(mp.get_context("spawn").Process, "start", failed_start)
    other, _, _, _, other_distribution = make_stack()
    with pytest.raises(OSError) as caught:
        _MaterialWorkerPool(other, other_distribution, run_id="other-run", epoch="other-epoch", slots=2)
    summary = caught.value._public_material_summary
    assert summary["claimed"] == 0 and summary["worker_exited"] and summary["receiver_exited"]
    assert summary["credit_thread_exited"] and summary["worker"] is None
    assert "private test" not in str(summary)


def test_worker_package_has_strict_identity_credit_shape_and_bounded_bytes():
    """私有包篡改/重复/跨epoch/截断/超限均拒绝；验证不恢复数值树。"""
    import struct

    from test_two_party_protocol import make_stack

    from secure_control.execution._material_worker import _package, _unpack, _WorkerSpec
    from secure_control.execution.localhost_codec import (
        _canonical_json,
        _encode_online_fragment,
        _load_json,
    )

    client, _, _, _, distribution = make_stack()
    spec = _WorkerSpec(distribution.p1.layout, client.fixed_point.modulus, 8, 8, None, None,
                       'run-"汉', distribution.session_id, "epoch", 0, 16)
    prepared = client.precompute_online_resources(distribution, step=0)
    plan = prepared.p1_resources.plan
    fragments = tuple(_encode_online_fragment(v, spec.modulus) for v in
                      (prepared.p1_resources, prepared.p2_resources))
    packet = _package(spec, plan, fragments, 100, 50)
    decoded, actual, _ = _unpack(spec, packet, 0)
    assert decoded == plan and actual == fragments and 2 * len(packet) < 512 * 1024
    size = struct.unpack(">I", packet[1:5])[0]
    header = _load_json(packet[5:5 + size])
    for field, value in (("version", True), ("step", False), ("epoch", "old"),
                         ("recipients", [1, 0]), ("recipients", [False, 1]), ("plan", "0" * 64),
                         ("lengths", [1, 1]), ("cpu_ns", 1.0)):
        changed = _canonical_json({**header, field: value})
        invalid = b"M" + struct.pack(">I", len(changed)) + changed + packet[5 + size:]
        with pytest.raises(ValueError):
            _unpack(spec, invalid, 0)
    for invalid, step in ((packet[:-1], 0), (packet + b"x", 0), (packet, 1),
                          (b"M" * (256 * 1024 + 1), 0), (packet[:-2] + b"xx", 0)):
        with pytest.raises(ValueError):
            _unpack(spec, invalid, step)
    client._material_owner(distribution).discard(prepared)


def test_worker_memory_guard_retains_first_error_and_report_without_generating(monkeypatch):
    from test_two_party_protocol import make_stack

    from secure_control.execution import _material_worker as worker
    from secure_control.execution.localhost_codec import _load_json

    client, _, _, _, distribution = make_stack()
    spec = worker._WorkerSpec(distribution.p1.layout, client.fixed_point.modulus, 8, 8, None, None,
                              "run", distribution.session_id, "epoch", 0, 16)
    monkeypatch.setattr(worker, "_memory", lambda: {"current_rss_bytes": 257 * 1024**2,
                                                    "peak_rss_bytes": 257 * 1024**2})
    packets, closed = [], []
    def forbidden(*args, **kwargs):
        pytest.fail("启动内存保护失败后不得开始生成或等额度")
    monkeypatch.setattr(worker, "_create_resource_pair", forbidden)
    worker._worker_main(spec, SimpleNamespace(poll=forbidden, close=lambda: closed.append("credit")),
                        SimpleNamespace(send_bytes=packets.append, close=lambda: closed.append("data")))
    assert closed == ["credit", "data"] and len(packets) == 1 and packets[0][:1] == b"R"
    report = _load_json(packets[0][1:])
    assert report["generated"] == 0 and report["memory_guard_failed"] and report["error_type"] == "RuntimeError"
    assert report["gc_begin"] is None and len(report["memory"]) == 2


@pytest.mark.parametrize("fault", (None, "worker_exit", "partial_send"))
def test_spawn_material_candidate_uses_existing_lan_state_segments_and_failure_stop(monkeypatch, fault):
    """真实spawn与原LAN小规模功能联调；不使用绝对周期作性能试跑。"""
    import multiprocessing as mp

    import numpy as np

    from secure_control.execution import lan_runtime, localhost_transport
    from secure_control.experiments.communication_benchmark import _config, _party_job, _ports
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    ports = _ports()
    context = mp.get_context("spawn")
    queue = context.Queue()
    parties = [context.Process(target=_party_job, args=(_config(role, ports), ports, 0, True, queue))
               for role in ("P1", "P2")]
    runtime, pool = None, None
    try:
        prepared = load_segmented_experiment(_config("Client", ports).experiment_config, 2, InteractiveSession())
        for party in parties:
            party.start()
        runtime = lan_runtime.LanSegmentedRuntime(_config("Client", ports), prepared.spec, prepared.context,
            prepared.contract, prepared.security_parameter, prepared.evidence,
            control=lan_runtime.RunControl(), segment_capacity=2)
        runtime.enable_material_preparation(slots=4, _candidate="worker")
        pool = runtime._segment._material_pool
        from secure_control.execution.cycle_timing import CycleTiming
        # 真实供料摘要包含模式/布尔/工人字典，周期schema只能接受整数公开计数。
        timing = CycleTiming(runtime.run_id, runtime._segment.session_id, runtime.controller_epoch,
            0, 0, None, 20_000_000, 0, 0, 20_000_000, queue_levels=runtime.cycle_queue_levels)
        assert all(type(v) is int and v >= 0 for v in timing.queue_levels.values())
        assert runtime.material_summary["material_mode"] == "local-worker-v1"
        worker_pid, session_id = pool._process.pid, runtime.public_setup
        pool.control_begin()
        original_send = localhost_transport.send_frame
        if fault == "worker_exit":
            pool._process.terminate()
            pool._process.join(timeout=5)
        if fault == "partial_send":
            def partial(sock, encoded, **kwargs):
                if sock is runtime._segment._sockets[1]:
                    raise OSError("test partial frame")
                return original_send(sock, encoded, **kwargs)
            monkeypatch.setattr(localhost_transport, "send_frame", partial)
        if fault:
            with pytest.raises((RuntimeError, OSError)):
                runtime.step(np.zeros(2))
            assert runtime.confirmed_step_count == 0 and runtime.phase in {"FAILED", "UNCERTAIN"}
            with pytest.raises(RuntimeError):
                runtime.step(np.zeros(2))
            assert not pool._process.is_alive()
            if fault == "worker_exit":
                assert pool.snapshot()["cleanup_failed"]
        else:
            identities, outputs, expected = [], [], []
            state = np.asarray(prepared.spec.x0, dtype=float)
            for step in range(5):
                if runtime.segment_full:
                    record = runtime.end_segment()
                    runtime.next_segment()
                    assert record.setup == session_id and pool._process.pid == worker_pid
                identity = runtime.step(np.zeros(2))
                assert identity.global_step == step
                identities.append((identity.session_id, identity.round_id))
                outputs.append(identity.raw_control)
                expected.append(np.asarray(prepared.spec.C) @ state)
                state = np.asarray(prepared.spec.A) @ state
                runtime.confirm_applied(identity)
                # 测试线程可等补货；实际control take没有此等待。
                with pool._condition:
                    assert pool._condition.wait_for(lambda: len(pool._queue) == 4 or pool._error, timeout=10)
                    assert not pool._error
            runtime.control.request_stop()
            runtime.end_segment()
            assert runtime.confirmed_step_count == 5 and runtime.resource_counts == {
                "products_consumed": 150, "truncations_consumed": 20}
            assert len({v[0] for v in identities}) == 1 and len({v[1] for v in identities}) == 5
            # 独立旧state出力递推：零输入保留配置的真实非零x0，不重置跨段状态。
            np.testing.assert_allclose(outputs, expected, atol=1e-5, rtol=0)
            stats = runtime.material_summary
            assert stats["claimed"] == 5 and stats["inventory_inflight_high_water"] <= 4
            assert stats["material_encoded_bound_high_water"] <= stats["material_reserved_bytes"]
            assert stats["worker_exited"] and stats["receiver_exited"] and stats["credit_thread_exited"]
            assert not stats["cleanup_failed"] and stats["worker"]["gc_begin"] is not None
        pool.close()  # 幂等；不再生成或换worker。
    finally:
        if runtime is not None:
            runtime.close()
        for party in parties:
            if party.pid is not None:
                party.join(timeout=5)
                if party.is_alive():
                    party.terminate()
                    party.join(timeout=5)
        queue.close()


@pytest.mark.parametrize(("sampling", "protocol_failure", "cleanup_failure"), [
    ("normal", True, False), ("limit", True, False), ("query", True, False),
    ("normal", False, False), ("limit", False, False), ("query", False, False),
    ("normal", True, True), ("normal", False, True), ("limit", False, True),
])
def test_s5_close_observation_preserves_first_error_and_always_cleans(
        monkeypatch, sampling, protocol_failure, cleanup_failure):
    """真实段开始异常出口；只注入请求/OS/清理，不执行控制或性能对照。"""
    from secure_control.execution import lan_runtime
    from secure_control.execution.localhost_codec import SegmentBeginPayload
    from secure_control.execution.localhost_transport import LocalhostTransportTimeout
    from secure_control.experiments import communication_benchmark as bench

    for candidate in ("thread", "worker"):
        with monkeypatch.context() as patcher:
            runtime = lan_runtime.LanContinuousRuntime.__new__(lan_runtime.LanContinuousRuntime)
            runtime._v2, runtime._failed, runtime._finished = True, False, False
            runtime._step, runtime._sequences = 0, [0, 0]
            runtime._sockets, runtime._material_pool = [object(), object()], None
            runtime.session_id, runtime.config = "test-session", SimpleNamespace(shutdown_timeout=1.)
            original = LocalhostTransportTimeout("private protocol message")
            original.phase = "SEGMENT_BEGIN"
            begin = SegmentBeginPayload("test-run", 0, 0, "0" * 64, None)
            closed, requests, observed, reads = [], [], [], []

            def request(*args, requests=requests, original=original, **kwargs):
                requests.append(True)
                raise original

            def cleanup(value, closed=closed):
                closed.append(value)
                if cleanup_failure:
                    raise ValueError("private cleanup message")

            def memory(reads=reads):
                reads.append(True)
                if len(reads) == 2 and sampling == "query":
                    raise OSError("private OS message")
                rss = 257 * 1024**2 if len(reads) == 2 and sampling == "limit" else 1024
                return {"current_rss_bytes": rss, "peak_rss_bytes": rss}

            failed_cycles = [{"global_step": 0, "status": "failed",
                              "failure_phase": "SEGMENT_BEGIN", "cycle_completed_ns": None}]

            def observation(*, runtime=runtime, begin=begin, observed=observed,
                            original=original, failed_cycles=failed_cycles, **options):
                options["_material_event"]("control_begin")
                try:
                    if protocol_failure:
                        runtime.begin_segment(begin)
                    else:
                        runtime.close()
                except (LocalhostTransportTimeout, RuntimeError, OSError, ValueError) as error:
                    observed.append(error)
                    return {"status": "failed", "failure_category": type(error).__name__,
                            "failed_phase": getattr(error, "phase", "CLOSE"),
                            "cycles": failed_cycles if error is original else []}
                return {"status": "stopped", "cycles": []}

            patcher.setattr(lan_runtime, "_request", request)
            patcher.setattr(lan_runtime.LanContinuousRuntime, "close", cleanup)
            patcher.setattr(bench, "_process_memory", memory)
            patcher.setattr(bench, "_run_continuous_observation", observation)
            result = bench._run_material_comparison({"steps": 1000}, candidate)
            summary = result["material_comparison"]
            assert closed == [runtime] and len(reads) == 2
            assert requests == ([True] if protocol_failure else [])
            assert lan_runtime.LanContinuousRuntime.close is cleanup
            assert summary["memory_guard_failed"] == (sampling != "normal")
            assert summary["cleanup_failed"] == cleanup_failure
            if protocol_failure:
                assert observed == [original] and result["failure_category"] == "LocalhostTransportTimeout"
                assert result["failed_phase"] == "SEGMENT_BEGIN" and result["cycles"] is failed_cycles
                assert runtime._failed
            elif sampling != "normal" or cleanup_failure:
                expected = {"limit": "RuntimeError", "query": "OSError"}.get(sampling, "ValueError")
                assert result["status"] == "failed" and result["failure_category"] == expected
            else:
                assert result["status"] == "stopped" and not observed
            assert summary.get("memory_sample_error_type") == {
                "normal": None, "limit": "RuntimeError", "query": "OSError"}[sampling]
            assert summary.get("cleanup_error_type") == ("ValueError" if cleanup_failure else None)
            assert result["comparison_only"] and not result["candidate_gate_pass"]
            assert not result["qualification_pass"] and not result["stage_pass"]
            assert "private" not in str(result)


@pytest.mark.parametrize("closing_fault", ("normal", "limit", "query", "cleanup"))
@pytest.mark.parametrize("s6", (False, True))
def test_s5_real_runner_failed_return_keeps_cycles_and_confirmed_prefix(monkeypatch, closing_fault, s6):
    """真实runner返回/finally出口和真实周期；虚拟时钟/协议替身不构成性能运行。"""
    import gc
    import sys
    from dataclasses import asdict

    from secure_control.execution import lan_runtime
    from secure_control.execution.cycle_timing import AbsoluteCycleClock, check_deadline
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_continuous_profile, lan_runner
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    def check(candidate, failure_step):
        with monkeypatch.context() as patcher:
            now, closed, close_context, reads, cycles, applied = [0], [], [], [], [], []

            class Runtime:
                def __init__(self, *args, **kwargs):
                    self.phase, self.run_id = "RUNNING", "test-run"
                    self.confirmed_step_count = self.protocol_committed_count = 0
                    self.resource_counts = {"products_consumed": 0, "truncations_consumed": 0}
                    self.public_setup = None
                    self.cycle_phase_ns, self.cycle_queue_levels = {}, {}
                    self.segment = SimpleNamespace(_material_pool=None)

                def snapshot(self):
                    count = self.confirmed_step_count
                    return lan_runtime.LanLifecycleSnapshot(self.phase, self.run_id, "test-session",
                        "epoch", 0, 0, count, f"round-{count}", self.protocol_committed_count,
                        count, 30 * count, 4 * count, 0)

                @property
                def segment_full(self):
                    return False

                def step(self, value, **kwargs):
                    step = self.confirmed_step_count
                    self.protocol_committed_count += 1
                    return SimpleNamespace(global_step=step, raw_control=(0.,), round_id=f"round-{step}",
                                           segment_index=0, session_id="test-session")

                def enable_material_preparation(self, **kwargs):
                    assert kwargs == {"slots": 16, "_candidate": "worker"}

                def _begin_material_control(self):
                    pass  # 软件协议替身，不创建工人或生成秘密材料。

                def confirm_applied(self, identity):
                    self.confirmed_step_count += 1
                    self.resource_counts = {"products_consumed": 30 * self.confirmed_step_count,
                                            "truncations_consumed": 4 * self.confirmed_step_count}

                def close(self):
                    close_context.append(sys.exception())
                    lan_runtime.LanContinuousRuntime.close(self.segment)

            def cleanup(segment):
                closed.append(segment)
                if closing_fault == "cleanup":
                    raise ValueError("private cleanup message")

            def memory():
                reads.append(True)
                end_read = 3 if s6 else 2  # S6还有g0输入前采样；故障只注入control_end。
                if len(reads) == end_read and closing_fault == "query":
                    raise OSError("private OS message")
                rss = 257 * 1024**2 if len(reads) == end_read and closing_fault == "limit" else 1024
                return {"current_rss_bytes": rss, "peak_rss_bytes": rss}

            def clock(period):
                return AbsoluteCycleClock(period, now=lambda: now[0],
                    sleep=lambda seconds: now.__setitem__(0, now[0] + round(seconds * 1e9)))

            inputs = []
            def input_value():
                step = len(inputs)
                inputs.append(step)
                now[0] += 21_000_000 if step == failure_step else 1_000_000
                return [0.]

            def advance(step, value, **kwargs):
                applied.append(step)
                now[0] += 1_000_000
                return {}

            prepared = SimpleNamespace(spec=SimpleNamespace(state_dimension=4), context=None,
                contract=None, security_parameter=8, evidence=None, segment_capacity=400,
                recheck_sources=lambda: None, scene=SimpleNamespace(period=.02,
                    controller_input=input_value, advance=advance))

            def observation(**options):
                result = lan_runner._run_prepared_segmented(None, prepared,
                    control=lan_runtime.RunControl(), session=InteractiveSession(), realtime=True,
                    material_slots=0, on_cycle=cycles.append,
                    phase=lambda name: options["_material_event"]("control_begin")
                        if name == "RUNNING" else None)
                return {"status": result["status"], "failure_category": result["category"],
                    "failed_phase": result["failure_phase"], "cycles": [asdict(v) for v in cycles],
                    "cycle_summary": result["cycle_summary"], "resource_counts": result["resource_counts"],
                    "protocol_committed_count": result["protocol_committed_count"],
                    "physically_confirmed_count": result["confirmed_step_count"]}

            patcher.setattr(lan_runner, "LanSegmentedRuntime", Runtime)
            patcher.setattr(lan_runner, "perf_counter_ns", lambda: now[0])
            patcher.setattr(lan_runner, "AbsoluteCycleClock", clock)
            patcher.setattr(lan_runner.gc, "collect", lambda generation: 0)
            patcher.setattr(lan_runner, "check_deadline", lambda deadline, phase:
                            check_deadline(deadline, phase, now=lambda: now[0]))
            patcher.setattr(lan_runtime.LanContinuousRuntime, "close", cleanup)
            patcher.setattr(bench, "_process_memory", memory)
            if s6:
                from secure_control.execution import localhost_transport as transport
                originals = (transport._send_exact, transport._receive_exact, transport.encode_envelope,
                    transport.decode_envelope, lan_runtime.LanSegmentedRuntime.close, list(gc.callbacks))
                ports = (101, 102, 103)
                real_prepared = lan_continuous_profile.load_segmented_experiment(
                    bench._config("Client", ports).experiment_config, 400, InteractiveSession())
                patcher.setattr(lan_continuous_profile, "load_segmented_experiment",
                                lambda *args: replace(real_prepared, scene=prepared.scene))
                queue_closes = []
                outcomes = iter([{"role": role, "directions": {}} for role in ("P1", "P2")])
                queue = SimpleNamespace(get=lambda **kwargs: next(outcomes), close=lambda: queue_closes.append(True))
                context = SimpleNamespace(Queue=lambda: queue, Process=lambda **kwargs: SimpleNamespace(
                    start=lambda: None, join=lambda **kwargs: None, is_alive=lambda: False))
                patcher.setattr(bench.mp, "get_context", lambda method: context)
                patcher.setattr(bench, "_ports", lambda: ports)
                result = bench.run_continuous_observation(steps=20, delay_ms=0, segment_steps=400,
                    optimized=True, recording_mode="light", worker_timeout_diagnostic=True)
                assert queue_closes == [True]
                assert originals == (transport._send_exact, transport._receive_exact, transport.encode_envelope,
                    transport.decode_envelope, lan_runtime.LanSegmentedRuntime.close, list(gc.callbacks))
                client_trace = result["diagnostic_report"]["roles"][0]
                assert client_trace["callback_restored"] and client_trace["socket_hooks_restored"]
                assert client_trace["encoded_bytes"] <= 72 * 1024
                assert result["worker_timeout_diagnostic"]["diagnostic_encoded_bytes"] <= 256 * 1024
                assert not result["worker_timeout_diagnostic"]["diagnostic_budget_failed"]
                cycles = result["cycles"]
            else:
                patcher.setattr(bench, "_run_continuous_observation", observation)
                result = bench._run_material_comparison({"steps": 1000}, candidate)
                assert result["cycles"] == [asdict(v) for v in cycles]
            assert close_context == [None] and len(closed) == 1 and len(reads) == (4 if s6 else 2)
            assert lan_runtime.LanContinuousRuntime.close is cleanup
            assert result["status"] == "failed" and result["failure_category"] == "CycleDeadlineExceeded"
            assert result["failed_phase"] == "INPUT"
            assert len(cycles) == failure_step + 1 and applied == list(range(failure_step))
            last = result["cycle_summary"]["last_cycle"]
            assert result["cycle_summary"]["attempts"] == failure_step + 1
            assert result["cycle_summary"]["misses"] == 1
            assert last["status"] == "miss_before_apply" and last["failure_phase"] == "INPUT"
            assert last["global_step"] == failure_step and last["cycle_completed_ns"] is None
            assert last["scheduled_start_ns"] == last["actual_sample_start_ns"] == failure_step * 20_000_000
            assert last["deadline_ns"] == (failure_step + 1) * 20_000_000
            assert all(v["status"] == "confirmed" and v["global_step"] == step
                       for step, v in enumerate(result["cycles"][:-1]))
            assert last["device_completed_ns"] is None and last["bookkeeping_completed_ns"] is None
            assert result["protocol_committed_count"] == result["physically_confirmed_count"] == failure_step
            assert result["resource_counts"] == {"products_consumed": 30 * failure_step,
                                                 "truncations_consumed": 4 * failure_step}
            summary = result["material_comparison"]
            assert summary["memory_guard_failed"] == (closing_fault in {"limit", "query"})
            assert summary["cleanup_failed"] == (closing_fault == "cleanup")
            assert summary["memory_sample_error_type"] == {
                "limit": "RuntimeError", "query": "OSError"}.get(closing_fault)
            assert summary["cleanup_error_type"] == ("ValueError" if closing_fault == "cleanup" else None)
            assert not result["candidate_gate_pass"] and not result["qualification_pass"]
            assert not result["stage_pass"] and result["comparison_only"] and "private" not in str(result)

    for candidate in (("worker",) if s6 else ("thread", "worker")):
        for failure_step in (0, 2):
            check(candidate, failure_step)


def test_s5_fixed_budget_rejected_before_any_port_or_process(monkeypatch):
    from secure_control.experiments import communication_benchmark as bench

    def forbidden(*args, **kwargs):
        pytest.fail("非法候选不得创建端口/材料/进程")
    monkeypatch.setattr(bench, "_ports", forbidden)
    options = {"steps": 1000, "delay_ms": 0, "segment_steps": 400, "optimized": True,
               "recording_mode": "light", "material_candidate": "worker"}
    for change in ({"steps": 999}, {"steps": True}, {"material_slots": 4}, {"diagnostic": True},
                   {"gc_trial_policy": "baseline"}, {"preload_steps": 1000}, {"delay_ms": 1},
                   {"timeout_trace": True}, {"recording_mode": "full"}, {"material_candidate": "invalid"}):
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**(options | change))


def test_s9_guard_selection_and_old_budgets_before_resources(monkeypatch):
    import gc

    from secure_control.experiments import communication_benchmark as bench

    def forbidden(*args, **kwargs):
        pytest.fail("非法长期组合不得分配端口、材料或进程")
    monkeypatch.setattr(bench, "_ports", forbidden)
    monkeypatch.setattr(bench, "_run_continuous_observation", forbidden)
    options = {"steps": 10000, "delay_ms": 0, "segment_steps": 400, "optimized": True,
               "recording_mode": "light", "worker_long_run": True}
    for change in ({"worker_long_run": 1}, {"steps": 9999}, {"steps": 10001}, {"steps": True},
                   {"steps": 10000.0}, {"delay_ms": False}, {"delay_ms": 1}, {"optimized": 1},
                   {"segment_steps": 400.0}, {"material_slots": 16.0}, {"material_slots": 4},
                   {"preload_steps": False}, {"preload_steps": 1}, {"preload_execution": "staged"},
                   {"recording_mode": "full"}, {"diagnostic": True}, {"timeout_trace": True},
                   {"timeout_trace": 0}, {"gc_trial_policy": "baseline"}, {"role_config": "unused"},
                   {"tcp_nodelay": False}, {"commit_policy": "serial"},
                   {"material_candidate": "worker"}, {"material_candidate": "thread"},
                   {"worker_timeout_diagnostic": True}, {"worker_timeout_diagnostic": 0}):
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**(options | change))
    for name, value in (("isenabled", False), ("get_threshold", (701, 10, 10)),
                        ("get_freeze_count", 1), ("get_debug", 1)):
        with monkeypatch.context() as patcher:
            patcher.setattr(gc, name, lambda value=value: value)
            with pytest.raises(ValueError):
                bench.run_continuous_observation(**options)
    with monkeypatch.context() as patcher:
        patcher.setattr(gc, "callbacks", [object()])
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**options)
    for change in ({"worker_long_run": False, "material_candidate": "worker"},
                   {"worker_long_run": False, "worker_timeout_diagnostic": True}):
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**(options | change))
    calls = []
    monkeypatch.setattr(bench, "_run_material_comparison", lambda opts, candidate, **kwargs:
                        calls.append((opts, candidate, kwargs)) or {"status": "synthetic"})
    assert bench.run_continuous_observation(**options) == {"status": "synthetic"}
    assert calls[0][1:] == ("worker", {"target_steps": 10000})
    assert calls[0][0]["steps"] == 10000 and not calls[0][0]["diagnostic"]
    bench.run_continuous_observation(**(options | {"steps": 1000, "worker_long_run": False,
                                                  "material_candidate": "worker"}))
    assert calls[-1][1:] == ("worker", {})


def _s9_public_result():
    """仅合成身份/计时/计数；不创建控制、材料或端口。"""
    cycles = []
    for step in range(10000):
        start = step * 20000000
        cycles.append({"run_id": "run", "session_id": "session", "controller_epoch": "epoch",
            "round_id": f"round-{step}", "global_step": step, "segment_index": step // 400,
            "status": "confirmed", "failure_phase": None, "period_ns": 20000000,
            "scheduled_start_ns": start, "actual_sample_start_ns": start + 1,
            "device_completed_ns": start + 2, "bookkeeping_completed_ns": start + 3,
            "cycle_completed_ns": start + 4, "deadline_ns": start + 20000000,
            "protocol_committed_count": step + 1, "physically_confirmed_count": step + 1})
    return {"status": "stopped", "requested_steps": 10000, "successful_steps": 10000,
        "failed_attempts": 0, "cycles": cycles, "cycle_summary": {"attempts": 10000, "misses": 0},
        "protocol_committed_count": 10000, "physically_confirmed_count": 10000,
        "resource_counts": {"products_consumed": 300000, "truncations_consumed": 40000},
        "material_summary": {"claimed": 10000, "generated_received": 10016,
            "inventory_inflight_high_water": 16, "material_encoded_bound_high_water": 8388608,
            "worker_exited": True, "receiver_exited": True, "credit_thread_exited": True,
            "cleanup_failed": False, "worker": {"error_type": None, "memory_guard_failed": False}},
        "worker_long_run": {"numeric_contract": {"mode": "bounded_input_reachability",
            "horizon_steps": None, "proof_algorithm": "encoded-block-power-rational-v1"}},
        "party_outcomes": [{"role": role, "status": "closed", "steps": [
            {"step": step, "round_id": f"round-{step}"} for step in range(10000)]}
            for role in ("P1", "P2")],
        "last_commit_observation": {"run_id": "run", "session_id": "session", "controller_epoch": "epoch",
            "round_id": "round-9999", "global_step": 9999, "step": 9999,
            "parties": {role: {"request_state": "sent", "valid_ack_received": True}
                        for role in ("P1", "P2")}}}


def test_s9_gate_rejects_single_bad_period_identity_receipt_or_material():
    from copy import deepcopy

    from secure_control.experiments import communication_benchmark as bench

    good = _s9_public_result()
    report = {"memory_guard_failed": False, "cleanup_failed": False, "producer_exited": True}
    assert bench._material_run_gate(good, report, "worker", 10000, strict=True)
    # 改一个公开事实就不能过门禁；包含内部边界和最后周期，不靠分位数掩盖。
    edits = [(("cycles", 799, "cycle_completed_ns"), 800 * 20000000),
        (("cycles", 799, "cycle_completed_ns"), 800 * 20000000 + 1),
        (("cycles", 9999, "cycle_completed_ns"), None),
        (("cycles", 400, "global_step"), 399), (("cycles", 400, "segment_index"), 0),
        (("cycles", 400, "round_id"), "round-399"), (("cycles", 400, "session_id"), "other"),
        (("cycles", 400, "controller_epoch"), "other"), (("cycles", 400, "run_id"), "other"),
        (("cycles", 400, "status"), "miss_after_apply"), (("cycles", 400, "actual_sample_start_ns"), None),
        (("cycles", 400, "physically_confirmed_count"), 400),
        (("cycles", 400, "scheduled_start_ns"), 1),
        (("party_outcomes", 0, "steps", 400, "round_id"), "round-399"),
        (("party_outcomes", 0, "steps", 400, "step"), 399),
        (("party_outcomes", 0, "status"), "uncertain"),
        (("last_commit_observation", "parties", "P2", "valid_ack_received"), False),
        (("last_commit_observation", "round_id"), "round-9998"),
        (("material_summary", "claimed"), 9999), (("material_summary", "error_type"), "OSError"),
        (("material_summary", "worker", "error_type"), "OSError"),
        (("material_summary", "worker", "memory_guard_failed"), True),
        (("material_summary", "inventory_inflight_high_water"), 17),
        (("material_summary", "material_encoded_bound_high_water"), 8388609),
        (("material_summary", "worker_exited"), False), (("material_summary", "receiver_exited"), False),
        (("material_summary", "credit_thread_exited"), False), (("material_summary", "cleanup_failed"), True),
        (("resource_counts", "products_consumed"), 299970),
        (("resource_counts", "truncations_consumed"), 39996),
        (("worker_long_run", "numeric_contract", "horizon_steps"), 10000),
        (("cycle_summary", "attempts"), 9999), (("cycle_summary", "misses"), 1)]
    for path, value in edits:
        bad = deepcopy(good)
        target = bad
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        assert not bench._material_run_gate(bad, report, "worker", 10000, strict=True), path
    for key in ("cycles", "party_outcomes", "last_commit_observation"):
        bad = deepcopy(good)
        bad.pop(key)
        assert not bench._material_run_gate(bad, report, "worker", 10000, strict=True)
    short = deepcopy(good)
    short["cycles"].pop()
    assert not bench._material_run_gate(short, report, "worker", 10000, strict=True)
    for key in ("memory_guard_failed", "cleanup_failed", "producer_exited"):
        assert not bench._material_run_gate(good, report | {key: key != "producer_exited"},
                                            "worker", 10000, strict=True)


@pytest.mark.parametrize("fault", ("normal", "initialization", "cleanup", "memory", "control"))
def test_s9_result_metadata_and_original_error_survive_stop(monkeypatch, fault):
    from secure_control.execution import lan_runtime
    from secure_control.experiments import communication_benchmark as bench

    good = _s9_public_result()
    runtime = object.__new__(lan_runtime.LanContinuousRuntime)
    runtime._material_pool = SimpleNamespace(snapshot=lambda: {"worker_exited": True})
    closed = []
    def close(value):
        closed.append(value)
        if fault == "cleanup":
            raise OSError("private closing error")
    memory = iter((1024, 257 * 1024**2 if fault == "memory" else 1024))
    def observe(**options):
        assert options["material_candidate"] == "worker" and not options.get("diagnostic")
        if fault == "initialization":
            raise ValueError("private startup error")
        options["_long_run_metadata"]["numeric_contract"] = good["worker_long_run"]["numeric_contract"]
        options["_material_event"]("control_begin")
        if fault == "control":
            good.update(status="failed", failure_category="CycleDeadlineExceeded", failed_phase="INPUT",
                        cycles=[{"status": "miss_before_apply", "cycle_completed_ns": None}])
        runtime.close()
        return good
    monkeypatch.setattr(lan_runtime.LanContinuousRuntime, "close", close)
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": next(memory)})
    monkeypatch.setattr(bench, "_run_continuous_observation", observe)
    result = bench.run_continuous_observation(steps=10000, delay_ms=0, segment_steps=400,
        optimized=True, recording_mode="light", worker_long_run=True)
    assert lan_runtime.LanContinuousRuntime.close is close
    assert result["worker_long_run"]["maximum_attempts"] == 10000
    assert result["worker_long_run"]["target_steps"] == 10000
    assert result["worker_long_run_gate_pass"] == (fault == "normal")
    assert result["comparison_only"] and not result["candidate_gate_pass"]
    assert not result["qualification_pass"] and not result["stage_pass"]
    if fault == "initialization":
        assert result["cycles"] == [] and result["worker_long_run"]["numeric_contract"] is None
        assert result["failure_category"] == "ValueError" and not closed
    else:
        assert closed == [runtime]
        if fault == "control":
            assert result["cycles"] is good["cycles"] and result["failed_phase"] == "INPUT"
            assert result["failure_category"] == "CycleDeadlineExceeded"
    assert "private" not in str(result)


def test_s9_cli_only_cycle_batch_transfers_long_flag(tmp_path, monkeypatch, capsys):
    import json
    import sys

    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_runner

    calls = []
    def selected(options, candidate, **kwargs):
        calls.append((options, candidate, kwargs))
        return {"status": "stopped", "cycle_timing": {"p50_ms": 1.0}}
    monkeypatch.setattr(bench, "_run_material_comparison", selected)
    def forbidden(*args, **kwargs):
        pytest.fail("非法case不能进入其他运行路径")
    monkeypatch.setattr(bench, "run_full_observation", forbidden)
    monkeypatch.setattr(bench, "run_local_benchmark", forbidden)
    base = ["secure-control", "benchmark", "--steps", "10000", "--segment-steps", "400",
            "--recording", "light", "--worker-long-run", "--output", str(tmp_path / "result.json")]
    for case, mode in (("cycle", "legacy"), ("full-observation", "batch"), ("dynamic", "batch")):
        monkeypatch.setattr(sys, "argv", base + ["--case", case, "--mode", mode])
        assert lan_runner._run() == 5 and not calls
        assert not (tmp_path / "result.json").exists()
    monkeypatch.setattr(sys, "argv", base + ["--case", "cycle", "--mode", "batch"])
    assert lan_runner._run() == 0
    assert calls[0][1:] == ("worker", {"target_steps": 10000})
    assert json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))["status"] == "stopped"
    capsys.readouterr()


def test_s9_real_initialization_restores_owned_observers_without_starting_roles(monkeypatch):
    import gc

    from secure_control.execution import lan_runtime
    from secure_control.execution import localhost_transport as transport
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_continuous_profile

    original = (transport._send_exact, transport._receive_exact, transport.encode_envelope,
                transport.decode_envelope, lan_runtime.LanContinuousRuntime.close, list(gc.callbacks))
    for failure_point in ("control", "profile"):
        with monkeypatch.context() as patcher:
            closed = []
            def forbidden(*args, **kwargs):
                pytest.fail("初始化软件故障测试不能启动角色")
            def failed(*args, **kwargs):
                raise OSError("private initialization")
            queue = SimpleNamespace(close=lambda closed=closed: closed.append(True))
            context = SimpleNamespace(Queue=lambda queue=queue: queue,
                Process=lambda forbidden=forbidden, **kwargs: SimpleNamespace(
                    start=forbidden, join=forbidden, is_alive=lambda: False))
            patcher.setattr(bench.mp, "get_context", lambda method, context=context: context)
            patcher.setattr(bench, "_ports", lambda: (101, 102, 103))
            if failure_point == "control":
                patcher.setattr(lan_runtime, "RunControl", failed)
            else:
                patcher.setattr(lan_continuous_profile, "load_segmented_experiment", failed)
            result = bench.run_continuous_observation(steps=10000, delay_ms=0, segment_steps=400,
                optimized=True, recording_mode="light", worker_long_run=True)
            assert result["status"] == "failed" and result["failure_category"] == "OSError"
            assert result["cycles"] == [] and not result["worker_long_run_gate_pass"]
            assert result["worker_long_run"]["numeric_contract"] is None and closed == [True]
            assert not result.get("diagnostic", False)
            assert "private initialization" not in str(result)
        assert original == (transport._send_exact, transport._receive_exact, transport.encode_envelope,
            transport.decode_envelope, lan_runtime.LanContinuousRuntime.close, list(gc.callbacks))


def test_s6_independent_worker_trace_guard_preserves_old_trial_limits(monkeypatch):
    from secure_control.experiments import communication_benchmark as bench

    def forbidden(*args, **kwargs):
        pytest.fail("非法S6不得分配端口、材料、工人或GC试验")
    monkeypatch.setattr(bench, "_ports", forbidden)
    monkeypatch.setattr(bench._StartupGCTrial, "installed", forbidden)
    options = {"steps": 20, "delay_ms": 0, "segment_steps": 400, "optimized": True,
               "recording_mode": "light", "worker_timeout_diagnostic": True}
    for change in ({"steps": 0}, {"steps": 19}, {"steps": 21}, {"steps": True},
                   {"worker_timeout_diagnostic": 1}, {"delay_ms": False}, {"delay_ms": 1},
                   {"diagnostic": True}, {"optimized": 1}, {"recording_mode": "full"},
                   {"gc_trial_policy": "baseline"}, {"timeout_trace": True}, {"timeout_trace": 1},
                   {"material_candidate": "worker"}, {"material_candidate": "thread"},
                   {"segment_steps": 20}, {"material_slots": 4}, {"preload_steps": 1},
                   {"preload_execution": "staged"}, {"role_config": "unused"},
                   {"tcp_nodelay": False}, {"commit_policy": "serial"}):
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**(options | change))
    for change in ({"worker_timeout_diagnostic": False, "material_candidate": "worker"},
                   {"worker_timeout_diagnostic": False, "timeout_trace": True}):
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**(options | change))
    monkeypatch.setattr(bench, "_run_material_comparison", lambda options, candidate: (options, candidate))
    accepted, candidate = bench.run_continuous_observation(**options)
    assert candidate == "worker" and accepted["worker_timeout_diagnostic"]
    assert accepted["diagnostic"] and accepted["timeout_trace"]
    assert accepted["steps"] == 20 and "_gc_trial" not in accepted


@pytest.mark.parametrize("failure_point", ("control", "prepared"))
def test_s6_initialization_failure_restores_owned_hooks_and_closes_queue(monkeypatch, failure_point):
    import gc

    from secure_control.execution import lan_runtime
    from secure_control.execution import localhost_transport as transport
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_continuous_profile

    originals = (transport._send_exact, transport._receive_exact, transport.encode_envelope,
                 transport.decode_envelope, lan_runtime.LanContinuousRuntime.close,
                 lan_runtime.LanSegmentedRuntime.close, list(gc.callbacks), gc.get_threshold())
    closed = []
    def failed(*args, **kwargs):
        raise OSError("private initialization message")
    def forbidden(*args, **kwargs):
        pytest.fail("软件初始化故障测试不能启动子进程")
    queue = SimpleNamespace(close=lambda: closed.append(True))
    context = SimpleNamespace(Queue=lambda: queue, Process=lambda **kwargs: SimpleNamespace(
        start=forbidden, join=forbidden, is_alive=lambda: False))
    monkeypatch.setattr(bench.mp, "get_context", lambda method: context)
    monkeypatch.setattr(bench, "_ports", lambda: (101, 102, 103))
    if failure_point == "control":
        monkeypatch.setattr(lan_runtime, "RunControl", failed)
    else:
        monkeypatch.setattr(lan_continuous_profile, "load_segmented_experiment", failed)
    result = bench.run_continuous_observation(steps=20, delay_ms=0, segment_steps=400,
        optimized=True, recording_mode="light", worker_timeout_diagnostic=True)
    assert result["status"] == "failed" and result["failure_category"] == "OSError"
    assert result["cycles"] == [] and result["diagnostic_report"]["incomplete"]
    assert result["timeout_trace"]["diagnostic_missing"] and closed == [True]
    assert originals == (transport._send_exact, transport._receive_exact, transport.encode_envelope,
        transport.decode_envelope, lan_runtime.LanContinuousRuntime.close,
        lan_runtime.LanSegmentedRuntime.close, list(gc.callbacks), gc.get_threshold())
    trace = result["diagnostic_report"]["roles"][0]
    assert trace["socket_hooks_restored"] and trace["callback_restored"]
    assert result["worker_timeout_diagnostic"]["diagnostic_encoded_bytes"] <= 256 * 1024
    assert not result["candidate_gate_pass"] and not result["qualification_pass"]
    assert not result["stage_pass"] and result["comparison_only"]
    assert "private initialization" not in str(result)


def test_s6_combined_budget_compacts_history_keeps_first_failure_and_rejects_qualification(monkeypatch):
    import json

    from secure_control.experiments import communication_benchmark as bench

    first = tuple("public-first-error" if key == "error_type" else None for key in bench._TimeoutDiagnostic.FIELDS)
    cycles, summary = [{"status": "failed", "cycle_completed_ns": None}], {"attempts": 1, "misses": 1}
    def observation(**options):
        return {"status": "failed", "failure_category": "CycleDeadlineExceeded", "failed_phase": "INPUT",
            "cycles": cycles, "cycle_summary": summary,
            "diagnostic_report": {"roles": [{"role": "Client", "first_failure": first,
                "outer_failure": first, "trace_fields": list(bench._TimeoutDiagnostic.FIELDS),
                "events": [{"public_history": "x" * (256 * 1024)}], "encoded_omitted": 2,
                "callback_restored": True, "socket_hooks_restored": True}]}}
    monkeypatch.setattr(bench, "_run_continuous_observation", observation)
    result = bench._run_material_comparison({"steps": 20, "worker_timeout_diagnostic": True}, "worker")
    budget = result["worker_timeout_diagnostic"]
    assert budget["diagnostic_budget_failed"] and budget["precompact_encoded_bytes"] > 256 * 1024
    assert budget["compacted_event_count"] == 1 and not budget["material_summary_omitted"]
    role = result["diagnostic_report"]["roles"][0]
    assert role["first_failure"] == role["outer_failure"] == first
    assert role["events"] == [] and role["encoded_omitted"] == 3 and role["incomplete"]
    encoded = len(json.dumps({name: result.get(name) for name in ("diagnostic_report", "timeout_trace",
        "material_comparison", "material_summary", "worker_timeout_diagnostic")},
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
    assert encoded == budget["diagnostic_encoded_bytes"] <= 256 * 1024
    assert result["cycles"] is cycles and result["cycle_summary"] is summary
    assert result["failure_category"] == "CycleDeadlineExceeded" and result["failed_phase"] == "INPUT"
    assert not result["candidate_gate_pass"] and not result["qualification_pass"] and not result["stage_pass"]


@pytest.mark.parametrize(("actor", "fault"), [
    (None, None), (0, "send"), (1, "send"), (0, "missing"), (1, "missing"),
    (0, "identity"), (1, "payload"),
])
def test_overlapping_commit_requires_both_original_acks_and_rejects_reuse(monkeypatch, actor, fault):
    """真实 framing：P2 可先提交；任一未知 ACK 不能签发输出或继续 endpoint。"""
    import numpy as np
    from test_two_party_protocol import make_stack

    from secure_control.execution import _localhost_workers as workers
    from secure_control.execution.localhost_transport import receive_envelope
    from secure_control.protocol.messages import ControlShareMessage, Protocol3StageReceipt

    client, _, _, _, distribution = make_stack()
    online = client.prepare_online(distribution, [.25], step=0)
    plan = online.p1_resources.plan
    pairs = [socket.socketpair() for _ in range(2)]
    deadline = time.monotonic() + .1
    endpoints = [workers._ClientPartyEndpoint(pair[0], party, plan, 7, 4096, 1., deadline)
                 for party, pair in enumerate(pairs)]
    events, committed, budgets = [], [], []
    original_send, original_receive = workers.send_envelope, workers.receive_envelope

    def send(sock, request, **kwargs):
        party = 0 if sock is pairs[0][0] else 1
        events.append(f"send{party}")
        budgets.append(kwargs["deadline"])
        original_send(sock, request, **kwargs)
        actual = receive_envelope(pairs[party][1], deadline=deadline, limit=4096)
        assert actual.sequence == 7 and actual.payload.operation == "commit"
        committed.append(party)  # 远端已提交后，send/ACK 仍可能未知。
        if actor == party and fault == "send":
            raise OSError("partial send is uncertain")
        if actor == party and fault == "missing":
            pairs[party][1].close()
            return
        response = replace(actual, kind="reply", sender=actual.recipient, recipient="Client", payload=None)
        if actor == party and fault == "identity":
            response = replace(response, sequence=6, session_id="old-session")
        if actor == party and fault == "payload":
            response = replace(response, payload=Protocol3StageReceipt(party, plan.session_id,
                               plan.round_id, plan.step, plan.triple_count, plan.truncation_count))
        original_send(pairs[party][1], response, deadline=deadline, limit=4096)

    def receive(sock, **kwargs):
        party = 0 if sock is pairs[0][0] else 1
        events.append(f"ack{party}")
        budgets.append(kwargs["deadline"])
        assert committed == [0, 1]
        return original_receive(sock, **kwargs)

    def stage(first, second, current):
        events.append("stage")
        assert current == plan
        for endpoint in endpoints:
            endpoint.share = ControlShareMessage(endpoint.party, plan.session_id, plan.round_id,
                                                  plan.step, plan.scale_ledger.output,
                                                  AdditiveShare(np.array([0], dtype=object)))
        return tuple(Protocol3StageReceipt(p, plan.session_id, plan.round_id, plan.step,
                                           plan.triple_count, plan.truncation_count) for p in (0, 1))

    def reconstruct(*args):
        events.append("reconstruct")
        return np.array([.5])

    monkeypatch.setattr(workers, "send_envelope", send)
    monkeypatch.setattr(workers, "receive_envelope", receive)
    monkeypatch.setattr(Protocol3Orchestrator, "stage_batch", lambda _, *args: stage(*args))
    monkeypatch.setattr(client, "reconstruct_control", reconstruct)
    try:
        if fault is None:
            output = workers._complete_client_round(client, *endpoints, plan, batch=True,
                                                     overlap_commit=True)
            assert output.output.tolist() == [.5]
            assert events == ["stage", "reconstruct", "send0", "send1", "ack0", "ack1"]
        else:
            with pytest.raises((OSError, ValueError, RuntimeError)):
                workers._complete_client_round(client, *endpoints, plan, batch=True,
                                                overlap_commit=True)
            assert not all(e.commit_observation["valid_ack_received"] for e in endpoints)
            if fault in ("missing", "identity") and actor == 0:
                assert committed == [0, 1] and "ack1" not in events
                assert "ack_wait" not in endpoints[1].commit_timings
        assert all(value == deadline for value in budgets)
        for endpoint in endpoints:
            if endpoint._commit_state != "not_started":
                assert endpoint.sequence == 8
                for method in (endpoint.start_commit, endpoint.finish_commit,
                               endpoint.start_stage_batch, endpoint.commit):
                    if method == endpoint.finish_commit and endpoint._commit_state == "in_flight":
                        continue  # 整轮 owner 负责关闭未读通道；本测试不补收 ACK 恢复成功。
                    with pytest.raises(RuntimeError):
                        method()
        assert len([e for e in events if e.startswith("send")]) <= 2
    finally:
        for pair in pairs:
            for sock in pair:
                sock.close()


def test_light_benchmark_corrects_provisional_success_and_never_opens_recording(tmp_path, monkeypatch):
    from dataclasses import asdict

    from test_cart_pole_lan import _observer_profile_for
    from test_lan_continuous import _plain_deployment

    from secure_control.execution.cycle_timing import CycleTiming
    from secure_control.experiments import cart_pole_segmented_evidence as evidence
    from secure_control.experiments import lan_runner
    from secure_control.experiments.communication_benchmark import run_continuous_observation

    paths = _plain_deployment(tmp_path)
    _observer_profile_for(paths)
    def forbidden(*args, **kwargs):
        pytest.fail("light constructed recording I/O")
    for name in ("_Spool", "_BatchWriter", "open_verified_cart_pole_segmented_run"):
        monkeypatch.setattr(evidence, name, forbidden)
    def run(config, prepared, **kwargs):
        prepared.recheck_sources()
        assert not any(kwargs[k] for k in ("on_start", "on_segment", "before_sample", "cycle_snapshot"))
        kwargs["phase"]("INPUT")
        kwargs["on_step"](SimpleNamespace(protocol=SimpleNamespace(
            global_step=0, segment_index=0, session_id="session", round_id="round")))
        timing = CycleTiming("run", "session", "epoch", 0, 0, "round", 20, 0, 0, 20,
                             cycle_completed_ns=19, status="confirmed")
        kwargs["on_cycle"](timing)
        return {"status": "failed", "category": "CycleDeadlineExceeded", "resource_counts": {},
                "failure_phase": "CYCLE_OBSERVATION", "cycle_summary": {"attempts": 1, "misses": 1,
                    "last_cycle": asdict(replace(timing, status="miss_after_apply",
                        cycle_completed_ns=None, failure_phase="CYCLE_OBSERVATION"))}}
    monkeypatch.setattr(lan_runner, "_run_prepared_segmented", run)
    before = set(tmp_path.rglob("*"))
    report = run_continuous_observation(steps=2, segment_steps=1, delay_ms=0, optimized=True,
                                       recording_mode="light", role_config=paths["Client"])
    assert len(report["cycles"]) == 1 and report["cycles"][0]["status"] == "miss_after_apply"
    assert report["cycles"][0]["cycle_completed_ns"] is None
    assert not report["stage_pass"] and not report["qualification_pass"]
    assert report["writer_batches"] is report["stop_drain_ns"] is report["spool_io"] is None
    assert report["storage_all"]["fsync_ms"] is None
    assert report["storage_all"]["source_check_control_count"] > 0
    assert before == set(tmp_path.rglob("*"))
    for options in ({"tcp_nodelay": 0}, {"commit_policy": "unknown"},
                    {"tcp_nodelay": False}, {"commit_policy": "serial"}):
        with pytest.raises((ValueError, TypeError)):
            run_continuous_observation(steps=2, segment_steps=1, delay_ms=0, optimized=True,
                                       role_config=paths["Client"], **options)


def test_public_layer_plan_keeps_independent_gates_and_empty_program():
    program = ScalarProgram(
        ("a", "b", "c"), (("secret_constant", Fraction(3, 2)),),
        (
            ScalarGate("first", "multiply", "a", "b"),
            ScalarGate("sum", "add", "first", "c"),
            ScalarGate("independent", "multiply", "b", "secret_constant"),
            ScalarGate("second", "multiply", "sum", "independent"),
        ),
        "second",
    )
    plan = build_scalar_layer_plan(program)
    assert plan.layers == (("first", "independent"), ("second",))
    assert plan.program_sha256 == program.topology_sha256()
    changed_secret = ScalarProgram(
        program.inputs, (("secret_constant", Fraction(-7, 4)),),
        program.gates, program.output,
    )
    assert build_scalar_layer_plan(changed_secret) == plan
    assert build_scalar_layer_plan(ScalarProgram(("kick",), (), (), "kick")).layers == ()


def test_session_recovery_reuses_verified_owners_but_never_lifecycles(monkeypatch):
    from test_two_party_protocol import make_stack

    from secure_control.crypto import truncation
    from secure_control.protocol.coordinator import _OnlineMaterialRecovery

    client, _, _, _, distribution = make_stack()
    verify = truncation.verify_prime_modulus
    verified = []

    def checked(*args, **kwargs):
        verified.append(args[0])
        return verify(*args, **kwargs)

    monkeypatch.setattr(truncation, "verify_prime_modulus", checked)
    recovery = _OnlineMaterialRecovery(
        distribution.p1, modulus=client.fixed_point.modulus,
        security_parameter=8, modulus_evidence=None,
    )
    restored = []
    for seed in (10, 11):
        online = client.prepare_online(distribution, [.25], step=0, rng=random.Random(seed))
        material = PartyOnlineMaterial.from_round(PartyOnlineRound(
            online.p1_input, online.p1_resources,
        ))
        restored.append(recovery.restore(material))
    first, second = (item.resources for item in restored)
    assert len(verified) == 1
    assert first.product_resources[0].triple._lifecycle.owner is second.product_resources[0].triple._lifecycle.owner
    assert first.state_truncation_resources[0].truncation._lifecycle.owner is second.state_truncation_resources[0].truncation._lifecycle.owner
    assert first.product_resources[0].triple._lifecycle is not second.product_resources[0].triple._lifecycle
    assert first.state_truncation_resources[0].truncation._lifecycle is not second.state_truncation_resources[0].truncation._lifecycle
    first.product_resources[0]._lifecycle.abort()
    assert second.aborted_count == 0
    _OnlineMaterialRecovery(distribution.p1, modulus=client.fixed_point.modulus,
                            security_parameter=8, modulus_evidence=None)
    assert len(verified) == 2  # 新 setup 即使 q 相同也重新验证真实证据。


def test_session_recovery_rejects_foreign_role_and_noncanonical_last_material():
    from test_two_party_protocol import make_stack

    from secure_control.protocol.coordinator import _OnlineMaterialRecovery

    client, _, _, _, distribution = make_stack()
    recovery = _OnlineMaterialRecovery(distribution.p1, modulus=client.fixed_point.modulus,
                                       security_parameter=8, modulus_evidence=None)
    online = client.prepare_online(distribution, [.25], step=0)
    material = PartyOnlineMaterial.from_round(PartyOnlineRound(online.p1_input, online.p1_resources))
    with pytest.raises(ValueError, match="session/角色"):
        recovery.restore(replace(material, input_message=replace(material.input_message, recipient=1)))
    last = replace(material.product_resources[-1], c=AdditiveShare(client.fixed_point.modulus))
    with pytest.raises(ValueError, match="canonical"):
        recovery.restore(replace(material, product_resources=(*material.product_resources[:-1], last)))


def test_peer_plan_digest_is_cached_without_accepting_mutated_installed_plan(monkeypatch):
    from test_two_party_protocol import make_stack

    from secure_control.execution import _localhost_peer as peer

    client, _, _, _, distribution = make_stack()
    prepared = client.precompute_online_resources(distribution, step=0)
    plan = prepared.p1_resources.plan
    digests = []
    original = peer.public_step_plan_sha256
    monkeypatch.setattr(peer, "public_step_plan_sha256", lambda value: (
        digests.append(value), original(value)
    )[1])
    port = LocalhostProtocol3PeerPort(None, "P1", 100000, 1, batch_enabled=True)
    port.bind(plan.session_id)
    port.set_batch_round(plan, modulus=client.fixed_point.modulus)
    ids = tuple(item.resource_id for item in plan.product_resources)
    for _ in range(3):
        assert port._batch_payload(plan, "product_complete", ids).plan_sha256 == original(plan)
    assert len(digests) == 1
    # frozen dataclass 的嵌套字段即使被非法原位改变，也不能复用旧摘要通过检查。
    object.__setattr__(plan.product_resources[-1], "resource_id", "changed")
    with pytest.raises(ValueError, match="公开身份"):
        port._batch_payload(plan, "product_complete", ids)
    client._material_owner(distribution).discard(prepared)


def test_compact_residues_and_wire_reject_noncanonical_structure_before_restore():
    """零/q-1、非整字节模数、最大宽度、填充及重复字段都有独立 oracle。"""
    import base64
    import json

    import numpy as np
    from test_two_party_protocol import make_stack

    from secure_control.execution import localhost_codec as codec
    from secure_control.protocol import Client
    from secure_control.protocol.messages import ControllerLayout, InputShareMessage

    for q in (3, 257, 2**256 - 189):
        width = (q.bit_length() + 7) // 8
        data = codec._encode_residues([AdditiveShare(0), AdditiveShare(q-1)], q)
        assert data == bytes(width) + (q-1).to_bytes(width, "big")
        assert [s.value for s in codec._decode_residues(data, 2, q)] == [0, q-1]
        for invalid in (True, 1., -1, q):
            with pytest.raises(ValueError):
                codec._encode_residues([AdditiveShare(invalid)], q)
        with pytest.raises(ValueError):
            codec._decode_residues(q.to_bytes(width, "big"), 1, q)
        with pytest.raises(ValueError):
            codec._decode_residues(data[:-1], 2, q)
    maximum = 512 * 1024
    assert len(codec._encode_residues([AdditiveShare(0)], 1 << (maximum*8-1))) == maximum
    with pytest.raises(ValueError):
        codec._encode_residues([AdditiveShare(0)], 1 << (maximum*8))

    _, _, _, _, distribution = make_stack()
    layout = ControllerLayout(4, 2, 1, distribution.p1.layout.scale_ledger)
    plan = Client._resource_plan(layout, "session", "round", 800)
    q = 2**256 - 189
    values = bytes(codec._preloaded_values_size(plan, q))
    assert plan.triple_count == 30 and plan.truncation_count == 4 and len(values) == 3136
    assert len(base64.b64encode(values)) == 4184
    peer = LocalhostProtocol3PeerPort(None, "P1", 8*1024*1024, 1., batch_enabled=True,
                                      wire_profile=codec._COMPACT_PROFILE)
    peer.bind(plan.session_id)
    peer.set_batch_round(plan, modulus=q, run_id="run", epoch_id="epoch")
    ids = tuple(r.resource_id for r in plan.product_resources)
    product_payload = peer._batch_payload(plan, "product", ids,
        products=tuple(ProductMaskPayload(AdditiveShare(0), AdditiveShare(q-1), 0) for _ in ids))
    assert len(peer._wire_batch(product_payload).values) == 1920
    from secure_control.protocol.messages import P2TruncationPayload
    trunc_payload = peer._batch_payload(plan, "truncation", tuple(r.resource_id for r in plan.state_truncation_resources),
        truncations=tuple(P2TruncationPayload(AdditiveShare(0)) for _ in range(4)))
    assert len(peer._wire_batch(trunc_payload).values) == 128
    inp = InputShareMessage(0, plan.session_id, plan.round_id, plan.step,
                            AdditiveShare(np.array([0, 0], dtype=object)))
    payload = codec._CompactOnlinePayload(inp, "run", "epoch", public_step_plan_sha256(plan), values)
    frame = WireEnvelope(SCHEMA_VERSION, "request", "Client", "P1", 999999, "online_stage",
                          plan.session_id, plan.round_id, plan.step, None, payload)
    encoded = encode_envelope(frame)
    assert len(encoded) + 4 <= 8192
    restored = decode_envelope(encoded).payload
    assert restored.values == values and restored.plan_sha256 == payload.plan_sha256
    assert codec._decode_preloaded_values(restored.values, restored.input_message, plan, q).plan == plan
    for field, bad in (("version", "control-batch-v1"), ("unknown", 1), ("values", "AB=="),
                       ("values", "AA==\n"), ("values", "A"*(4*((maximum+2)//3)+4))):
        obj = json.loads(encoded)
        obj["payload"][field] = bad
        with pytest.raises(LocalhostCodecError):
            decode_envelope(json.dumps(obj).encode())
    with pytest.raises(LocalhostCodecError, match="重复"):
        decode_envelope(encoded.replace(b'"values":', b'"values":"AA==","values":'))
    for field, bad in (("step", 799), ("round_id", "old"), ("recipient", "P2")):
        with pytest.raises(LocalhostCodecError):
            replace(frame, **{field: bad})


@pytest.mark.parametrize("profile", ["control-dynamic-compact-v1", "control-dynamic-compact-v2"])
def test_compact_restore_and_peer_bind_original_plan_input_and_phase(profile):
    from test_two_party_protocol import make_stack

    from secure_control.execution import lan_runtime as lan
    from secure_control.execution import localhost_codec as codec

    client, _, _, _, distribution = make_stack()
    current = client.prepare_online(distribution, [.25], step=0)
    plan, q = current.p1_resources.plan, client.fixed_point.modulus
    raw = codec._encode_preloaded_values(current.p1_resources, q)
    value = codec._CompactOnlinePayload(current.p1_input, "run", "epoch", public_step_plan_sha256(plan), raw, profile)
    args = {"layout": distribution.p1.layout, "session": plan.session_id, "round_id": plan.round_id,
            "step": 0, "modulus": q, "run_id": "run", "epoch_id": "epoch", "party": 0, "wire_profile": profile}
    assert lan._restore_compact_online(value, **args).plan == plan
    for changed in (replace(value, version=next(p for p in codec._COMPACT_PROFILES if p != profile)),
                    replace(value, run_id="other"), replace(value, epoch_id="other"),
                    replace(value, plan_sha256="0"*64), replace(value, values=raw[:-1]),
                    replace(value, input_message=replace(value.input_message, recipient=1)),
                    replace(value, input_message=replace(value.input_message, round_id="old"))):
        with pytest.raises(ValueError):
            lan._restore_compact_online(changed, **args)
    with pytest.raises(ValueError):
        codec._encode_preloaded_values(replace(current.p1_resources,
            product_resources=tuple(reversed(current.p1_resources.product_resources))), q)
    peer = LocalhostProtocol3PeerPort(None, "P1", 8*1024*1024, 1.,
                                      batch_enabled=True, wire_profile=profile)
    peer.bind(plan.session_id)
    peer.set_batch_round(plan, modulus=q, run_id="run", epoch_id="epoch", physical_step=7)
    ids = tuple(r.resource_id for r in plan.product_resources)
    products = tuple(ProductMaskPayload(AdditiveShare(0), AdditiveShare(q-1), 1) for _ in ids)
    old = Protocol3BatchPayload("product", public_step_plan_sha256(plan), "run", "epoch", 7, 0, ids, products)
    compact = peer._wire_batch(old)
    frame = WireEnvelope(SCHEMA_VERSION, "request", "P2", "P1", 1, "peer_batch",
                          plan.session_id, plan.round_id, 0, None, compact)
    for changed in (replace(frame, sequence=2), replace(frame, round_id="old"), replace(frame, step=1),
                    replace(frame, payload=old),
                    replace(frame, payload=replace(compact, version=next(p for p in codec._COMPACT_PROFILES if p != profile))), replace(frame, payload=replace(compact, run_id="old")),
                    replace(frame, payload=replace(compact, epoch_id="old")),
                    replace(frame, payload=replace(compact, physical_step=8)),
                    replace(frame, payload=replace(compact, plan_sha256="0"*64)),
                    replace(frame, payload=replace(compact, values=compact.values[:-1])),
                    replace(frame, payload=replace(compact, values=q.to_bytes(4,"big")+compact.values[4:]))):
        with pytest.raises(ValueError):
            peer._validate_batch(changed, plan, "product", ids)
        assert peer._receive_sequence == 1
    assert peer._validate_batch(decode_envelope(encode_envelope(frame)), plan, "product", ids).products == products
    assert peer._receive_sequence == 2
    client.abort_round(current)


@pytest.mark.parametrize("profile", ["control-dynamic-compact-v1", "control-dynamic-compact-v2"])
def test_compact_worker_packet_and_original_capability_bind_encoding_profile(profile):
    from copy import copy

    from test_two_party_protocol import make_stack

    from secure_control.execution import _material_worker as worker
    from secure_control.execution.localhost_codec import _COMPACT_PROFILES, _encode_preloaded_values

    client, _, _, _, distribution = make_stack()
    owner = client._material_owner(distribution)
    prepared = owner.create(0, rng=random.Random(31))
    plan = prepared.p1_resources.plan
    spec = worker._WorkerSpec(owner.layout, client.fixed_point.modulus, 8, 8, None, None,
        "run", distribution.session_id, "epoch", 0, 16, profile)
    worker._check_spec(spec)
    with pytest.raises(ValueError, match="预留"):
        worker._check_spec(replace(spec, modulus=1 << 100000))
    fragments = tuple(_encode_preloaded_values(r, spec.modulus)
                      for r in (prepared.p1_resources, prepared.p2_resources))
    packet = worker._package(spec, plan, fragments, 10, 5)
    assert worker._unpack(spec, packet, 0)[:2] == (plan, fragments)
    for changed in (replace(spec, encoding_profile=next(p for p in _COMPACT_PROFILES if p != profile)),
                    replace(spec, encoding_profile="control-batch-v1"), replace(spec, epoch="old")):
        with pytest.raises(ValueError):
            worker._unpack(changed, packet, 0)
    wrong = worker._package(spec, plan, (b'{"old":"json"}', fragments[1]), 10, 5)
    with pytest.raises(ValueError, match="长度"):
        worker._unpack(spec, wrong, 0)
    source = object()
    owner.open_encoded_source(source, encoding_profile=profile)
    with pytest.raises(ValueError):
        owner.register_encoded(source, plan, fragments)
    cap = owner.register_encoded(source, plan, fragments, encoding_profile=profile)
    assert cap.encoding_profile == profile
    for invalid in (copy(cap), replace(cap, encoding_profile="control-batch-v1")):
        with pytest.raises(ValueError, match="原始"):
            client._bind_encoded_input(distribution, invalid, [.25], step=0)
    current = client._bind_encoded_input(distribution, cap, [.25], step=0)
    with pytest.raises(ValueError):
        client._bind_encoded_input(distribution, cap, [.25], step=0)
    client.abort_round(current)
    owner.discard(prepared)


@pytest.mark.parametrize("failure", ("encoding", "second_send", "second_reply"))
def test_compact_fused_preflight_and_partial_failure_never_commit_or_replay(monkeypatch, failure):
    import numpy as np
    from test_two_party_protocol import make_stack

    from secure_control.execution import _localhost_workers as workers
    from secure_control.execution import lan_runtime as lan
    from secure_control.execution import localhost_codec as codec
    from secure_control.execution import localhost_transport as transport
    from secure_control.execution._material_worker import _MaterialWorkerPool
    from secure_control.protocol.messages import ControlShareMessage, Protocol3StageReceipt

    client, _, _, _, distribution = make_stack()
    owner = client._material_owner(distribution)
    prepared = owner.create(0)
    plan = prepared.p1_resources.plan
    source = object()
    owner.open_encoded_source(source, encoding_profile=codec._COMPACT_PROFILE)
    cap = owner.register_encoded(source, plan, tuple(codec._encode_preloaded_values(r, client.fixed_point.modulus)
        for r in (prepared.p1_resources, prepared.p2_resources)), encoding_profile=codec._COMPACT_PROFILE)
    pool = _MaterialWorkerPool.__new__(_MaterialWorkerPool)
    pool.owner, pool.take = owner, lambda step: cap
    pool.observe_current_encoded = lambda size: None
    runtime = lan.LanContinuousRuntime.__new__(lan.LanContinuousRuntime)
    runtime.__dict__.update(_v2=True, _failed=False, _finished=False, _step=0,
        _wire_profile=codec._COMPACT_PROFILE, _segment_start=0, _segment_capacity=400,
        _preload_steps=0, _material_pool=pool, _sockets=["p1", "p2"], _sequences=[4, 4],
        _batch=True, _overlap_commit=True, client=client, distribution=distribution,
        spec=SimpleNamespace(input_dimension=1), config=SimpleNamespace(step_timeout=1.),
        session_id=distribution.session_id, setup_run_id="run", setup=SimpleNamespace(controller_epoch="epoch"))
    events, requests = [], {}
    encode = transport.encode_envelope
    def encoded(request):
        events.append("encode")
        if failure == "encoding" and request.recipient == "P2":
            raise ValueError("second encoding")
        return encode(request)
    def sent(sock, data, **kwargs):
        assert events[:2] == ["encode", "encode"]
        requests[sock] = decode_envelope(data)
        assert requests[sock].operation == "online_stage"
        events.append(sock)
        if failure == "second_send" and sock == "p2":
            raise ValueError("second send")
    def received(sock, **kwargs):
        assert events[:4] == ["encode", "encode", "p1", "p2"]
        request = requests[sock]
        party = 0 if sock == "p1" else 1
        receipt = Protocol3StageReceipt(party, plan.session_id, plan.round_id, 0,
                                       plan.triple_count, plan.truncation_count)
        share = ControlShareMessage(party, plan.session_id, plan.round_id, 0,
            plan.scale_ledger.output, AdditiveShare(np.array([0], dtype=object)))
        return WireEnvelope(SCHEMA_VERSION, "reply", request.recipient, "Client",
            request.sequence + (1 if party == 1 else 0), "online_stage", plan.session_id,
            plan.round_id, 0, None, codec.PartyStageResult(receipt, share))
    monkeypatch.setattr(transport, "encode_envelope", encoded)
    monkeypatch.setattr(workers, "send_frame", sent)
    monkeypatch.setattr(workers, "receive_envelope", received)
    monkeypatch.setattr(runtime, "close", lambda: events.append("closed"))
    monkeypatch.setattr(client, "reconstruct_control", lambda *args: pytest.fail("failed fused request reconstructed"))
    with pytest.raises((ValueError, RuntimeError)):
        runtime.step([.25])
    assert runtime._failed and not client._issued_rounds and events[-1] == "closed"
    assert runtime._round_started is (failure != "encoding")
    if failure == "encoding":
        assert events == ["encode", "encode", "closed"]
    with pytest.raises(RuntimeError):
        runtime.step([.25])
    with pytest.raises(ValueError):
        client._bind_encoded_input(distribution, cap, [.25], step=0)
    owner.discard(prepared)


def test_compact_and_original_kernel_exact_shares_across_two_400_boundaries(monkeypatch):
    """801轮纯协议正确性；没有控制周期、性能计时、供料预热或资格观察。"""
    import numpy as np
    from test_two_party_protocol import make_stack

    from secure_control.execution import _localhost_peer as peer_module
    from secure_control.execution.localhost_codec import (
        _COMPACT_PROFILE,
        _COMPACT_PROFILE_V2,
        _COMPACT_PROFILE_V3,
        _decode_preloaded_values,
        _encode_preloaded_values,
    )

    client, _, _, _, distribution = make_stack()
    profiles = ("control-batch-v1", _COMPACT_PROFILE, _COMPACT_PROFILE_V2, _COMPACT_PROFILE_V3)
    roles = [[role_type(rehydrate_offline_material(PartyOfflineMaterial.from_message(material),
                distribution.range_contract)) for role_type, material in ((P1, distribution.p1), (P2, distribution.p2))]
             for _ in profiles]
    peers = [[LocalhostProtocol3PeerPort(s, f"P{i+1}", 8*1024*1024, 10.,
                batch_enabled=True, wire_profile=profile) for i, s in enumerate(socket.socketpair())]
             for profile in profiles]
    frames = {profile: [] for profile in profiles}
    original_send, original_exchange = peer_module.send_envelope, peer_module._exchange_frame
    def sent(sock, frame, **kwargs):
        frames["control-batch-v1" if isinstance(frame.payload, Protocol3BatchPayload) else frame.payload.version].append(
            (frame.payload.phase, len(encode_envelope(frame))+4))
        return original_send(sock, frame, **kwargs)
    def exchanged(sock, data, **kwargs):
        frame = decode_envelope(data)
        frames[frame.payload.version].append((frame.payload.phase, len(data)+4))
        return original_exchange(sock, data, **kwargs)
    monkeypatch.setattr(peer_module, "send_envelope", sent)
    monkeypatch.setattr(peer_module, "_exchange_frame", exchanged)
    for pair in peers:
        for port in pair:
            port.bind(distribution.session_id)
    errors = []
    try:
        for step in range(801):
            current = client.prepare_online(distribution, [.25 if step % 2 else -.125],
                                             step=step, rng=random.Random(step+110))
            plan = current.p1_resources.plan
            original = [PartyOnlineMaterial.from_round(PartyOnlineRound(inp, resources))
                for inp, resources in ((current.p1_input, current.p1_resources),
                                       (current.p2_input, current.p2_resources))]
            compact = [_decode_preloaded_values(_encode_preloaded_values(resources, client.fixed_point.modulus),
                inp, plan, client.fixed_point.modulus) for inp, resources in (
                    (current.p1_input, current.p1_resources), (current.p2_input, current.p2_resources))]
            results = []
            for index, materials in enumerate((original, compact, compact, compact)):
                outputs = [[], []]
                local = [rehydrate_online_material(m, modulus=client.fixed_point.modulus, security_parameter=8)
                         for m in materials]
                strategy = "client_authorized" if profiles[index] == _COMPACT_PROFILE_V3 else "peer_barriers"
                endpoints = [LocalProtocol3PartyEndpoint(roles[index][i], local[i], outputs[i].append,
                                                        completion_strategy=strategy)
                             for i in (0, 1)]
                receipts = [None, None]
                for port in peers[index]:
                    port.set_batch_round(plan, modulus=client.fixed_point.modulus, run_id="run", epoch_id="epoch")
                def stage(i, endpoints=endpoints, pair=peers[index], receipts=receipts):
                    try:
                        receipts[i] = stage_protocol3_batch(endpoints[i], pair[i])
                    except BaseException as error:  # noqa: BLE001 - 保留线程原始失败供断言。
                        errors.append(error)
                threads = [Thread(target=stage, args=(i,)) for i in (0, 1)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(12.)
                assert not any(t.is_alive() for t in threads) and not errors, errors
                if strategy == "client_authorized":
                    assert all(r.resources.consumed_count == 0 for r in local)
                    authorization = Protocol3Orchestrator(completion_strategy=strategy).authorize(tuple(receipts), plan)
                    for endpoint in endpoints:
                        endpoint.commit_staged(authorization)
                else:
                    Protocol3Orchestrator().commit(*endpoints)
                results.append([outputs[i][0].value.value for i in (0, 1)])
                assert all(r.resources.consumed_count == plan.triple_count+plan.truncation_count for r in local)
            for i in (0, 1):
                for index in (1, 2, 3):
                    assert np.array_equal(results[0][i], results[index][i])
                    assert np.array_equal(roles[0][i].state_share.value, roles[index][i].state_share.value)
            client.abort_round(current)
        for profile in profiles:
            authorized = profile == _COMPACT_PROFILE_V3
            assert len(frames[profile]) == 801*(3 if authorized else 7)
            assert {phase: sum(p == phase for p, _ in frames[profile]) for phase in (
                "product", "product_complete", "truncation", "state_complete")} == {
                    "product": 1602, "product_complete": 0 if authorized else 1602,
                    "truncation": 801, "state_complete": 0 if authorized else 1602}
    finally:
        for pair in peers:
            for port in pair:
                port.close()


def test_preloaded_material_values_are_lossless_and_reject_noncanonical_last_value():
    from test_two_party_protocol import make_stack

    from secure_control.execution.localhost_codec import (
        _decode_preloaded_values,
        _encode_preloaded_values,
    )

    client, _, _, _, distribution = make_stack()
    online = client.prepare_online(distribution, [.25], step=0, rng=random.Random(91))
    q = client.fixed_point.modulus
    for inp, resources in ((online.p1_input, online.p1_resources),
                           (online.p2_input, online.p2_resources)):
        encoded = _encode_preloaded_values(resources, q)
        material = _decode_preloaded_values(encoded, inp, resources.plan, q)
        assert material == PartyOnlineMaterial.from_round(PartyOnlineRound(inp, resources))
        width = (q.bit_length() + 7) // 8
        assert len(encoded) == width * (3 * resources.plan.triple_count
                                        + 2 * resources.plan.truncation_count)
        with pytest.raises(ValueError, match="长度"):
            _decode_preloaded_values(encoded[:-1], inp, resources.plan, q)
        with pytest.raises(ValueError, match="residue"):
            _decode_preloaded_values(encoded[:-width] + q.to_bytes(width, "big"),
                                     inp, resources.plan, q)
        last = resources.state_truncation_resources[-1].truncation
        previous = last.r_prime
        object.__setattr__(last, "r_prime", AdditiveShare(True))
        with pytest.raises(ValueError, match="residue"):
            _encode_preloaded_values(resources, q)
        object.__setattr__(last, "r_prime", previous)
    client.abort_round(online)


def test_preloaded_client_requires_original_confirmed_capability_and_fresh_current_input(monkeypatch):
    from copy import copy

    from test_two_party_protocol import make_stack

    from secure_control.protocol.messages import ControlShareMessage, PreloadReceipt

    client, _, _, _, distribution = make_stack()
    batch = client.begin_preloaded_resources(distribution, run_id="run", controller_epoch="epoch",
                                             count=2)
    digest = batch.manifest.sha256()
    def receipts(phase, count=2, index=None, first=None):
        return tuple(PreloadReceipt(party, digest, phase, index, first, count) for party in (0, 1))
    with pytest.raises(ValueError, match="就绪"):
        client.bind_preloaded_input(distribution, batch, [.25], step=0)
    with pytest.raises(ValueError, match="复制"):
        client.export_preloaded_step(distribution, copy(batch), step=0)
    with pytest.raises(ValueError, match="生成次序"):
        client.export_preloaded_step(distribution, batch, step=0)
    client.record_preloaded_receipts(distribution, batch, receipts("init"))
    with pytest.raises(ValueError):
        client.record_preloaded_receipts(distribution, batch, receipts("seal"))
    owner = client._material_owner(distribution)
    original, held = owner.create, []
    def create(*args, **kwargs):
        prepared = original(*args, **kwargs)
        held.append(prepared)
        return prepared
    monkeypatch.setattr(owner, "create", create)
    for step in range(2):
        exported = client.export_preloaded_step(distribution, batch, step=step)
        prepared = held[-1]
        assert exported.plan.round_id == batch.manifest.round_ids[step]
        assert not client._issued_rounds
        assert prepared.p1_resources.aborted_count == prepared.p1_resources.consumed_count == 0
        assert all(v._lifecycle.status == "exported" for v in (*prepared.p1_resources.product_resources,
                   *prepared.p1_resources.state_truncation_resources))
        with pytest.raises(ValueError):
            client.bind_online_input(distribution, prepared, [.25], step=step)
        for i in range(exported.plan.triple_count):
            a, b, c = (sum(pair) % client.fixed_point.modulus for pair in zip(
                exported.p1_values[3*i:3*i+3], exported.p2_values[3*i:3*i+3], strict=True))
            assert a * b % client.fixed_point.modulus == c
    client.record_preloaded_receipts(distribution, batch, receipts("block", index=0, first=0))
    client.record_preloaded_receipts(distribution, batch, receipts("seal"))
    with pytest.raises(ValueError, match="input_payload_bounds"):
        client.bind_preloaded_input(distribution, batch, [1000], step=0)
    assert not client._issued_rounds
    for step in range(2):
        current = client.bind_preloaded_input(distribution, batch, [.25], step=step)
        with pytest.raises(ValueError, match="重复领取"):
            client.bind_preloaded_input(distribution, batch, [.25], step=step)
        assert (current.session_id, current.round_id, step) in client._issued_rounds
        with pytest.raises(ValueError, match="重构"):
            client.retire_preloaded_round(current, success=True)
        import numpy as np
        messages = tuple(ControlShareMessage(party, current.session_id, current.round_id, step,
                         current.plan.scale_ledger.output, AdditiveShare(np.array([0], dtype=object)))
                         for party in (0, 1))
        client.reconstruct_control(*messages)
        client.retire_preloaded_round(current, success=True)
    with pytest.raises(ValueError, match="耗尽"):
        client.bind_preloaded_input(distribution, batch, [.25], step=2)
    client.discard_preloaded_resources(distribution, batch)
    with pytest.raises(ValueError, match="废弃"):
        client.bind_preloaded_input(distribution, batch, [.25], step=2)


def test_segment_begin_sends_both_before_reading_and_closes_on_bad_second_ack(monkeypatch):
    from secure_control.execution import lan_runtime as lan
    from secure_control.execution.localhost_codec import SegmentBeginPayload

    runtime = lan.LanContinuousRuntime.__new__(lan.LanContinuousRuntime)
    runtime._v2, runtime._failed, runtime._finished, runtime._step = True, False, False, 2
    runtime._sockets, runtime._sequences = ["p1", "p2"], [10, 10]
    runtime.session_id = "session"
    runtime.config = SimpleNamespace(shutdown_timeout=1.)
    runtime._confirmed_steps, runtime._confirmed_plans = ["old"], ["old"]
    events = []

    def sent(sock, *args, **kwargs):
        assert kwargs["send_only"]
        events.append(sock)
        return sock

    def received(sock, *args, **kwargs):
        assert events[:2] == ["p1", "p2"]
        if sock == "p2":
            raise ValueError("bad second ACK")

    monkeypatch.setattr(lan, "_request", sent)
    monkeypatch.setattr(lan, "_receive_reply", received)
    monkeypatch.setattr(runtime, "close", lambda: events.append("closed"))
    begin = SegmentBeginPayload("run", 1, 2, "a" * 64, "previous-round")
    with pytest.raises(ValueError, match="second ACK"):
        runtime.begin_segment(begin)
    assert runtime._failed and events == ["p1", "p2", "closed"]
    assert runtime._confirmed_steps == ["old"]


def test_online_preflights_both_full_frames_once_and_invalidates_on_bad_second_ack(monkeypatch):
    """第二帧超限不得先泄出第一帧；发送复用已校验的 canonical 字节。"""
    from test_two_party_protocol import make_stack

    from secure_control.execution import lan_runtime as lan
    from secure_control.execution import localhost_codec as codec
    from secure_control.execution import localhost_transport as transport

    original = codec._encode_value
    for oversized in (True, False):
        client, _, _, _, distribution = make_stack()
        online = client.prepare_online(distribution, [.25], step=0)
        runtime = lan.LanContinuousRuntime.__new__(lan.LanContinuousRuntime)
        runtime._v2, runtime._failed, runtime._finished, runtime._step = True, False, False, 0
        runtime._segment_start, runtime._segment_capacity = 0, 400
        runtime._material_pool = None
        runtime._preload_steps = 0
        runtime._wire_profile = "control-batch-v1"
        runtime._sockets, runtime._sequences = ["p1", "p2"], [4, 4]
        runtime.client, runtime.distribution = client, distribution
        runtime.spec, runtime.config = SimpleNamespace(input_dimension=1), SimpleNamespace(step_timeout=1.)
        runtime.session_id = online.session_id
        frames = tuple(WireEnvelope(
            SCHEMA_VERSION, "request", "Client", role, 4, "online", online.session_id,
            online.round_id, 0, None, PartyOnlineMaterial.from_round(PartyOnlineRound(inp, resources)),
        ) for role, inp, resources in (
            ("P1", online.p1_input, online.p1_resources),
            ("P2", online.p2_input, online.p2_resources),
        ))
        canonical = tuple(encode_envelope(frame) for frame in frames)
        events = []

        def counted(value, events=events):
            if isinstance(value, PartyOnlineMaterial):
                events.append("encode")
            return original(value)

        def encoded(message, oversized=oversized):
            value = encode_envelope(message)
            return value + b" " * lan._FRAME_LIMIT if oversized and message.recipient == "P2" else value

        def sent(sock, payload, deadline, events=events, canonical=canonical):
            assert events[:2] == ["encode", "encode"] and events.count("encode") == 2
            assert payload[4:] == canonical[0 if sock == "p1" else 1]
            events.append(sock)

        def received(sock, *args, events=events, **kwargs):
            assert events[-2:] == ["p1", "p2"]
            if sock == "p2":
                raise ValueError("bad second ACK")

        monkeypatch.setattr(client, "prepare_online", lambda *args, online=online, **kwargs: online)
        monkeypatch.setattr(codec, "_encode_value", counted)
        monkeypatch.setattr(transport, "encode_envelope", encoded)
        monkeypatch.setattr(transport, "_send_exact", sent)
        monkeypatch.setattr(lan, "_receive_reply", received)
        monkeypatch.setattr(runtime, "close", lambda events=events: events.append("closed"))
        expected = LocalhostTransportProtocolError if oversized else ValueError
        with pytest.raises(expected, match="上限" if oversized else "second ACK"):
            runtime.step([.25])
        assert events == ["encode", "encode", *([] if oversized else ["p1", "p2"]), "closed"]
        assert runtime._failed and runtime._step == 0
        assert runtime._round_started is (not oversized)
        assert (online.session_id, online.round_id, online.step) not in client._issued_rounds
        monkeypatch.setattr(codec, "_encode_value", original)


@pytest.mark.integration
def test_continuous_observation_retains_first_failed_attempt_without_error_payload(monkeypatch):
    from secure_control.experiments.communication_benchmark import run_continuous_observation
    from secure_control.protocol import Client

    def failed(*args, **kwargs):
        raise ValueError("private-value-must-not-appear")

    monkeypatch.setattr(Client, "prepare_online", failed)
    report = run_continuous_observation(steps=2, delay_ms=0, segment_steps=1)
    assert report["status"] == "failed"
    assert len(report["steps"]) == 1 and report["steps"][0]["status"] == "failed"
    assert report["steps"][0]["global_step"] == 0
    assert report["timing"]["sample_count"] == 1
    assert "private-value-must-not-appear" not in str(report)


def test_finite_diagnostic_same_thread_missing_clock_gc_and_bounded_events(monkeypatch):
    import gc
    import json
    from itertools import count
    from threading import Thread

    from secure_control.experiments.communication_benchmark import _Diagnostic

    wall, cpu = count(0, 100), count(0, 10)
    diag = _Diagnostic("Client", wall=lambda: next(wall), cpu=lambda: next(cpu), limit=3)
    before = list(gc.callbacks), gc.isenabled(), gc.get_threshold()
    with diag.installed():
        diag.select(2)
        with diag.scope("ignored"):
            pass
        assert all(slot is None for slot in diag.slots)
        diag.select(0)
        for _ in range(2):
            with diag.scope("input"):
                pass
        diag._gc("start", {"generation": 0})
        diag._gc("stop", {"generation": 0})
        diag._gc("start", {"generation": 1})
        with diag.scope("dropped"):
            pass
    assert (list(gc.callbacks), gc.isenabled(), gc.get_threshold()) == before
    report = diag.report()
    value = next(item for item in report["events"] if item["kind"] == "phase")
    assert (value["calls"], value["wall_ns"], value["cpu_ns"], value["non_cpu_ns"]) == (2, 200, 20, 180)
    assert len(report["events"]) == 3 and report["overflow"] == 2
    assert report["callback_restored"] and report["gc_before"] == report["gc_after"]

    def unavailable():
        raise NotImplementedError

    missing = _Diagnostic("P1", cpu=unavailable)
    missing.select(397)
    with missing.scope("restore"):
        pass
    value = missing.report()["events"][0]
    assert value["cpu_ns"] is None and value["non_cpu_ns"] is None
    assert value["cpu_missing_calls"] == 1 and missing.cpu_errors > 0
    token = missing.begin("thread_check")
    errors = []

    def wrong_thread():
        try:
            missing.end(token)
        except RuntimeError as error:
            errors.append(type(error).__name__)

    worker = Thread(target=wrong_thread)
    worker.start()
    worker.join()
    assert errors == ["RuntimeError"]
    missing.end(token)

    large = _Diagnostic("Client")
    large.select(405)
    for index in range(600):
        with large.scope("public_phase_" + str(index)):
            pass
    large_report = large.report()
    assert large_report["overflow"] == 88 and large_report["encoded_overflow"] > 0
    assert len(json.dumps(large_report, separators=(",", ":")).encode()) < 80 * 1024


@pytest.mark.integration
def test_finite_diagnostic_keeps_failed_null_cycle_and_restores_canonical_hooks(monkeypatch):
    import gc
    import json
    import os

    from secure_control.execution import lan_runtime, localhost_transport
    from secure_control.experiments import cart_pole_segmented_evidence as evidence
    from secure_control.experiments.communication_benchmark import run_continuous_observation
    from secure_control.protocol import Client

    before = (list(gc.callbacks), gc.isenabled(), gc.get_threshold(),
              evidence._batch_phase, evidence._Spool.record_batch, os.fsync,
              lan_runtime.receive_envelope, localhost_transport._send_exact)

    def failed(*args, **kwargs):
        raise ValueError("secret-diagnostic-must-not-appear")

    monkeypatch.setattr(Client, "bind_preloaded_input", failed)
    report = run_continuous_observation(steps=1, delay_ms=0, segment_steps=2,
                                       optimized=True, preload_steps=1, diagnostic=True)
    assert report["diagnostic"] and not report["qualification_pass"]
    assert not report["stage_pass"] and report["successful_steps"] == 0
    assert len(report["cycles"]) == 1
    cycle = report["cycles"][0]
    assert cycle["device_completed_ns"] is None and cycle["cycle_completed_ns"] is None
    assert cycle["physically_confirmed_count"] == cycle["protocol_committed_count"] == 0
    assert report["recording_summary"]["durable_step_count"] == 0
    assert "secret-diagnostic-must-not-appear" not in json.dumps(report)
    assert (list(gc.callbacks), gc.isenabled(), gc.get_threshold(),
            evidence._batch_phase, evidence._Spool.record_batch, os.fsync,
            lan_runtime.receive_envelope, localhost_transport._send_exact) == before
    diag = report["diagnostic_report"]
    assert len(json.dumps(diag, separators=(",", ":"), ensure_ascii=False).encode()) == diag["encoded_bytes"]
    assert diag["encoded_bytes"] <= 256 * 1024 and len(diag["roles"]) == 3
    assert all(role["callback_restored"] and role["gc_before"] == role["gc_after"]
               for role in diag["roles"])


def test_supply_diagnostic_windows_gc_pairing_missing_cpu_and_fixed_budgets():
    import gc
    import json
    from itertools import count

    from secure_control.experiments.communication_benchmark import _Diagnostic

    def unavailable():
        raise NotImplementedError

    wall = count(0, 100)
    diag = _Diagnostic("Client", supply=True, wall=lambda: next(wall), cpu=unavailable)
    selected = [step for step in range(406) if diag._selected_step(step)]
    assert selected == [0, 1, 165, 166, 167, 168, 176, 177, 178, 179, 180]
    before = list(gc.callbacks), gc.isenabled(), gc.get_threshold()
    with diag.installed():
        diag.select(164)
        diag._gc("start", {"generation": 1})
        diag.select(165)
        diag._gc("stop", {"generation": 1})
        diag._gc("stop", {"generation": 2})
        diag._gc("start", {"generation": 0})
        diag._gc("stop", {"generation": 2})
        for _ in range(600):
            with diag.scope("public_task"):
                pass
    assert (list(gc.callbacks), gc.isenabled(), gc.get_threshold()) == before
    report = diag.report()
    assert report["overflow"] == 92 and report["encoded_overflow"] > 0
    assert len(json.dumps(report, separators=(",", ":")).encode()) < 80 * 1024
    events = report["events"]
    paired = events[0]
    assert paired["pairing"] == "complete" and paired["generation"] == 1
    assert paired["control_global_step"] == 164 and paired["control_global_step_end"] == 165
    assert paired["start_ns"] < paired["end_ns"] and paired["cpu_delta_ns"] is None
    assert {item["pairing"] for item in events if item["kind"] == "gc_interval"} == {
        "complete", "missing_start", "missing_stop",
    }
    assert all(item.get("cpu_delta_ns") is None for item in events)
    # report不消费overflow状态；默认诊断仍使用原跨段窗口。
    assert diag.report() == report
    legacy = _Diagnostic("Client")
    assert legacy._selected_step(397) and not legacy._selected_step(179)
    entire = _Diagnostic("Client", supply=True, all_gc=True)
    entire.select(999)
    entire._gc("start", {"generation": 2})
    entire._gc("stop", {"generation": 2, "collected": 7, "uncollectable": 0})
    entire._gc("start", {"generation": 1})
    complete, missing = entire.report()["events"]
    assert complete["control_global_step"] == 999 and complete["collected"] == 7
    assert complete["uncollectable"] == 0 and complete["pairing"] == "complete"
    assert missing["pairing"] == "missing_stop" and missing["collected"] is None
    party = _Diagnostic("P1", supply=True)
    party.select(167)
    with party.scope("party_stage"):
        pass
    event = party.report()["events"][0]
    assert event["control_global_step"] == 167
    assert event["control_active"] is event["control_active_end"] is None


def test_gc_trial_rejects_invalid_combinations_before_any_experiment(monkeypatch):
    from secure_control.experiments import communication_benchmark as benchmark

    def forbidden(*args, **kwargs):
        pytest.fail("invalid GC trial created experiment/GC scope")

    monkeypatch.setattr(benchmark, "_ports", forbidden)
    monkeypatch.setattr(benchmark._StartupGCTrial, "installed", forbidden)
    options = {"steps": 1000, "delay_ms": 0, "segment_steps": 400, "optimized": True,
               "diagnostic": True, "recording_mode": "light", "gc_trial_policy": "baseline"}
    for change in ({"steps": True}, {"steps": 999}, {"delay_ms": 1}, {"delay_ms": False},
                   {"segment_steps": 8}, {"material_slots": 4}, {"preload_steps": 1},
                   {"preload_execution": "staged"}, {"optimized": False}, {"diagnostic": False},
                   {"recording_mode": "full"}, {"role_config": "missing"}, {"tcp_nodelay": False},
                   {"commit_policy": "serial"}, {"gc_trial_policy": "invalid"}):
        with pytest.raises(ValueError):
            benchmark.run_continuous_observation(**{**options, **change})
    trial = benchmark._StartupGCTrial("baseline")
    for policy in ("baseline", "startup-freeze"):
        traced = {**options, "steps": 200, "gc_trial_policy": policy, "timeout_trace": True}
        for change in ({"steps": 1000}, {"steps": 199}, {"steps": True}, {"timeout_trace": 1},
                       {"timeout_trace": False}, {"gc_trial_policy": None}, {"gc_trial_policy": "invalid"},
                       {"role_config": "missing"}, {"material_slots": 4}, {"preload_steps": 1},
                       {"diagnostic": False}, {"recording_mode": "full"}, {"segment_steps": 200},
                       {"delay_ms": 1}, {"tcp_nodelay": False}, {"commit_policy": "serial"}):
            with pytest.raises(ValueError):
                benchmark.run_continuous_observation(**{**traced, **change})
    monkeypatch.setattr(benchmark, "_run_continuous_observation", lambda **kwargs: kwargs)
    default = benchmark.run_continuous_observation(steps=200, segment_steps=400, delay_ms=0)
    assert default["timeout_trace"] is False  # 默认路径不进入任何GC/探针作用域。
    for memory in ({"current_rss_bytes": None, "peak_rss_bytes": 1},
                   {"current_rss_bytes": trial.RSS_LIMIT + 1, "peak_rss_bytes": trial.RSS_LIMIT + 1}):
        monkeypatch.setattr(benchmark, "_process_memory", lambda memory=memory: memory)
        with pytest.raises(RuntimeError):
            trial.memory("before_input", step=100, guard=True)
        assert trial.report["memory_samples"][-1]["global_step"] == 100


def test_gc_trial_real_gc_isolated_process_reclaims_new_cycles_and_restores_on_failure():
    import subprocess
    import sys
    import textwrap

    # 真freeze只在一次性子进程执行；不把pytest及其他测试的对象送入永久代。
    program = textwrap.dedent('''
        import gc, sys, weakref
        from threading import Event, Thread
        from secure_control.experiments import communication_benchmark as benchmark
        from secure_control.experiments.communication_benchmark import _StartupGCTrial
        from secure_control.execution.lan_runtime import LanSegmentedRuntime, _OnlineResourcePool
        case = sys.argv[1]
        before = gc.isenabled(), gc.get_threshold(), gc.get_debug(), list(gc.callbacks)
        if case in ("s3-scope", "s4-scope", "s4-scope-failure"):
            from contextlib import ExitStack
            from secure_control.execution import localhost_transport
            policy = "baseline" if case.startswith("s4-") else "startup-freeze"
            if policy == "baseline":
                def forbidden(*args):
                    raise AssertionError("baseline called freeze/unfreeze/disable")
                gc.freeze = gc.unfreeze = gc.disable = forbidden
            original_send, original_close = localhost_transport._send_exact, LanSegmentedRuntime.close
            predecessor = lambda *args: original_send(*args)
            localhost_transport._send_exact = predecessor
            def simulated(**options):
                assert options["steps"] == 200 and options["timeout_trace"]
                trial = options["_gc_trial"]
                assert trial.policy == policy
                assert bool(gc.get_freeze_count()) == (policy == "startup-freeze")
                observer = benchmark._TimeoutDiagnostic("Client", (101, 102, 103))
                sockets = ExitStack()
                trial.cleanup.callback(sockets.close)
                sockets.enter_context(observer.sockets())
                _, _, restore = benchmark._meter("Client", (101, 102, 103), 0, diagnostic=observer)
                trial.cleanup.callback(restore)
                if case == "s4-scope-failure":
                    raise OSError("private baseline scope initialization failure")
                restore()
                sockets.close()
                assert localhost_transport._send_exact is predecessor
                return {"status": "stopped", "timeout_trace": {"format_version": 1},
                        "diagnostic_report": {"roles": [observer.report()]}}
            benchmark._run_continuous_observation = simulated
            report = benchmark.run_continuous_observation(
                steps=200, delay_ms=0, segment_steps=400, optimized=True, diagnostic=True,
                recording_mode="light", gc_trial_policy=policy, timeout_trace=True)
            assert localhost_transport._send_exact is predecessor
            assert LanSegmentedRuntime.close is original_close
            assert report["gc_trial"]["restored"] and not report["gc_trial"]["cleanup_failed"]
            if case == "s4-scope-failure":
                assert report["status"] == "failed" and report["failure_category"] == "OSError"
            else:
                assert report["status"] == "stopped"
                assert report["diagnostic_report"]["roles"][0]["socket_hooks_restored"]
            assert report["gc_trial"]["freeze"]["after_count"] == 0 if policy == "baseline" else report["gc_trial"]["freeze"]["after_count"] > 0
            assert not report["qualification_pass"] and not report["stage_pass"]
            assert report["comparison_only"] and report["diagnostic"]
            assert (gc.isenabled(), gc.get_threshold(), gc.get_debug(), list(gc.callbacks)) == before
            sys.exit(0)
        if case in ("init-failure", "hook-init-failure", "s3-hook-init-failure"):
            from secure_control.execution import lan_runtime, localhost_transport
            originals = (localhost_transport._send_exact, localhost_transport.encode_envelope,
                         lan_runtime.LanSegmentedRuntime.close)
            def no_ports():
                assert gc.get_freeze_count() > 0
                raise OSError("private initialization failure")
            if case == "init-failure":
                benchmark._ports = no_ports
            else:
                def no_control():
                    raise OSError("private control initialization failure")
                lan_runtime.RunControl = no_control
            report = benchmark.run_continuous_observation(
                steps=200 if case == "s3-hook-init-failure" else 1000,
                delay_ms=0, segment_steps=400, optimized=True, diagnostic=True,
                recording_mode="light", gc_trial_policy="startup-freeze",
                timeout_trace=case == "s3-hook-init-failure")
            assert report["status"] == "failed" and report["failure_category"] == "OSError"
            assert report["gc_trial"]["restored"] and not report["gc_trial"]["cleanup_failed"]
            assert gc.get_freeze_count() == 0
            assert (gc.isenabled(), gc.get_threshold(), gc.get_debug(), list(gc.callbacks)) == before
            assert not report["qualification_pass"] and not report["stage_pass"]
            assert report["comparison_only"] and report["diagnostic"]
            assert (localhost_transport._send_exact, localhost_transport.encode_envelope,
                    lan_runtime.LanSegmentedRuntime.close) == originals
            sys.exit(0)
        if case == "memory-end":
            closed = []
            LanSegmentedRuntime.close = lambda runtime: closed.append(True)
            trial = _StartupGCTrial("startup-freeze")
            with trial.installed():
                trial.control_started = True
                benchmark._process_memory = lambda: {
                    "current_rss_bytes": trial.RSS_LIMIT + 1, "peak_rss_bytes": trial.RSS_LIMIT + 1}
                LanSegmentedRuntime.close(None)
            assert closed == [True] and trial.report["memory_guard_failed"]
            assert trial.report["restored"] and gc.get_freeze_count() == 0
            assert [s["moment"] for s in trial.report["memory_samples"]] == [
                "before_cold_collect", "after_cold_collect", "control_end", "after_restore"]
            sys.exit(0)
        if case == "reject":
            callback = lambda phase, info: None
            gc.callbacks.append(callback)
            try:
                with _StartupGCTrial("startup-freeze").installed():
                    raise AssertionError("accepted foreign callback")
            except RuntimeError:
                pass
            assert gc.callbacks == [callback] and gc.get_freeze_count() == 0
            sys.exit(0)
        class Cycle:
            pass
        old = Cycle()
        old.link = old
        old_ref = weakref.ref(old)
        trial = _StartupGCTrial("baseline" if case == "baseline" else "startup-freeze")
        gate = Event()
        def initialized(pool, *args, **kwargs):
            pool._thread = Thread(target=gate.wait)
            pool._thread.start()
        def closed(pool):
            raise RuntimeError("cleanup payload must not be exposed")
        if case in ("join-failure", "boundary-failure"):
            _OnlineResourcePool.__init__, _OnlineResourcePool.close = initialized, closed
        try:
            with trial.installed():
                del old
                new = Cycle()
                new.link = new
                new_ref = weakref.ref(new)
                del new
                gc.collect(2)
                assert new_ref() is None
                assert (old_ref() is not None) == (case != "baseline")
                assert gc.isenabled() and gc.get_threshold() == before[1]
                if case in ("join-failure", "boundary-failure"):
                    pool = _OnlineResourcePool(None, None)
                    trial.final_cleanup = case == "join-failure"
                    pool.close()
                    trial.final_cleanup = False
                if case == "exception":
                    raise OSError("original failure")
        except OSError as error:
            assert case == "exception" and str(error) == "original failure"
        except RuntimeError:
            assert case == "boundary-failure"
        finally:
            gate.set()
            if case in ("join-failure", "boundary-failure"):
                pool._thread.join(2)
        report = trial.report
        assert gc.get_freeze_count() == 0 and report["restored"]
        assert (gc.isenabled(), gc.get_threshold(), gc.get_debug(), list(gc.callbacks)) == before
        assert report["cold_collect"]["duration_ns"] >= 0
        assert report["freeze"]["after_count"] > 0 if case != "baseline" else report["freeze"]["after_count"] == 0
        if case in ("join-failure", "boundary-failure"):
            assert report["cleanup_failed"] and not report["producers_exited"]
            assert report["shutdown_collect"] is None
            assert report["cleanup_errors"] == ["RuntimeError", "producer_not_exited"]
        else:
            assert not report["cleanup_failed"] and report["producers_exited"]
            assert old_ref() is None
        assert [s["moment"] for s in report["memory_samples"]] == [
            "before_cold_collect", "after_cold_collect", "after_restore"]
        try:
            with _StartupGCTrial("baseline").installed():
                raise AssertionError("reused process")
        except RuntimeError:
            pass
    ''')
    for case in ("baseline", "freeze", "exception", "join-failure", "boundary-failure", "reject", "init-failure", "hook-init-failure", "s3-hook-init-failure", "s3-scope", "s4-scope", "s4-scope-failure", "memory-end"):
        result = subprocess.run([sys.executable, "-c", program, case], capture_output=True, timeout=20,
                                check=False)
        assert result.returncode == 0, (case, result.stdout, result.stderr)


def _qpc_fake_readable(monkeypatch):
    """无端口旧观察fixture接入正式QPC就绪；不改字节/首错oracle。"""
    from secure_control.execution import localhost_transport as transport

    def ready(read, write, errors, timeout):
        assert len(read) == 1 and not write and not errors and timeout > 0
        assert read[0].gettimeout() == 0
        return read, [], []
    monkeypatch.setattr(transport.select, "select", ready)


def test_timeout_trace_forwards_partial_frames_native_errors_and_never_retries(monkeypatch):
    _qpc_fake_readable(monkeypatch)
    import struct

    from secure_control.execution import localhost_transport as transport
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments.communication_benchmark import _TimeoutDiagnostic

    class Socket:
        def __init__(self, data=b"", error=None):
            self.data, self.error = bytearray(data), error
            self.calls, self.timeouts = [], []
            self.timeout = None

        def getsockname(self):
            return "127.0.0.1", 9000

        def getpeername(self):
            return "127.0.0.1", 101

        def settimeout(self, value):
            self.timeouts.append(value)
            self.timeout = value

        def gettimeout(self):
            return self.timeout

        def send(self, data):
            self.calls.append(("send", bytes(data)))
            if self.error is not None and len(self.calls) == 3:
                raise self.error
            return min(3, len(data))

        def recv(self, size):
            self.calls.append(("recv", size))
            if self.error is not None:
                raise self.error
            value = bytes(self.data[:min(2, size)])
            del self.data[:len(value)]
            return value

    deadline = _CycleDeadline(time.perf_counter_ns() + 10**9)
    observer = _TimeoutDiagnostic("Client", (101, 102, 103))
    observer.select(47)
    fields = observer.FIELDS
    original_send, original_receive = transport._send_exact, transport._receive_exact
    original_encode, original_decode = transport.encode_envelope, transport.decode_envelope
    plain, traced = Socket(), Socket()
    transport._send_exact(plain, b"private-payload-not-in-evidence", deadline)
    with observer.sockets():
        transport._send_exact(traced, b"private-payload-not-in-evidence", deadline)
        assert plain.calls == traced.calls  # 原memoryview cursor/剩余byte切片完全相同。
        assert all(0 < value <= 1 for value in traced.timeouts)
        incoming = Socket(struct.pack("!I", 4) + b"ABCD")
        assert transport.receive_frame(incoming, deadline=deadline, limit=1024) == b"ABCD"
        probe = observer.probes[incoming]
        assert probe.receive_header
        native = [dict(zip(fields, r[2], strict=True)) for r in observer.slots
                  if r and r[0] == "trace" and r[1] == "socket"]
        assert {r["frame_part"] for r in native if r["operation"] == "recv"} == {"header", "body"}
        for record in native:
            assert record["qpc_before_ns"] <= record["qpc_after_ns"]
            if record["operation"] == "settimeout":
                assert record["timeout_s"] == record["actual_timeout_s"]
        failure = TimeoutError("private-native-error-never-export")
        broken = Socket(error=failure)
        with pytest.raises(transport.LocalhostTransportTimeout) as caught:
            transport._send_exact(broken, b"private-0123456789", deadline)
        assert caught.value.__cause__ is failure and len(broken.calls) == 3
        first = dict(zip(fields, observer.first_failure, strict=True))
        outer = dict(zip(fields, observer.outer_failure, strict=True))
        assert first["timeout_origin"] == "socket_send" and first["confirmed_bytes_before"] == 6
        assert first["native_progress_unknown"] and first["end_ns"] < deadline.deadline_ns
        assert outer["error_type"] == "LocalhostTransportTimeout" and outer["cause_type"] == "TimeoutError"
        assert observer.report()["latched"]
    assert (transport._send_exact, transport._receive_exact) == (original_send, original_receive)
    assert (transport.encode_envelope, transport.decode_envelope) == (original_encode, original_decode)
    import json
    encoded = json.dumps(observer.report())
    assert "private-payload" not in encoded and "private-native-error" not in encoded

    early = _TimeoutDiagnostic("Client", (101, 102, 103))
    early.select(47)
    sock = Socket(error=TimeoutError("hidden"))
    with early.sockets(), pytest.raises(transport.LocalhostTransportTimeout):
        transport._receive_exact(sock, 4, deadline)
    assert len(sock.calls) == 1
    assert dict(zip(fields, early.first_failure, strict=True))["timeout_origin"] == "socket_recv"
    expired = _TimeoutDiagnostic("Client", (101, 102, 103))
    expired.select(47)
    sock = Socket()
    with expired.sockets(), pytest.raises(transport.LocalhostTransportTimeout):
        transport._send_exact(sock, b"x", _CycleDeadline(time.perf_counter_ns()-1))
    assert not sock.calls and not sock.timeouts
    assert dict(zip(fields, expired.first_failure, strict=True))["timeout_origin"] == "absolute_precheck"
    disconnected = _TimeoutDiagnostic("Client", (101, 102, 103))
    disconnected.select(47)
    sock = Socket()
    with disconnected.sockets(), pytest.raises(transport.LocalhostTransportDisconnected):
        transport._receive_exact(sock, 4, deadline)
    assert len(sock.calls) == 1


def test_timeout_trace_rings_clock_domains_whitelist_and_first_failure_latch(monkeypatch):
    import json

    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments.communication_benchmark import _TimeoutDiagnostic, _TraceSocket

    observer = _TimeoutDiagnostic("Client", (101, 102, 103))
    observer.select(999)
    observer.wall = lambda: 1000
    monkeypatch.setattr(time, "monotonic_ns", lambda: 10_000_000_000)
    sock = SimpleNamespace(gettimeout=lambda: .5)
    probe = _TraceSocket(sock, observer, "P1")
    probe.deadline, probe.direction, probe.context = 20., "Client->P1", ("public", *["a"*128]*8)
    record = observer.values(probe, "send", 500, 900, requested=10, returned=3)
    data = dict(zip(observer.FIELDS, record, strict=True))
    assert data["deadline_domain"] == "legacy_monotonic" and data["remaining_ns"] == 10_000_000_000
    probe.deadline = _CycleDeadline(5000)
    record = observer.values(probe, "send", 500, 900, requested=10, returned=3)
    assert dict(zip(observer.FIELDS, record, strict=True))["remaining_ns"] == 4000
    for _ in range(1000):
        observer.put("socket", record)
        observer.put("frame", record)
    observer._gc("start", {"generation": 2})
    observer.failed(record)
    for _ in range(1000):
        observer.put("socket", record)  # 模拟停止流量，首错后不覆盖现场。
        observer.marker("runtime_close_end")
    observer._gc("stop", {"generation": 2, "collected": 3, "uncollectable": 0})
    result = observer.report()
    assert observer.slots[288][2] is record and observer.first_failure is record
    assert result["evicted_count"]["socket"] == 872 and result["encoded_omitted"] > 0
    assert len(observer.slots) == 304 and len(result["events"]) <= 512
    assert len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()) == result["encoded_bytes"]
    assert result["encoded_bytes"] <= 72*1024
    assert result == observer.report()
    assert any(r.get("kind") == "gc_interval" and r["collected"] == 3 for r in result["events"])
    observer.remember(SimpleNamespace(sender="Client", recipient="P1", operation="endpoint",
        session_id="public-session", round_id="public-round", step=47, sequence=3,
        resource_id="secret-resource-ignored", payload=SimpleNamespace(operation="stage_batch", secret="hidden")))
    assert all(isinstance(v, tuple) for v in observer.contexts.values())
    public = json.dumps(observer.contexts["Client", "P1"])
    assert "hidden" not in public and "secret-resource" not in public
    # 真实socket可hash；fixture保留相同行为且不打开网络端口。
    class Socket:
        getsockname = staticmethod(lambda: ("127.0.0.1", 9000))
        getpeername = staticmethod(lambda: ("127.0.0.1", 101))
    sockets = [Socket() for _ in range(5)]
    for channel in sockets[:4]:
        assert observer.probe(channel) is observer.probe(channel)
    with pytest.raises(RuntimeError):
        observer.probe(sockets[4])
    assert len(observer.probes) == 4
    probe.requested_timeout = True
    sock.gettimeout = lambda: float("nan")
    invalid = dict(zip(observer.FIELDS, observer.values(probe, "send", 500, 900), strict=True))
    assert invalid["timeout_s"] is None and invalid["actual_timeout_s"] is None
    assert observer.time_fields_unavailable == 2


def test_supply_diagnostic_real_producer_labels_original_owner_and_exception_cleanup(monkeypatch):
    import gc
    from threading import Event, get_native_id

    from test_two_party_protocol import make_stack

    from secure_control.execution.lan_runtime import _OnlineResourcePool
    from secure_control.experiments.communication_benchmark import _Diagnostic, _observe_diagnostic
    from secure_control.protocol.roles import _PreparedResourceOwner

    client, _, _, _, distribution = make_stack()
    diag = _Diagnostic("Client", supply=True)
    ready, release = Event(), Event()
    create, produce = _PreparedResourceOwner.create, _OnlineResourcePool._produce
    before = list(gc.callbacks), gc.isenabled(), gc.get_threshold()

    def gated(owner, step, **kwargs):
        if step == 172:
            diag._gc("start", {"generation": 1})
            ready.set()
            assert release.wait(3)
            diag._gc("stop", {"generation": 1})
        return create(owner, step, **kwargs)

    monkeypatch.setattr(_PreparedResourceOwner, "create", gated)
    with pytest.raises(ValueError, match="private-error"), diag.installed(), _observe_diagnostic(diag):
        pool = _OnlineResourcePool(client, distribution, start=168, slots=4)
        try:
            assert pool.low_water == 3 and not any(diag.slots)
            diag.select(167)
            taken = pool.take(168)
            assert taken._owner is pool.owner and ready.wait(3)
            diag.select(168)
            release.set()
        finally:
            release.set()
            pool.close()
            pool.owner.discard(taken)
        assert not client._issued_rounds
        assert taken.p1_resources.aborted_count == 11
        assert pool.snapshot()["material_reserved_bytes"] <= 8 * 1024 * 1024
        raise ValueError("private-error")
    assert _PreparedResourceOwner.create is gated and _OnlineResourcePool._produce is produce
    assert (list(gc.callbacks), gc.isenabled(), gc.get_threshold()) == before
    report = diag.report()
    assert "private-error" not in str(report)
    tasks = [item for item in report["events"] if item["kind"] == "interval"]
    assert {item["phase"] for item in tasks} == {"material_produce", "material_create"}
    assert all(item["owner"] == "Client producer" and item["prepared_step"] == 172
               and item["control_global_step"] == 167 and item["control_global_step_end"] == 168
               and item["native_thread_id"] != get_native_id() for item in tasks)
    collection = next(item for item in report["events"] if item["kind"] == "gc_interval"
                      and item["generation"] == 1)
    assert collection["pairing"] == "complete" and collection["owner"] == "Client producer"
    assert collection["prepared_step"] == 172 and collection["control_global_step_end"] == 168
    diag.select(179)
    with diag.scope("control_cycle"):
        pass
    control = next(item for item in diag.report()["events"] if item.get("phase") == "control_cycle")
    assert control["owner"] == "Client control"


@pytest.mark.parametrize("role", ("P1", "P2"))
@pytest.mark.parametrize("boundaries_enabled,trace_enabled", ((False, False), (True, False),
                                                          (False, True), (True, True)))
def test_party_receive_observers_delegate_once_and_restore(monkeypatch, role, boundaries_enabled,
                                                          trace_enabled):
    """组合观察必须单向委托；只替换原接收，不启动网络/协议/控制或供料。"""
    import gc
    from contextlib import ExitStack

    from secure_control.execution import lan_runtime, lan_scalar_runtime, localhost_transport
    from secure_control.experiments import communication_benchmark as bench

    requests = [SimpleNamespace(sender="Client", operation=operation, step=step,
                                payload=SimpleNamespace(action="stop"))
                for operation, step in (("lan_hello", None), ("online", 0),
                                        ("online", 1), ("segment_end", 2))]
    calls, snapshots = [], []
    channel, deadline = object(), object()
    original_error = LocalhostTransportProtocolError("private-receive-failure")

    def receive(sock, *, deadline, limit):
        calls.append((sock, deadline, limit))
        if len(calls) > len(requests):
            raise original_error
        return requests[len(calls) - 1]

    def stats():
        value = [{"collections": len(snapshots) + 1, "collected": 0, "uncollectable": 0}]
        snapshots.append(value)
        return value

    monkeypatch.setattr(lan_runtime, "receive_envelope", receive)
    monkeypatch.setattr(gc, "get_stats", stats)
    hooks = ((lan_runtime, "receive_envelope"), (lan_runtime, "_party_reply"),
             (localhost_transport, "_send_exact"), (localhost_transport, "_receive_exact"),
             (localhost_transport, "encode_envelope"), (localhost_transport, "decode_envelope"),
             (lan_scalar_runtime, "encode_scalar_frame_v3"),
             (lan_scalar_runtime, "decode_scalar_frame_v3"))
    before = tuple(getattr(owner, name) for owner, name in hooks)
    gc_before = list(gc.callbacks), gc.isenabled(), gc.get_threshold()
    boundaries = {} if boundaries_enabled else None
    observer = bench._TimeoutDiagnostic(role, (101, 102, 103)) if trace_enabled else None
    with ExitStack() as owned:
        if observer:
            owned.enter_context(observer.installed())
            owned.enter_context(observer.sockets())
        _, _, restore = bench._meter(role, (101, 102, 103), 0, diagnostic=observer,
                                    gc_boundaries=boundaries)
        owned.callback(restore)
        for index, request in enumerate(requests, 1):
            assert lan_runtime.receive_envelope(channel, deadline=deadline, limit=1024) is request
            assert len(calls) == index
        with pytest.raises(LocalhostTransportProtocolError) as caught:
            lan_runtime.receive_envelope(channel, deadline=deadline, limit=1024)
        assert caught.value is original_error
        assert calls == [(channel, deadline, 1024)] * 5
        assert len(snapshots) == (2 if boundaries_enabled else 0)
        if boundaries_enabled:
            assert set(boundaries) == {"begin", "end"}
            assert boundaries["begin"]["stats"] is snapshots[0]
            assert boundaries["end"]["stats"] is snapshots[1]
            assert all(value["enabled"] == gc_before[1] and
                       tuple(value["threshold"]) == gc_before[2] for value in boundaries.values())
    assert tuple(getattr(owner, name) for owner, name in hooks) == before
    assert (list(gc.callbacks), gc.isenabled(), gc.get_threshold()) == gc_before
    if observer:
        report = observer.report()
        received = [event for event in report["events"] if event.get("phase") == "receive_request"]
        assert sorted(event["control_global_step"] for event in received) == [0, 1, 2]
        assert all(event["status"] == "complete" for event in received)
        assert report["callback_restored"] and report["socket_hooks_restored"]
        assert report["encoded_bytes"] <= report["encoded_limit"] == 72 * 1024
        assert "private-receive" not in str(report)


@pytest.mark.parametrize("role", ("P1", "P2"))
def test_s6_party_job_composes_receive_observers_and_preserves_original_failure(monkeypatch, role):
    """实际party入口采用软件业务替身，验证组合可达、公开错误与恢复，不做测量。"""
    import gc

    from secure_control.execution import lan_runtime, localhost_transport
    from secure_control.experiments import communication_benchmark as bench

    def check(failure_index):
        with monkeypatch.context() as patcher:
            calls, outcomes = [], []
            requests = [SimpleNamespace(sender="Client", operation=operation, step=step,
                                        payload=SimpleNamespace(action="stop"))
                        for operation, step in (("lan_hello", None), ("online", 0),
                                                ("segment_end", 1))]
            original_error = LocalhostTransportProtocolError("private-party-receive")

            def receive(*args, **kwargs):
                calls.append((args, kwargs))
                if failure_index is not None and len(calls) == failure_index + 1:
                    raise original_error
                return requests[len(calls) - 1]

            def party(config, *, batch):
                assert config.role == role and batch
                for request in requests:
                    assert lan_runtime.receive_envelope(None, deadline=123, limit=1024) is request
                return {"status": "closed", "material_summary": None}

            patcher.setattr(lan_runtime, "receive_envelope", receive)
            patcher.setattr(bench, "run_party_single_step", party)
            patcher.setattr(bench, "_process_memory", lambda: {"scope": "software fixture"})
            hooks = ((lan_runtime, "receive_envelope"), (lan_runtime, "_party_reply"),
                     (lan_runtime.LanSegmentedRuntime, "close"),
                     (localhost_transport, "_send_exact"), (localhost_transport, "_receive_exact"),
                     (localhost_transport, "encode_envelope"), (localhost_transport, "decode_envelope"))
            before = tuple(getattr(owner, name) for owner, name in hooks)
            gc_before = list(gc.callbacks), gc.isenabled(), gc.get_threshold()
            bench._party_job(bench._config(role, (101, 102, 103)), (101, 102, 103), 0, True,
                             SimpleNamespace(put=outcomes.append), diagnostic_enabled=True,
                             supply_diagnostic=True, timeout_trace=True, material_comparison=True)
            assert len(outcomes) == 1
            assert len(calls) == (3 if failure_index is None else failure_index + 1)
            outcome = outcomes[0]
            assert outcome["role"] == role
            assert outcome["status"] == ("closed" if failure_index is None else "failed")
            assert outcome.get("error_type") == (None if failure_index is None else
                                                  "LocalhostTransportProtocolError")
            assert set(outcome["gc_boundaries"]) == (set() if failure_index == 0 else {"begin", "end"})
            assert tuple(getattr(owner, name) for owner, name in hooks) == before
            assert (list(gc.callbacks), gc.isenabled(), gc.get_threshold()) == gc_before
            diagnostic = outcome["diagnostic"]
            assert diagnostic["callback_restored"] and diagnostic["socket_hooks_restored"]
            assert diagnostic["gc_before"] == diagnostic["gc_after"]
            received = [event for event in diagnostic["events"] if event.get("phase") == "receive_request"]
            expected_steps = {None: [0, 1], 0: [], 2: [0]}[failure_index]
            assert sorted(event["control_global_step"] for event in received) == expected_steps
            assert "private-party" not in str(outcome)

    for failure_index in (None, 0, 2):
        check(failure_index)


def test_supply_diagnostic_canonical_send_encode_public_metadata_and_cleanup(monkeypatch):
    import json

    from secure_control.execution import localhost_transport
    from secure_control.experiments.communication_benchmark import _Diagnostic, _meter

    calls = []
    def sending(sock, payload, deadline):
        calls.append((sock, payload, deadline))
        raise TimeoutError("private-socket-message")

    monkeypatch.setattr(localhost_transport, "_send_exact", sending)
    original_encode = localhost_transport.encode_envelope
    diag = _Diagnostic("Client", supply=True)
    diag.select(179)
    counts, activity, restore = _meter("Client", (101, 102, 103), 0, diagnostic=diag)
    try:
        frame = WireEnvelope(SCHEMA_VERSION, "shutdown", "Client", "P1", 1, "shutdown",
                             "private-session", None, None, None, None)
        encoded = localhost_transport.encode_envelope(frame)
        sock = SimpleNamespace(getsockname=lambda: ("localhost", 104),
                               getpeername=lambda: ("localhost", 101))
        with pytest.raises(TimeoutError, match="private-socket"):
            localhost_transport._send_exact(sock, encoded, 123)
    finally:
        restore()
    assert calls == [(sock, encoded, 123)]
    assert localhost_transport._send_exact is sending
    assert localhost_transport.encode_envelope is original_encode
    assert activity["send_ms"] >= 0 and counts["Client->P1"]["frames"] == 1
    events = diag.report()["events"]
    assert len(events) == 2 and {item["phase"] for item in events} == {"encode_ms", "send_ms"}
    assert all(item["direction"] == "Client->P1" and item["public_bytes"] == len(encoded)
               and item["control_global_step"] == 179 for item in events)
    assert next(item for item in events if item["phase"] == "send_ms")["status"] == "TimeoutError"
    assert "private-" not in json.dumps(events) and getattr(diag.state, "phase", None) is None


@pytest.mark.integration
def test_supply_diagnostic_mode_keeps_failed_cycle_and_restores_all_hooks(monkeypatch):
    import gc
    import json

    from secure_control.execution import lan_runtime, localhost_transport
    from secure_control.experiments.communication_benchmark import run_continuous_observation
    from secure_control.protocol import Client
    from secure_control.protocol.roles import _PreparedResourceOwner

    before = (list(gc.callbacks), gc.isenabled(), gc.get_threshold(),
              lan_runtime._OnlineResourcePool._produce, _PreparedResourceOwner.create,
              localhost_transport._send_exact, localhost_transport.encode_envelope)
    def failed(*args, **kwargs):
        raise ValueError("private-supply-input")

    monkeypatch.setattr(Client, "bind_online_input", failed)
    report = run_continuous_observation(steps=1, delay_ms=0, segment_steps=400,
                                       optimized=True, diagnostic=True, recording_mode="light")
    assert not report["qualification_pass"] and report["successful_steps"] == 0
    assert report["cycles"][0]["device_completed_ns"] is None
    assert report["cycles"][0]["cycle_completed_ns"] is None
    assert (list(gc.callbacks), gc.isenabled(), gc.get_threshold(),
            lan_runtime._OnlineResourcePool._produce, _PreparedResourceOwner.create,
            localhost_transport._send_exact, localhost_transport.encode_envelope) == before
    diag = report["diagnostic_report"]
    assert diag["supply_diagnostic"] and "176..180" in diag["selected_global_steps"]
    assert len(json.dumps(diag, separators=(",", ":"), ensure_ascii=False).encode()) == diag["encoded_bytes"]
    assert diag["encoded_bytes"] <= diag["encoded_limit"] == 256 * 1024
    assert all(role["event_limit"] == 512 and role["encoded_events_limit"] == 72 * 1024
               and role["callback_restored"] and role["gc_before"] == role["gc_after"]
               for role in diag["roles"])
    control = next(item for item in diag["roles"][0]["events"] if item["phase"] == "control_cycle")
    assert control["status"] == report["cycles"][0]["status"]
    assert "private-supply" not in json.dumps(report)


def test_swing_up_has_38_products_in_16_public_layers():
    from test_lan_scalar_v3 import _inputs

    _, _, _, _, program, _ = _inputs()
    plan = build_scalar_layer_plan(program)
    assert tuple(len(layer) for layer in plan.layers) == (
        5, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 4, 2, 1, 1,
    )
    assert {name for layer in plan.layers for name in layer} == {
        gate.name for gate in program.gates if gate.operation == "multiply"
    }


def test_dynamic_batch_codec_requires_whole_identity_shape_and_direction():
    payload = Protocol3BatchPayload(
        "product", "a" * 64, None, "session", None, 0,
        ("one", "two"),
        (ProductMaskPayload(AdditiveShare(1), AdditiveShare(2), 0),
         ProductMaskPayload(AdditiveShare(3), AdditiveShare(4), 0)),
    )
    frame = WireEnvelope(
        SCHEMA_VERSION, "request", "P1", "P2", 1,
        "peer_batch", "session", "round", 0, None, payload,
    )
    assert decode_envelope(encode_envelope(frame)) == frame
    with pytest.raises(ValueError, match="shape"):
        Protocol3BatchPayload("product", "a" * 64, None, "session", None, 0,
                              ("one", "two"), payload.products[:1])
    with pytest.raises(LocalhostCodecError, match="方向"):
        WireEnvelope(
            SCHEMA_VERSION, "request", "P1", "P2", 2, "peer_batch",
            "session", "round", 0, None,
            Protocol3BatchPayload("truncation", "a" * 64, None, "session", None,
                                  2, (), truncations=()),
        )


@pytest.mark.integration
def test_default_lan_party_rejects_unnegotiated_legacy_hello(monkeypatch):
    from secure_control.execution import lan_runtime

    accepted, remote = socket.socketpair()
    monkeypatch.setattr(lan_runtime, "accept_role", lambda *_args: accepted)
    monkeypatch.setattr(
        lan_runtime, "_accept_hello",
        lambda *_args: ("session", LanHelloPayload("a" * 64, "b" * 64)),
    )
    try:
        with pytest.raises(ValueError, match="批量能力不一致"):
            lan_runtime._run_party_session(
                SimpleNamespace(role="P1", startup_timeout=1), None, None, None,
                expected_batch=True,
            )
        assert accepted.fileno() == -1
    finally:
        remote.close()


@pytest.mark.parametrize("mismatch", ["round", "plan", "sequence"])
@pytest.mark.integration
def test_dynamic_peer_rejects_incomplete_or_cross_round_batch(mismatch):
    from test_two_party_protocol import make_stack

    client, _, _, _, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(21))
    plan = online.p1_resources.plan
    ids = tuple(item.resource_id for item in plan.product_resources)
    products = tuple(ProductMaskPayload(AdditiveShare(0), AdditiveShare(0), 1)
                     for _ in ids)
    fields = {
        "phase": "product", "plan_sha256": public_step_plan_sha256(plan),
        "run_id": "run", "epoch_id": "epoch", "physical_step": 7,
        "batch_index": 0, "resource_ids": ids, "products": products,
    }
    if mismatch == "epoch":
        fields["epoch_id"] = "previous-epoch"
    elif mismatch == "plan":
        fields["plan_sha256"] = "a" * 64
    elif mismatch == "ids":
        fields["resource_ids"] = (*ids[:-1], "wrong-id")
    elif mismatch == "phase":
        fields.update(phase="product_complete", batch_index=1, products=())
    payload = Protocol3BatchPayload(**fields)
    sockets = socket.socketpair()
    receiver = LocalhostProtocol3PeerPort(
        sockets[0], "P1", 8 * 1024 * 1024, 5, batch_enabled=True,
    )
    receiver.bind(plan.session_id)
    receiver.set_batch_round(plan, modulus=client.fixed_point.modulus,
                             run_id="run", epoch_id="epoch", physical_step=7)
    frame = WireEnvelope(
        SCHEMA_VERSION, "request", "P2", "P1", 2 if mismatch == "sequence" else 1,
        "peer_batch", plan.session_id,
        "wrong-round" if mismatch == "round" else plan.round_id,
        plan.step, None, payload,
    )
    try:
        send_envelope(sockets[1], frame, deadline=time.monotonic() + 5,
                      limit=8 * 1024 * 1024)
        with pytest.raises(ValueError, match="身份不匹配"):
            receiver._receive_batch(plan, "product", ids)
    finally:
        receiver.close()
        sockets[1].close()


@pytest.mark.integration
def test_dynamic_peer_rejects_noncanonical_member_and_duplicate_resource_id():
    from test_two_party_protocol import make_stack

    client, _, _, _, distribution = make_stack()
    plan = client.prepare_online(distribution, [0.25], step=0).p1_resources.plan
    ids = tuple(item.resource_id for item in plan.product_resources)
    with pytest.raises(ValueError, match="身份不合法"):
        Protocol3BatchPayload("product", "a" * 64, None, "epoch", None, 0,
                              (ids[0], ids[0]),
                              (ProductMaskPayload(AdditiveShare(0), AdditiveShare(0), 1),) * 2)
    sockets = socket.socketpair()
    peer = LocalhostProtocol3PeerPort(sockets[0], "P1", 8 * 1024 * 1024, 5,
                                      batch_enabled=True)
    peer.bind(plan.session_id)
    peer.set_batch_round(plan, modulus=client.fixed_point.modulus)
    try:
        with pytest.raises(ValueError, match="canonical residue"):
            peer._check_batch_values(
                tuple(ProductMaskPayload(AdditiveShare(0),
                                         AdditiveShare(client.fixed_point.modulus), 1)
                      for _ in ids), len(ids), "product", sender="P2",
            )
    finally:
        peer.close()
        sockets[1].close()


@pytest.mark.integration
def test_dynamic_batch_frame_budget_rejects_before_any_bytes_are_sent():
    from test_two_party_protocol import make_stack

    client, _, _, _, distribution = make_stack()
    plan = client.prepare_online(distribution, [0.25], step=0).p1_resources.plan
    ids = tuple(item.resource_id for item in plan.product_resources)
    payload = Protocol3BatchPayload(
        "product", public_step_plan_sha256(plan), None, plan.session_id, None, 0, ids,
        tuple(ProductMaskPayload(AdditiveShare(0), AdditiveShare(0), 0) for _ in ids),
    )
    frame = WireEnvelope(SCHEMA_VERSION, "request", "P1", "P2", 1, "peer_batch",
                         plan.session_id, plan.round_id, plan.step, None, payload)
    sockets = socket.socketpair()
    try:
        with pytest.raises(LocalhostTransportProtocolError, match="上限"):
            send_envelope(sockets[0], frame, deadline=time.monotonic() + 2, limit=128)
        sockets[1].setblocking(False)
        with pytest.raises(BlockingIOError):
            sockets[1].recv(1)
    finally:
        for sock in sockets:
            sock.close()


@pytest.mark.integration
@pytest.mark.stress
def test_large_legal_peer_batch_with_small_socket_buffers_does_not_deadlock():
    from test_two_party_protocol import make_stack

    client, _, _, _, distribution = make_stack()
    original = client.prepare_online(distribution, [0.25], step=0).p1_resources.plan
    plan = replace(original, product_resources=tuple(
        replace(original.product_resources[0], resource_id=f"large-{index}")
        for index in range(4096)
    ))
    sockets = socket.socketpair()
    for sock in sockets:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    peers = [LocalhostProtocol3PeerPort(
        sock, "P1" if index == 0 else "P2", 8 * 1024 * 1024, 10,
        batch_enabled=True,
    ) for index, sock in enumerate(sockets)]
    for peer in peers:
        peer.bind(plan.session_id)
        peer.set_batch_round(plan, modulus=client.fixed_point.modulus)
    outputs = [None, None]
    errors = []

    def run(index):
        masks = tuple(ProductMaskPayload(
            AdditiveShare(client.fixed_point.modulus - 1), AdditiveShare(0), index,
        ) for _ in plan.product_resources)
        try:
            outputs[index] = peers[index].exchange_products(plan, masks)
        except Exception as error:  # noqa: BLE001 - 跨线程断言实际异常
            errors.append(error)

    threads = [Thread(target=run, args=(index,)) for index in (0, 1)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        assert not any(thread.is_alive() for thread in threads)
        assert not errors, errors
        assert all(len(output) == 4096 for output in outputs)
        assert outputs[0][0].party == 1 and outputs[1][0].party == 0
    finally:
        for peer in peers:
            peer.close()


@pytest.mark.parametrize("strategy,fault", (("peer_barriers", "bad_last_member"),
    ("peer_barriers", "lost_product_barrier"), ("client_authorized", "bad_last_member"),
    ("client_authorized", "lost_truncation")))
def test_dynamic_batch_fault_burns_all_resources_without_stage_or_state_change(strategy, fault):
    from test_two_party_protocol import make_stack

    client, _, _, _, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(22))
    role = P1(rehydrate_offline_material(
        PartyOfflineMaterial.from_message(distribution.p1), distribution.range_contract,
    ))
    local = rehydrate_online_material(
        PartyOnlineMaterial.from_round(PartyOnlineRound(
            online.p1_input, online.p1_resources,
        )), modulus=client.fixed_point.modulus, security_parameter=8,
    )
    shares = []
    endpoint = LocalProtocol3PartyEndpoint(role, local, shares.append, completion_strategy=strategy)
    prior_state = role.state_share

    class FaultPeer:
        def exchange_products(self, plan, masks):
            result = [ProductMaskPayload(AdditiveShare(0), AdditiveShare(0), 1)
                      for _ in masks]
            if fault == "bad_last_member":
                result[-1] = ProductMaskPayload(AdditiveShare(0), AdditiveShare(0), 0)
            return tuple(result)

        def product_complete(self, plan):
            raise TimeoutError("lost product barrier")

        def receive_truncations(self, plan):
            raise TimeoutError("lost truncation")

    with pytest.raises((ValueError, TimeoutError)):
        stage_protocol3_batch(endpoint, FaultPeer())
    assert not shares
    assert role.state_share == prior_state
    assert local.resources.consumed_count == 0
    assert local.resources.aborted_count == (online.p1_resources.plan.triple_count +
                                             online.p1_resources.plan.truncation_count)
    with pytest.raises(ValueError, match="重复开始"):
        stage_protocol3_batch(endpoint, FaultPeer())


@pytest.mark.integration
def test_scalar_layer_rejects_wrong_phase_and_noncanonical_member():
    from secure_control.execution.lan_scalar_runtime import _SocketScalarPeer

    sockets = socket.socketpair()
    peer = _SocketScalarPeer(
        sockets[0], party=0, run_id="run", epoch_id="epoch", session_id="session",
        physical_step=7, local_step=0, round_id="round",
        deadline=time.monotonic() + 5, program_sha256="a" * 64, modulus=101,
    )
    try:
        for phase, values in (("complete", ()), ("product", ((101, 0),))):
            payload = ScalarLayerPayloadV1(phase, "a" * 64, 0, ("resource",), values)
            frame = ScalarFrameV3(
                "P2", "P1", "run", "epoch", "session", 7, 0,
                "round", "layer:0", "peer_layer", payload,
            )
            send_frame(sockets[1], encode_scalar_frame_v3(frame),
                       deadline=time.monotonic() + 5, limit=8 * 1024 * 1024)
            with pytest.raises(ValueError, match="无效"):
                peer._receive_layer("product", 0, ("resource",))
    finally:
        sockets[0].close()
        sockets[1].close()


@pytest.mark.integration
def test_dynamic_batch_real_peer_frames_preserve_old_state_output_and_modular_state(
    monkeypatch,
):
    from test_two_party_protocol import make_stack

    from secure_control.execution import _localhost_peer

    client, _, _, _, distribution = make_stack()
    online = client.prepare_online(distribution, [0.25], step=0, rng=random.Random(20))
    plan = online.p1_resources.plan
    p1, p2 = (
        role_type(rehydrate_offline_material(
            PartyOfflineMaterial.from_message(material), distribution.range_contract,
        ))
        for role_type, material in ((P1, distribution.p1), (P2, distribution.p2))
    )
    rounds = tuple(rehydrate_online_material(
        PartyOnlineMaterial.from_round(PartyOnlineRound(input_share, resources)),
        modulus=client.fixed_point.modulus, security_parameter=8,
    ) for input_share, resources in (
        (online.p1_input, online.p1_resources),
        (online.p2_input, online.p2_resources),
    ))
    shares = [[], []]
    endpoints = (
        LocalProtocol3PartyEndpoint(
            p1, rounds[0], shares[0].append,
        ),
        LocalProtocol3PartyEndpoint(
            p2, rounds[1], shares[1].append,
        ),
    )
    sockets = socket.socketpair()
    peers = [LocalhostProtocol3PeerPort(
        sockets[party], "P1" if party == 0 else "P2", 8 * 1024 * 1024, 10,
        batch_enabled=True,
    ) for party in (0, 1)]
    for peer in peers:
        peer.bind(plan.session_id)
        peer.set_batch_round(plan, modulus=client.fixed_point.modulus)
    frames = []
    original = _localhost_peer.send_envelope

    def counted(*args, **kwargs):
        frames.append(args[1].operation)
        return original(*args, **kwargs)

    monkeypatch.setattr(_localhost_peer, "send_envelope", counted)
    receipts = [None, None]
    errors = []

    def run(party):
        try:
            receipts[party] = stage_protocol3_batch(endpoints[party], peers[party])
        except Exception as error:  # noqa: BLE001 - 将线程异常交还断言
            errors.append(error)

    threads = [Thread(target=run, args=(party,)) for party in (0, 1)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            assert not thread.is_alive()
        assert not errors, errors
        assert frames == ["peer_batch"] * 7
        assert [(item.products, item.truncations) for item in receipts] == [(9, 2)] * 2
        assert client.reconstruct_control(shares[0][0], shares[1][0]).tolist() == [0.625]
        Protocol3Orchestrator().commit(*endpoints)
        reconstructed = client.fixed_point.decode_residue(
            client.sharing.reconstruct(p1.state_share, p2.state_share)
        )
        assert reconstructed.tolist() == [0.3125, -0.0625]
    finally:
        for peer in peers:
            peer.close()


def test_scalar_batch_matches_legacy_integer_shares_with_same_isolated_materials():
    from test_lan_scalar_v3 import _inputs

    _, _, modulus, evidence, program, certificate = _inputs()
    materials = prepare_scalar_round(
        program, {"p": .2, "v": -.4, "beta": .31, "omega": 1.7},
        certificate, modulus=modulus, modulus_evidence=evidence,
        round_id="batch-math-oracle", step=0,
    )
    public = ScalarProgram(
        program.inputs, tuple((name, Fraction(0)) for name, _ in program.constants),
        program.gates, program.output,
    )

    def execute(*, batch: bool):
        channels = (Queue(), Queue())
        events = []

        class Peer:
            def __init__(self, party):
                self.party = party

            def send(self, phase, index, ids, values=()):
                events.append((self.party, phase))
                channels[1 - self.party].put((phase, index, ids, values))

            def receive(self, phase, index, ids):
                actual = channels[self.party].get(timeout=10)
                assert actual[:3] == (phase, index, ids)
                return actual[3]

            def exchange_layer_products(self, index, ids, values):
                if self.party == 0:
                    self.send("product", index, ids, values)
                    return self.receive("product", index, ids)
                incoming = self.receive("product", index, ids)
                self.send("product", index, ids, values)
                return incoming

            def send_layer_truncations(self, index, ids, values):
                self.send("truncation", index, ids, values)

            def receive_layer_truncations(self, index, ids):
                return self.receive("truncation", index, ids)

            def complete_layer(self, index, ids):
                if self.party == 0:
                    self.send("complete", index, ids)
                    self.receive("complete", index, ids)
                else:
                    self.receive("complete", index, ids)
                    self.send("complete", index, ids)

            def exchange_product(self, resource, d, e):
                self.send("product", 0, (resource,), (d, e))
                return self.receive("product", 0, (resource,))

            def send_truncation(self, resource, value):
                self.send("truncation", 0, (resource,), value)

            def receive_truncation(self, resource):
                return self.receive("truncation", 0, (resource,))

            def complete_gate(self, resource):
                self.send("complete", 0, (resource,))
                self.receive("complete", 0, (resource,))

        executors = [ScalarPartyExecutor(
            public, materials[party], modulus=modulus, fractional_bits=80,
            security_parameter=80, modulus_evidence=evidence,
        ) for party in (0, 1)]
        outputs = [None, None]
        errors = []

        def run(party):
            try:
                executor = executors[party]
                peer = Peer(party)
                outputs[party] = (executor.evaluate_batch(peer) if batch
                                  else executor.evaluate(peer))
            except Exception as error:  # noqa: BLE001 - 将并发异常交给主线程断言
                errors.append(error)

        threads = [Thread(target=run, args=(party,)) for party in (0, 1)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            assert not thread.is_alive()
        assert not errors, errors
        assert [item.consumed for item in executors] == [38, 38]
        return outputs, events

    legacy, legacy_frames = execute(batch=False)
    batched, batch_frames = execute(batch=True)
    assert batched == legacy
    assert len(legacy_frames) == 190
    assert len(batch_frames) == 80


@pytest.mark.parametrize(
    ("case", "mode", "client_groups", "peer_frames"),
    [("dynamic", "batch", 6, 7), ("scalar", "batch", 6, 80)],
)
@pytest.mark.integration
@pytest.mark.stress
def test_real_three_process_benchmark_counts_public_frames(
    case, mode, client_groups, peer_frames,
):
    from secure_control.experiments.communication_benchmark import run_local_benchmark

    report = run_local_benchmark(case, mode, steps=2, delay_ms=0)
    assert report["successful_steps"] == 2
    assert report["client_request_reply_groups_per_step"] == client_groups
    assert report["peer_frames_per_step"] == peer_frames
    assert report["client_phase_p50_ms"]["stage_ms"] > 0
    assert report["client_step_activity_p50_ms"]["receive_ms"] > 0


def test_full_observation_bounds_public_rows_and_restores_wrappers():
    from secure_control.experiments.communication_benchmark import _FullObservation
    from secure_control.scenarios.cart_pole import secure_full_experiment as full

    observer = _FullObservation(2, {}, {})
    original = full.CausalVelocityEstimator.observe
    with pytest.raises(OSError), observer.installed():
        observer.begin()
        observer.current["control_started"] = True
        observer.current["protocol_completed"] = True
        observer.current["device_confirmed"] = True
        observer.components["large_ms"] = 1
        for _ in range(300):
            observer.event("scalar_epoch_setup", 1, 2, "complete")
        observer.finish("failed")
        raise OSError("secret sentinel must never be part of evidence")
    assert full.CausalVelocityEstimator.observe is original
    assert len(observer.events) == 256 and observer.event_overflow == 44
    assert observer.rows[0]["duration_ms"] is None
    assert observer.rows[0]["device_confirmed"]  # 失败不能抹掉已经确认的设备事实。
    assert observer.encoded_charge < 4096
    observer.begin()
    observer.confirmed()
    assert observer.rows[-1]["duration_ms"] is not None


@pytest.mark.integration
def test_full_observation_real_switch_failure_keeps_attempt_and_public_whitelist(monkeypatch):
    import json

    from secure_control.experiments.communication_benchmark import run_full_observation
    from secure_control.scenarios.cart_pole import swing_up

    load = swing_up.load_cart_pole_swing_up_config
    from secure_control.execution.lan_scalar_runtime import LanScalarRuntime

    original = LanScalarRuntime.step
    monkeypatch.setattr(swing_up, "load_cart_pole_swing_up_config", lambda *a, **k:
                        replace(load(*a, **k), horizon_steps=20, acquisition_deadline_steps=20))

    def fail(runtime, values, physical_step):
        if physical_step == 11:
            raise OSError("secret sentinel")
        return original(runtime, values, physical_step)

    monkeypatch.setattr(LanScalarRuntime, "step", fail)
    report = run_full_observation(steps=20, delay_ms=0, segment_steps=2)
    assert report["successful_steps"] == 11
    assert report["failed_attempts"] == 1
    assert report["steps"][-1]["status"] == "failed"
    assert report["steps"][-1]["duration_ms"] is None
    assert report["steps"][-1]["phase"] == "energy"
    assert report["steps"][0]["measurement_read"]["end_ns"] < report["steps"][0]["consumption_start_ns"]
    assert report["qualification_pass"] is False and report["absolute_scheduling"] is False
    assert any(e["phase"] == "scalar_epoch_setup" and e["physical_step"] == 10 for e in report["events"])
    assert LanScalarRuntime.step is fail
    assert "secret sentinel" not in json.dumps(report)
    assert "raw_force" not in json.dumps(report) and "output_share" not in json.dumps(report)
    with pytest.raises(ValueError):
        run_full_observation(steps=10000, delay_ms=0)

def test_s10_guard_is_independent_and_rejects_before_resources(monkeypatch):
    import gc

    from secure_control.experiments import communication_benchmark as bench

    def forbidden(*args, **kwargs):
        pytest.fail("S10非法组合不能创建端口、材料或工人")
    monkeypatch.setattr(bench, "_ports", forbidden)
    options = {"steps": 4000, "delay_ms": 0, "segment_steps": 400, "optimized": True,
               "recording_mode": "light", "worker_wait_diagnostic": True}
    for change in ({"worker_wait_diagnostic": 1}, {"steps": 3999}, {"steps": 4001}, {"steps": True},
                   {"segment_steps": 400.0}, {"material_slots": 16.0}, {"preload_steps": False},
                   {"delay_ms": False}, {"delay_ms": 1}, {"preload_steps": 1}, {"preload_execution": "staged"},
                   {"optimized": 1}, {"recording_mode": "full"}, {"diagnostic": True},
                   {"worker_long_run": True}, {"worker_long_run": 0}, {"worker_timeout_diagnostic": True},
                   {"worker_timeout_diagnostic": 0}, {"material_candidate": "worker"},
                   {"gc_trial_policy": "baseline"}, {"timeout_trace": True}, {"timeout_trace": 0},
                   {"role_config": "unused"}, {"tcp_nodelay": False}, {"commit_policy": "serial"}):
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**(options | change))
    for name, value in (("isenabled", False), ("get_threshold", (701, 10, 10)),
                        ("get_freeze_count", 1), ("get_debug", 1), ("callbacks", [object()])):
        with monkeypatch.context() as context:
            context.setattr(gc, name, value if name == "callbacks" else lambda value=value: value)
            with pytest.raises(ValueError):
                bench.run_continuous_observation(**options)
    calls = []
    monkeypatch.setattr(bench, "_run_material_comparison", lambda opts, candidate, **kw:
                        calls.append((opts, candidate, kw)) or {"status": "software-only"})
    assert bench.run_continuous_observation(**options)["status"] == "software-only"
    assert calls[0][1:] == ("worker", {"target_steps": 4000})
    assert calls[0][0]["diagnostic"] and calls[0][0]["timeout_trace"]
    # 两个开关任意排列都必须拒绝，不以先到的旧入口掩盖新选择。
    for selector, steps in (("worker_long_run", 10000), ("worker_timeout_diagnostic", 20),
                            ("material_candidate", 1000)):
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**(options | {selector: "worker" if selector == "material_candidate" else True,
                                                           "steps": steps}))


class _S10Socket:
    """无端口替身；分片及故障仍穿过canonical framing，不执行控制轮。"""
    def __init__(self, data=b"", fail_at=None):
        self.data, self.fail_at = bytearray(data), fail_at
        self.calls, self.timeout = [], None
        self.failure = TimeoutError("private socket text")

    def getsockname(self):
        return "127.0.0.1", 9000

    def getpeername(self):
        return "127.0.0.1", 102

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value

    def recv(self, length):
        self.calls.append(("recv", length))
        if len(self.calls) == self.fail_at:
            raise self.failure
        size = min(2, length, len(self.data))
        value = bytes(self.data[:size])
        del self.data[:size]
        return value

    def send(self, data):
        self.calls.append(("send", len(data)))
        if len(self.calls) == self.fail_at:
            raise self.failure
        return min(2, len(data))


@pytest.mark.parametrize("wait_profile", (False, True))
def test_rv004_recoverable_qpc_receive_keeps_legacy_diagnostics_live(monkeypatch, wait_profile):
    """真实canonical/旧观察器配合；假字节/就绪，不打开网络或运行控制。"""
    import ssl

    from secure_control.execution import localhost_transport as transport
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments.communication_benchmark import _TimeoutDiagnostic

    monkeypatch.setattr(transport.select, "select", lambda read, write, errors, timeout: (read, write, []))
    for transient in (BlockingIOError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
        for ending in ("success", "timeout", "disconnect", "eof"):
            observer = _TimeoutDiagnostic("Client", (101, 102, 103), wait_profile=wait_profile)
            observer.select(0)
            channel = _S10Socket()
            channel.timeout = .5
            terminal = TimeoutError("terminal") if ending == "timeout" else OSError(9, "terminal")
            chunks = [b"ab", transient(), b"cd" if ending == "success" else b"" if ending == "eof" else terminal]
            if transient is not BlockingIOError:
                channel.pending = lambda: 0
            def receive(length, channel=channel, chunks=chunks):
                channel.calls.append(("recv", length))
                item = chunks.pop(0)
                if isinstance(item, BaseException):
                    raise item
                assert len(item) <= length
                return item
            channel.recv = receive
            with observer.sockets():
                deadline = _CycleDeadline(time.perf_counter_ns()+10**9)
                if ending == "success":
                    assert transport._receive_exact(channel, 4, deadline) == b"abcd"
                    assert observer.first_failure is observer.first_failure_entry is None
                    assert not observer.latched and observer.outer_failure is None
                    # 原生瞬态仍在有界环中；恢复后普通I/O和新GC区间继续记录。
                    socket_count, gc_count = observer.seen["socket"], observer.seen["gc"]
                    chunks.append(b"efgh")
                    assert transport._receive_exact(channel, 4, deadline) == b"efgh"
                    observer._supply_gc("start", 2)
                    observer._supply_gc("stop", 2, 0, 0)
                    assert observer.seen["socket"] > socket_count and observer.seen["gc"] == gc_count+1
                else:
                    error_type = transport.LocalhostTransportTimeout if ending == "timeout" else transport.LocalhostTransportDisconnected
                    with pytest.raises(error_type) as caught:
                        transport._receive_exact(channel, 4, deadline)
                    first = dict(zip(observer.FIELDS, observer.first_failure, strict=True))
                    outer = dict(zip(observer.FIELDS, observer.outer_failure, strict=True))
                    assert observer.latched and first["confirmed_bytes_before"] == 2
                    assert first["error_type"] == ("LocalhostTransportDisconnected" if ending == "eof" else type(terminal).__name__)
                    assert outer["error_type"] == error_type.__name__
                    assert caught.value.__cause__ is (None if ending == "eof" else terminal)
                    if wait_profile and ending != "eof":
                        entry = dict(zip(observer.ENTRY_FIELDS, observer.first_failure_entry, strict=True))
                        assert entry["operation"] == "recv" and entry["native_called"]
                        assert entry["confirmed_bytes_before"] == 2 and entry["requested_bytes"] == 2
                assert getattr(observer.state, "qpc_receive_probe", None) is None
            report = observer.report()
            assert channel.timeout == .5 and report["socket_hooks_restored"]
            native = [dict(zip(observer.FIELDS, row[2], strict=True)) for row in observer.slots
                      if row and row[0] == "trace" and row[1] == "socket"]
            assert any(row["error_type"] == transient.__name__ for row in native)
            assert report["encoded_bytes"] <= report["encoded_limit"]
    # 同类异常在旧float接收/发送中会终止，不能因为修复QPC续收而被全局忽略。
    for operation in ("legacy_receive", "qpc_send"):
        observer = _TimeoutDiagnostic("Client", (101, 102, 103), wait_profile=wait_profile)
        observer.select(0)
        channel = _S10Socket(fail_at=1)
        channel.failure = BlockingIOError()
        with observer.sockets(), pytest.raises(transport.LocalhostTransportDisconnected) as caught:
            if operation == "legacy_receive":
                transport._receive_exact(channel, 4, time.monotonic()+1)
            else:
                transport._send_exact(channel, b"abcd", _CycleDeadline(time.perf_counter_ns()+10**9))
        assert caught.value.__cause__ is channel.failure and observer.latched
        assert dict(zip(observer.FIELDS, observer.first_failure, strict=True))["error_type"] == "BlockingIOError"


@pytest.mark.parametrize(("operation", "fail_at", "part", "confirmed"),
                         [("recv", 2, "header", 2), ("recv", 4, "body", 2), ("send", 2, "header_and_body", 2)])
def test_s10_native_entry_preserves_partial_progress_original_error_and_first_failure(monkeypatch, operation, fail_at, part, confirmed):
    _qpc_fake_readable(monkeypatch)
    import struct

    from secure_control.execution import localhost_transport as transport
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments.communication_benchmark import _TimeoutDiagnostic

    observer = _TimeoutDiagnostic("Client", (101, 102, 103), wait_profile=True)
    observer.select(2823)
    sock = _S10Socket(struct.pack("!I", 5)+b"abcde", fail_at)
    deadline = _CycleDeadline(time.perf_counter_ns()+1_000_000_000)
    original_native = getattr(sock, operation)
    def native(*args):
        try:
            return original_native(*args)
        finally:
            if len(sock.calls) == fail_at:
                # 原生失败后才改变观察时钟：旧post字段应负，新entry仍为正。
                observer.wall = lambda: deadline.deadline_ns+1_000_000
    setattr(sock, operation, native)
    callbacks = list(__import__("gc").callbacks)
    original_precheck = transport._set_remaining_timeout
    with observer.installed(), observer.sockets(), pytest.raises(transport.LocalhostTransportTimeout) as raised:
        if operation == "recv":
            transport.receive_frame(sock, deadline=deadline, limit=10)
        else:
            transport.send_frame(sock, b"abcde", deadline=deadline, limit=10)
    assert raised.value.__cause__ is sock.failure and len(sock.calls) == fail_at
    entry = dict(zip(observer.ENTRY_FIELDS, observer.first_failure_entry, strict=True))
    assert entry["operation"] == operation and entry["peer"] == "P2" and entry["frame_part"] == part
    assert entry["native_called"] and entry["remaining_at_entry_ns"] > 0
    assert dict(zip(observer.FIELDS, observer.first_failure, strict=True))["remaining_ns"] < 0
    assert entry["confirmed_bytes_before"] == confirmed
    assert entry["actual_timeout_s"] == entry["requested_timeout_s"]
    assert entry["actual_timeout_s"] == 0 if operation == "recv" else entry["actual_timeout_s"] > 0
    assert entry["deadline_ns"] == deadline.deadline_ns and entry["clock_domain"] == "qpc_cycle"
    assert entry["qpc_before_ns"] <= entry["qpc_after_ns"]
    saved = observer.first_failure_entry
    observer.marker("runtime_close_end")
    observer.failed(tuple(None for _ in observer.FIELDS))
    assert observer.first_failure_entry is saved
    report = observer.report()
    assert report["format_version"] == 2 and report["profile"] == "worker-online-wait-v1"
    assert report["callback_restored"] and report["socket_hooks_restored"]
    assert transport._set_remaining_timeout is original_precheck and __import__("gc").callbacks == callbacks
    assert any(event.get("entry") == saved for event in report["events"])
    assert "private socket text" not in str(report)


def test_s10_expired_precheck_never_calls_native_and_keeps_negative_entry():
    from secure_control.execution import localhost_transport as transport
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments.communication_benchmark import _TimeoutDiagnostic

    observer = _TimeoutDiagnostic("Client", (101, 102, 103), wait_profile=True)
    sock = _S10Socket()
    deadline = _CycleDeadline(time.perf_counter_ns()-1_000_000)
    with observer.sockets(), pytest.raises(transport.LocalhostTransportTimeout):
        transport.receive_frame(sock, deadline=deadline, limit=10)
    entry = dict(zip(observer.ENTRY_FIELDS, observer.first_failure_entry, strict=True))
    assert entry["operation"] == "timeout_precheck" and entry["native_called"] is False
    assert entry["remaining_at_entry_ns"] < 0 and not sock.calls
    assert entry["requested_bytes"] == 4 and entry["requested_timeout_s"] is None


def test_s10_both_phase_filters_context_and_gc_are_observable_and_bounded(monkeypatch):
    import gc
    import json

    from secure_control.experiments.communication_benchmark import _TimeoutDiagnostic

    observer = _TimeoutDiagnostic("P2", (101, 102, 103), wait_profile=True)
    observer.select(2822)
    observer.state.frame_unknown = True
    assert observer._label()[1] is None
    calls = []
    observer.wrap("material_restore", lambda: calls.append("restore"))()
    observer.wrap("decode_ms", lambda: calls.append("decode"))()
    observer.state.frame_unknown = False
    observer.select(2823)
    observer.wrap("online_ack", lambda: calls.append("ack"))()
    phases = {e.get("phase") for e in observer.report()["events"]}
    assert {"material_restore", "decode_ms", "online_ack"} <= phases
    observer._gc("start", {"generation": 1})
    observer._gc("stop", {"generation": 1, "collected": 2, "uncollectable": 0})
    assert any(e.get("pairing") == "complete" for e in observer.report()["events"])
    for _ in range(1000):
        observer.wrap("online_wait_P2", lambda: None)()
    observer._gc("start", {"generation": 2})
    pending = observer.gc_pending
    assert pending is not None
    report = observer.report()
    assert calls == ["restore", "decode", "ack"] and len(observer.slots) == 304
    assert report["evicted_count"]["frame"] > 0 and report["encoded_bytes"] <= 72*1024
    assert any(e.get("pairing") == "missing_stop" for e in report["events"])
    assert report == observer.report() and "private" not in json.dumps(report)
    assert gc.get_threshold() == (700, 10, 10)


@pytest.mark.parametrize("fault", ("success", "control", "cleanup", "budget"))
def test_s10_diagnostic_never_grants_qualification_and_preserves_failure(monkeypatch, fault):
    from secure_control.experiments import communication_benchmark as bench

    cycles = [{"status": "failed", "cycle_completed_ns": None}] if fault == "control" else []
    roles = [{"role": "Client", "format_version": 2, "first_failure_entry": ("public",),
              "events": [{"padding": "x" * (256*1024)}] if fault == "budget" else [],
              "callback_restored": True, "socket_hooks_restored": True}]
    def observed(**options):
        if fault == "cleanup":
            options["_register_trace_cleanup"](lambda: (_ for _ in ()).throw(OSError("private cleanup")))()
        return {"status": "failed" if fault == "control" else "stopped", "cycles": cycles,
                "failure_category": "LocalhostTransportTimeout" if fault == "control" else None,
                "failed_phase": "ROUND_IN_FLIGHT" if fault == "control" else None,
                "diagnostic_report": {"roles": roles}, "successful_steps": 0, "failed_attempts": len(cycles)}
    monkeypatch.setattr(bench, "_run_continuous_observation", observed)
    result = bench._run_material_comparison({"steps": 4000, "worker_wait_diagnostic": True}, "worker", target_steps=4000)
    assert result["diagnostic"] and result["comparison_only"] and result["cycles"] is cycles
    assert all(result[key] is False for key in ("candidate_gate_pass", "worker_long_run_gate_pass", "stage_pass", "qualification_pass"))
    assert result["worker_wait_diagnostic"]["maximum_attempts"] == 4000
    assert "worker_timeout_diagnostic" not in result and "worker_long_run" not in result
    if fault == "control":
        assert result["failure_category"] == "LocalhostTransportTimeout" and result["failed_phase"] == "ROUND_IN_FLIGHT"
    elif fault != "success":
        assert result["status"] == "failed"
    if fault == "budget":
        assert result["worker_wait_diagnostic"]["diagnostic_budget_failed"]
        assert result["diagnostic_report"]["roles"][0]["first_failure_entry"] == ("public",)
    assert "private cleanup" not in str(result)


def test_s10_real_observer_composition_records_online_chain_without_previous_identity(monkeypatch):
    import struct

    from test_two_party_protocol import make_stack

    from secure_control.execution import lan_runtime
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.protocol import coordinator

    client_owner, _, _, _, distribution = make_stack()
    online = client_owner.prepare_online(distribution, [.25], step=2823, rng=random.Random(10))
    message = WireEnvelope(SCHEMA_VERSION, "request", "Client", "P2", 3, "online",
                           online.session_id, online.round_id, 2823, None,
                           PartyOnlineMaterial.from_round(PartyOnlineRound(online.p2_input, online.p2_resources)))
    encoded = encode_envelope(message)
    sock = _S10Socket(struct.pack("!I", len(encoded))+encoded)
    sock.getsockname = lambda: ("127.0.0.1", 102)
    sock.getpeername = lambda: ("127.0.0.1", 9000)
    sock.send = lambda data: len(data)
    observer = bench._TimeoutDiagnostic("P2", (101, 102, 103), wait_profile=True)
    observer.select(2822)
    observer.remember(SimpleNamespace(sender="Client", recipient="P2", operation="online",
                                     step=2822, round_id="previous-public-round", payload=None))
    recovered = object()
    monkeypatch.setattr(coordinator._OnlineMaterialRecovery, "restore", lambda self: recovered)
    with observer.installed(), observer.sockets():
        _, _, restore = bench._meter("P2", (101, 102, 103), 0, diagnostic=observer)
        try:
            request = lan_runtime.receive_envelope(sock, deadline=time.monotonic()+10, limit=len(encoded))
            assert (request.session_id, request.round_id, request.step) == (online.session_id, online.round_id, 2823)
            assert coordinator._OnlineMaterialRecovery.restore(object()) is recovered
            lan_runtime._party_reply(sock, request, None, 10)
        finally:
            restore()
    report = observer.report()
    phases = {e.get("phase") for e in report["events"]}
    assert {"decode_ms", "receive_request", "material_restore", "online_ack"} <= phases
    assert any(e.get("operation") == "online_decode_return" for e in report["events"])
    entries = [dict(zip(observer.ENTRY_FIELDS, e["entry"], strict=True))
               for e in report["events"] if e.get("entry")]
    received = [e for e in entries if e["operation"] == "recv"]
    assert received and all(e["context"] is None and e["control_label"][1] is None for e in received)
    assert all(e["clock_domain"] == "legacy_monotonic" for e in entries)
    assert report["callback_restored"] and report["socket_hooks_restored"]
    # Client两个等待各有独立区间，透传原请求/参数/返回和失败对象。
    calls = []
    error = OSError("private wait")
    def receive(sock, request, **kwargs):
        calls.append((request.recipient, kwargs))
        if request.recipient == "P2":
            raise error
        return recovered
    monkeypatch.setattr(lan_runtime, "_receive_reply", receive)
    client = bench._TimeoutDiagnostic("Client", (101, 102, 103), wait_profile=True)
    client.select(2823)
    first_request = SimpleNamespace(sender="Client", recipient="P1", operation="online", step=2823,
                                    round_id=online.round_id, session_id=online.session_id, payload=None)
    with client.sockets():
        assert lan_runtime._receive_reply(None, first_request, deadline=123.) is recovered
        with pytest.raises(OSError) as raised:
            lan_runtime._receive_reply(None, message, deadline=123.)
        assert raised.value is error
    events = client.report()["events"]
    assert {(e["phase"], e["status"]) for e in events if e.get("phase", "").startswith("online_wait")} == {
        ("online_wait_P1", "complete"), ("online_wait_P2", "OSError")}
    assert calls == [("P1", {"deadline": 123.}), ("P2", {"deadline": 123.})]


@pytest.mark.parametrize("failure_point", ("control", "prepared"))
def test_s10_real_initialization_restores_new_and_old_hooks_without_starting_roles(monkeypatch, failure_point):
    import gc

    from secure_control.execution import lan_runtime
    from secure_control.execution import localhost_transport as transport
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_continuous_profile

    originals = (transport._send_exact, transport._receive_exact, transport._set_remaining_timeout,
                 transport.encode_envelope, transport.decode_envelope, lan_runtime._receive_reply,
                 lan_runtime._party_reply, lan_runtime.LanSegmentedRuntime.close, list(gc.callbacks))
    closed = []
    def failed(*args, **kwargs):
        raise OSError("private initialization")
    def forbidden(*args, **kwargs):
        pytest.fail("软件测试不能启动定位控制进程")
    context = SimpleNamespace(Queue=lambda: SimpleNamespace(close=lambda: closed.append(True)),
        Process=lambda **kwargs: SimpleNamespace(start=forbidden, join=forbidden, is_alive=lambda: False))
    monkeypatch.setattr(bench.mp, "get_context", lambda method: context)
    monkeypatch.setattr(bench, "_ports", lambda: (101, 102, 103))
    monkeypatch.setattr(lan_runtime if failure_point == "control" else lan_continuous_profile,
                        "RunControl" if failure_point == "control" else "load_segmented_experiment", failed)
    result = bench.run_continuous_observation(steps=4000, delay_ms=0, segment_steps=400,
        optimized=True, recording_mode="light", worker_wait_diagnostic=True)
    assert result["status"] == "failed" and result["failure_category"] == "OSError" and closed == [True]
    assert originals == (transport._send_exact, transport._receive_exact, transport._set_remaining_timeout,
        transport.encode_envelope, transport.decode_envelope, lan_runtime._receive_reply,
        lan_runtime._party_reply, lan_runtime.LanSegmentedRuntime.close, list(gc.callbacks))
    assert result["worker_wait_diagnostic"]["actual_attempts"] == 0
    role = result["diagnostic_report"]["roles"][0]
    assert role["profile"] == "worker-online-wait-v1" and role["socket_hooks_restored"] and role["callback_restored"]
    assert role["first_failure_entry"] is None and "private initialization" not in str(result)


def test_s10_cli_rejects_other_routes_and_transfers_only_diagnostic_flag(tmp_path, monkeypatch):
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_runner

    calls = []
    monkeypatch.setattr(bench, "run_continuous_observation", lambda **kw:
                        calls.append(kw) or {"status": "stopped", "cycle_timing": {"p50_ms": 1.}})
    base = ["secure-control", "benchmark", "--worker-wait-diagnostic", "--steps", "4000",
            "--recording", "light", "--output", str(tmp_path/"raw.json")]
    monkeypatch.setattr("sys.argv", base+["--case", "full-observation"])
    assert lan_runner._run() == 5 and not calls
    monkeypatch.setattr("sys.argv", base+["--case", "cycle", "--mode", "batch"])
    assert lan_runner._run() == 0
    assert calls[0]["worker_wait_diagnostic"] is True and calls[0]["worker_long_run"] is False


def test_s11_party_offline_collect_once_before_ack_and_restore_meter(monkeypatch):
    """穿过真实party/meter组合；装配后清理，原参数及所有hook退出恢复。"""
    import gc

    from secure_control.execution import lan_runtime, localhost_transport
    from secure_control.experiments import communication_benchmark as bench

    before = (lan_runtime._party_reply, lan_runtime.receive_envelope,
              localhost_transport._send_exact, localhost_transport.decode_envelope, list(gc.callbacks))
    calls, assembled = [], []
    sock, payload, answer = object(), object(), object()
    def reply(s, request, value, timeout, *, deadline=None):
        assert (s, value, timeout, deadline) == (sock, payload, 30, 123)
        calls.append(request.operation)
        return answer
    def collect(generation):
        assert generation == 2 and assembled == ["offline", "role", "recovery"]
        calls.append("collect")
        for callback in tuple(gc.callbacks):
            callback("start", {"generation": 2})
            callback("stop", {"generation": 2, "collected": 6, "uncollectable": 0})
        return 6
    def run(config, *, batch):
        assert batch
        for op in ("lan_ready", "lan_setup"):
            request = SimpleNamespace(operation=op, payload=None)
            assert lan_runtime._party_reply(sock, request, payload, 30, deadline=123) is answer
        assembled.extend(("offline", "role", "recovery"))
        for op in ("offline", "offline", "online", "commit", "segment_begin", "segment_end"):
            request = SimpleNamespace(operation=op, payload=SimpleNamespace(action="stop"))
            assert lan_runtime._party_reply(sock, request, payload, 30, deadline=123) is answer
        return {"status": "closed"}
    monkeypatch.setattr(lan_runtime, "_party_reply", reply)
    monkeypatch.setattr(gc, "collect", collect)
    monkeypatch.setattr(bench, "run_party_single_step", run)
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 1024, "peak_rss_bytes": 1024})
    queue = Queue()
    bench._party_job(SimpleNamespace(role="P1"), (101, 102, 103), 0, True, queue,
                     material_comparison=True, server_gc_candidate=True)
    row = queue.get_nowait()
    assert row["status"] == "closed" and calls == ["lan_ready", "lan_setup", "collect",
        "offline", "offline", "online", "commit", "segment_begin", "segment_end"]
    assert lan_runtime._party_reply is reply
    assert before[1:] == (lan_runtime.receive_envelope, localhost_transport._send_exact,
                          localhost_transport.decode_envelope, list(gc.callbacks))
    observed = row["server_gc"]
    assert observed["startup_collect"]["completed"] and observed["startup_collect"]["collected"] == 6
    assert observed["startup_attempted"] and observed["normal_stop_ack_sent"]
    assert observed["events"] == [] and observed["callback_and_hook_restored"]
    assert observed["gc_before"]["threshold"] == observed["gc_after"]["threshold"] == [700, 10, 10]


def test_s11_selector_rejects_invalid_and_conflicting_modes_before_side_effects(monkeypatch):
    import gc

    from secure_control.experiments import communication_benchmark as bench

    calls = []
    def selected(options, candidate, **kw):
        calls.append((options, candidate, kw))
        return {}
    def forbidden(*args, **kwargs):
        pytest.fail("非法S11选择不能创建端口、角色或材料")
    monkeypatch.setattr(bench, "_run_material_comparison", selected)
    monkeypatch.setattr(bench, "_ports", forbidden)
    base = {"steps": 4000, "delay_ms": 0, "segment_steps": 400, "material_slots": 16,
            "optimized": True, "recording_mode": "light", "server_gc_candidate": True}
    edits = {"steps": (20, 1000, 10000, 4000., True), "segment_steps": (400., 401),
        "material_slots": (16., 17), "delay_ms": (True, .1), "preload_steps": (1, False),
        "preload_execution": ("split",), "optimized": (False,), "recording_mode": ("full",),
        "diagnostic": (True,), "timeout_trace": (True,), "material_candidate": ("worker", "thread"),
        "worker_timeout_diagnostic": (True,), "worker_long_run": (True,), "worker_wait_diagnostic": (True,),
        "gc_trial_policy": ("baseline",), "role_config": ("external.yaml",), "tcp_nodelay": (False, True),
        "commit_policy": ("parallel",), "server_gc_candidate": (1, "yes")}
    for key, values in edits.items():
        for value in values:
            with pytest.raises(ValueError):
                bench.run_continuous_observation(**(base | {key: value}))
            assert not calls
    for name, replacement in (("isenabled", lambda: False), ("get_threshold", lambda: (701, 10, 10)),
                              ("get_freeze_count", lambda: 1), ("get_debug", lambda: 1),
                              ("callbacks", [lambda *args: None])):
        with monkeypatch.context() as patcher:
            patcher.setattr(gc, name, replacement)
            with pytest.raises(ValueError):
                bench.run_continuous_observation(**base)
        assert not calls
    bench.run_continuous_observation(**base)
    assert calls[0][1:] == ("worker", {"target_steps": 4000})
    assert calls[0][0]["server_gc_candidate"] is True


def test_s11_startup_or_original_reply_error_never_fakes_ack_and_restores(monkeypatch):
    import gc

    from secure_control.execution import lan_runtime
    from secure_control.experiments import communication_benchmark as bench

    callbacks, state = list(gc.callbacks), bench._ServerGCObservation.state()
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 1024})
    for fault in ("collect", "reply"):
        calls, error = [], OSError("private failure text")
        def collect(generation, calls=calls, fault=fault, error=error):
            calls.append("collect")
            if fault == "collect":
                raise error
            return 4
        def reply(*args, calls=calls, error=error, **kwargs):
            calls.append("reply")
            raise error
        monkeypatch.setattr(gc, "collect", collect)
        monkeypatch.setattr(lan_runtime, "_party_reply", reply)
        observation = bench._ServerGCObservation("P2")
        with pytest.raises(OSError) as caught, observation.installed():
            lan_runtime._party_reply(object(), SimpleNamespace(operation="offline"), None, 30)
        assert caught.value is error and calls == (["collect"] if fault == "collect" else ["collect", "reply"])
        row = observation.report()
        assert row["startup_collect"]["completed"] == (fault == "reply")
        assert row["startup_collect"]["error_type"] == ("OSError" if fault == "collect" else None)
        assert row["callback_and_hook_restored"] and lan_runtime._party_reply is reply
        assert gc.callbacks == callbacks and bench._ServerGCObservation.state()["threshold"] == state["threshold"]
        assert "private" not in str(row)


def test_s11_gen2_ring_is_bounded_pairing_honest_and_no_runtime_encoding(monkeypatch):
    from secure_control.experiments import communication_benchmark as bench

    ticks = iter(range(10000))
    observation = bench._ServerGCObservation("P1", wall=lambda: next(ticks))
    def forbidden(*args, **kw):
        pytest.fail("回调不能编码JSON或主动collect")
    with monkeypatch.context() as patcher:
        patcher.setattr(bench.json, "dumps", forbidden)
        patcher.setattr(bench.gc, "collect", forbidden)
        observation._gc("start", {"generation": 0})
        observation._gc("stop", {"generation": 0})
        assert observation.pending is None and observation.count == 0
        for _ in range(70):
            observation._gc("start", {"generation": 2})
            observation._gc("stop", {"generation": 2, "collected": 6, "uncollectable": 0})
        observation._gc("stop", {"generation": 2})
        observation._gc("start", {"generation": 2})
        observation._gc("start", {"generation": 2})
    row = observation.report()
    assert len(row["events"]) == 64 and row["completed_count"] == 70 and row["evicted_count"] == 6
    assert row["unpaired_count"] == 2 and row["pending"] is not None
    assert row["max_interval_ns"] == 1 and row["total_interval_ns"] == 70
    assert row["events"][0][:2] == (12, 13) and row["events"][-1][:2] == (138, 139)
    assert row["encoded_bytes"] <= 32768 and not row["budget_failed"]
    assert all(len(event) == 6 for event in row["events"])
    assert "round" not in row["fields"] and "step" not in row["fields"]


def test_s11_observation_clock_encoding_and_child_memory_failures_refuse_evidence(monkeypatch):
    from secure_control.experiments import communication_benchmark as bench

    ticks = iter((2, 1))
    observation = bench._ServerGCObservation("P1", wall=lambda: next(ticks))
    observation._gc("start", {"generation": 2})
    observation._gc("stop", {"generation": 2, "collected": 0, "uncollectable": 0})
    assert observation.error_type == "ValueError" and observation.count == 0
    huge = 10**300
    observation.slots = [(huge, huge + 1, huge, 2, huge, huge)] * 64
    row = observation.report()
    assert row["budget_failed"] and row["encoded_omitted"] > 0 and row["encoded_bytes"] <= 32768
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 257 * 1024**2})
    with pytest.raises(RuntimeError, match="RSS"):
        observation._memory("software_fixture")


def _s11_public_result():
    """复用已有公开周期fixture，缩为4000并补9次维护/启动/原停止证据。"""
    from secure_control.experiments import communication_benchmark as bench

    result = _s9_public_result()
    result["cycles"] = result["cycles"][:4000]
    result.update(requested_steps=4000, successful_steps=4000, protocol_committed_count=4000,
                  physically_confirmed_count=4000, cycle_summary={"attempts": 4000, "misses": 0},
                  resource_counts={"products_consumed": 120000, "truncations_consumed": 16000})
    result["material_summary"].update(claimed=4000, generated_received=4016)
    numeric = result.pop("worker_long_run")["numeric_contract"]
    numeric.update(block_steps=19, parameter_bits=40, runtime_payload_bits=46)
    metadata = {"format_version": 1, "target_steps": 4000, "maximum_attempts": 4000,
                "first_failure_stop": True, "numeric_contract": numeric}
    for step in range(399, 3999, 400):
        result["cycles"][step]["phase_durations_ns"] = {"maintenance": 1}
    for party in result["party_outcomes"]:
        party["steps"] = party["steps"][:4000]
        observation = bench._ServerGCObservation(party["role"])
        observation.gc_before = observation.gc_after = {
            "enabled": True, "threshold": [700, 10, 10], "freeze_count": 0, "debug": 0}
        observation.startup = {"start_ns": -10, "end_ns": -1, "collected": 6,
                               "completed": True, "error_type": None, "native_thread_id": 1}
        observation.startup_attempted = observation.normal_stop_ack_sent = observation.restored = True
        party["server_gc"] = observation.report()
    result["last_commit_observation"].update(round_id="round-3999", step=3999, global_step=3999)
    result.update(comparison_only=True, qualification_pass=False, stage_pass=False)
    return result, metadata


def test_s11_gate_separates_finite_candidate_from_runtime_gen2_coverage():
    from secure_control.experiments import communication_benchmark as bench

    report = {"memory_guard_failed": False, "cleanup_failed": False, "producer_exited": True}
    for covered in (False, True):
        result, metadata = _s11_public_result()
        if covered:
            for party in result["party_outcomes"]:
                party["server_gc"]["events"] = [(100, 200, 1, 2, 6, 0)]
        bench._finish_server_gc(result, report, metadata)
        assert result["server_gc_candidate_gate_pass"]
        assert metadata["runtime_gen2_covered"] == covered
        assert metadata["actual_attempts"] == 4000 and metadata["invocation_budget_consumed"]
        assert metadata["encoded_bytes"] <= 98304
        assert result["diagnostic"] is False and result["diagnostic_report"] is None and result["timeout_trace"] is None
        assert result["comparison_only"] and not any(result[key] for key in
            ("candidate_gate_pass", "worker_long_run_gate_pass", "qualification_pass", "stage_pass"))


def test_s11_gate_rejects_bad_period_boundary_proof_stop_and_missing_evidence():
    from copy import deepcopy

    from secure_control.experiments import communication_benchmark as bench

    good, metadata = _s11_public_result()
    report = {"memory_guard_failed": False, "cleanup_failed": False, "producer_exited": True}
    bench._finish_server_gc(good, report, metadata)
    edits = [(("cycles", 0, "global_step"), False), (("cycle_summary", "misses"), False),
        (("cycles", 399, "cycle_completed_ns"), good["cycles"][399]["deadline_ns"]),
        (("cycles", 3999, "cycle_completed_ns"), None), (("cycles", 400, "actual_sample_start_ns"), None),
        (("cycles", 399, "phase_durations_ns", "maintenance"), -1),
        (("cycles", 799, "phase_durations_ns"), {}), (("cycles", 400, "round_id"), "round-399"),
        (("server_gc_candidate", "numeric_contract", "block_steps"), 20),
        (("server_gc_candidate", "numeric_contract", "horizon_steps"), 4000),
        (("server_gc_candidate", "numeric_contract", "runtime_payload_bits"), 45),
        (("server_gc_candidate", "roles", 0, "normal_stop_ack_sent"), False),
        (("server_gc_candidate", "roles", 1, "startup_collect", "completed"), False),
        (("server_gc_candidate", "observation_failed"), True),
        (("last_commit_observation", "parties", "P2", "valid_ack_received"), False),
        (("material_summary", "worker_exited"), False), (("material_summary", "cleanup_failed"), True),
        (("material_summary", "inventory_inflight_high_water"), 17),
        (("material_summary", "material_encoded_bound_high_water"), 8388609),
        (("resource_counts", "products_consumed"), 119970), (("protocol_committed_count",), 3999)]
    for path, value in edits:
        bad = deepcopy(good)
        parent = bad
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = value
        assert not bench._server_gc_run_gate(bad, report), path
    for key in ("cycles", "party_outcomes", "last_commit_observation", "server_gc_candidate"):
        bad = deepcopy(good)
        bad.pop(key)
        assert not bench._server_gc_run_gate(bad, report)


def test_s11_missing_role_record_or_budget_failure_preserves_control_first_error():
    from secure_control.experiments import communication_benchmark as bench

    report = {"memory_guard_failed": False, "cleanup_failed": False, "producer_exited": True}
    for fault in ("missing", "encoding", "pending", "budget"):
        result, metadata = _s11_public_result()
        original_cycles = result["cycles"]
        if fault == "missing":
            result["party_outcomes"][1].pop("server_gc")
        elif fault == "encoding":
            result["party_outcomes"][1]["server_gc"] = {"role": "P2", "error_type": "OSError"}
        elif fault == "pending":
            for party in result["party_outcomes"]:
                party["server_gc"].update(events=[(100, 200, 1, 2, 6, 0)], pending=(300, 1))
        else:
            metadata["scope_fixture"] = "public" * 17000
            result.update(status="uncertain", failure_category="LocalhostTransportTimeout", failed_phase="ROUND_IN_FLIGHT")
        bench._finish_server_gc(result, report, metadata)
        assert result["cycles"] is original_cycles and not metadata["runtime_gen2_covered"]
        if fault in ("missing", "encoding"):
            assert result["failure_category"] == "ServerGCObservation" and not result["server_gc_candidate_gate_pass"]
        elif fault == "pending":
            assert result["server_gc_candidate_gate_pass"]  # 有限通过，但gen2观察不完整
        else:
            assert result["failure_category"] == "LocalhostTransportTimeout" and metadata["budget_failed"]
            assert result["failed_phase"] == "ROUND_IN_FLIGHT" and not result["server_gc_candidate_gate_pass"]


def test_s11_real_initialization_restores_hooks_closes_queue_and_retains_original_error(monkeypatch):
    import gc

    from secure_control.execution import lan_runtime, localhost_transport
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_continuous_profile

    originals = (localhost_transport._send_exact, localhost_transport._receive_exact,
                 lan_runtime._party_reply, lan_runtime.LanSegmentedRuntime.close, list(gc.callbacks))
    for fault in ("control", "profile"):
        with monkeypatch.context() as patcher:
            closed = []
            def failed(*args, **kwargs):
                raise OSError("private startup text")
            def forbidden(*args, **kwargs):
                pytest.fail("软件fixture不能启动角色或性能验证")
            context = SimpleNamespace(Queue=lambda closed=closed: SimpleNamespace(close=lambda: closed.append(True)),
                Process=lambda **kwargs: SimpleNamespace(start=forbidden, join=forbidden, is_alive=lambda: False))
            patcher.setattr(bench.mp, "get_context", lambda method, context=context: context)
            patcher.setattr(bench, "_ports", lambda: (101, 102, 103))
            patcher.setattr(lan_runtime if fault == "control" else lan_continuous_profile,
                            "RunControl" if fault == "control" else "load_segmented_experiment", failed)
            result = bench.run_continuous_observation(steps=4000, delay_ms=0, segment_steps=400,
                optimized=True, recording_mode="light", server_gc_candidate=True)
            assert closed == [True] and result["failure_category"] == "OSError" and result["cycles"] == []
            assert result["server_gc_candidate"]["actual_attempts"] == 0
            assert result["diagnostic"] is False and result["diagnostic_report"] is None
            assert not result["server_gc_candidate_gate_pass"] and "private startup" not in str(result)
        assert originals == (localhost_transport._send_exact, localhost_transport._receive_exact,
                            lan_runtime._party_reply, lan_runtime.LanSegmentedRuntime.close, list(gc.callbacks))


def test_s11_cli_rejects_other_routes_and_transfers_only_candidate_flag(tmp_path, monkeypatch):
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_runner

    calls = []
    monkeypatch.setattr(bench, "run_continuous_observation", lambda **kw:
                        calls.append(kw) or {"status": "stopped", "cycle_timing": {"p50_ms": 1.}})
    base = ["secure-control", "benchmark", "--server-gc-candidate", "--steps", "4000",
            "--recording", "light", "--output", str(tmp_path / "raw.json")]
    for route in (["--case", "full-observation"], ["--case", "cycle", "--mode", "legacy"]):
        monkeypatch.setattr("sys.argv", base + route)
        assert lan_runner._run() == 5 and not calls and not (tmp_path / "raw.json").exists()
    monkeypatch.setattr("sys.argv", base + ["--case", "cycle", "--mode", "batch"])
    assert lan_runner._run() == 0
    assert calls[0]["server_gc_candidate"] is True and calls[0]["worker_wait_diagnostic"] is False


def _s12_hook_snapshot():
    import gc

    from secure_control.execution import (
        _localhost_peer,
        _localhost_workers,
        lan_runtime,
        localhost_transport,
    )

    return ([getattr(owner, name) for owner, names in (
        (localhost_transport, ("_send_exact", "_receive_exact", "_set_remaining_timeout", "encode_envelope", "decode_envelope")),
        (lan_runtime, ("_party_reply", "receive_envelope", "stage_protocol3_batch")),
        (lan_runtime.LanSegmentedRuntime, ("close",)),
        (_localhost_workers._ClientPartyEndpoint, ("start_stage_batch", "finish_stage_batch")),
        (_localhost_peer.LocalhostProtocol3PeerPort, ("exchange_products", "product_complete", "send_truncations", "receive_truncations", "state_complete")),
    ) for name in names], list(gc.callbacks))


def test_s12_party_failure_restores_all_hooks_before_report_and_preserves_original_error(monkeypatch):
    import gc

    from secure_control.execution import lan_runtime
    from secure_control.experiments import communication_benchmark as bench

    def reply(*args, **kwargs):
        return None
    def run(config, *, batch):
        assert batch
        lan_runtime._party_reply(object(), SimpleNamespace(operation="offline"), None, 30)
        raise OSError("private control failure")
    monkeypatch.setattr(lan_runtime, "_party_reply", reply)
    monkeypatch.setattr(bench, "run_party_single_step", run)
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 1024})
    monkeypatch.setattr(gc, "collect", lambda generation: 6)
    before = _s12_hook_snapshot()
    queue = Queue()
    bench._party_job(SimpleNamespace(role="P2"), (101, 102, 103), 0, True, queue,
        material_comparison=True, stage_wait_diagnostic=True)
    result = queue.get_nowait()
    assert result["status"] == "failed" and result["error_type"] == "OSError"
    assert _s12_hook_snapshot() == before
    assert "private" not in str(result) and "server_gc" not in result
    report = result["stage_wait"]
    assert report["hooks_restored"] and report["gc"]["callback_and_hook_restored"]
    assert report["gc"]["startup_collect"]["completed"] and report["gc"]["startup_collect"]["collected"] == 6


def test_s12_guard_and_reverse_conflicts_reject_before_resources(monkeypatch):
    import gc

    from secure_control.experiments import communication_benchmark as bench

    def forbidden(*args, **kwargs):
        pytest.fail("S12非法选择不能启动端口或材料")
    monkeypatch.setattr(bench, "_ports", forbidden)
    base = {"steps": 4000, "delay_ms": 0, "segment_steps": 400, "optimized": True,
            "recording_mode": "light", "stage_wait_diagnostic": True}
    for change in ({"stage_wait_diagnostic": 1}, {"steps": 20}, {"steps": 1000}, {"steps": 10000},
            {"steps": 4000.}, {"material_slots": True}, {"segment_steps": 400.}, {"delay_ms": False},
            {"preload_steps": False}, {"preload_steps": 1}, {"preload_execution": "staged"},
            {"optimized": False}, {"recording_mode": "full"}, {"diagnostic": True}, {"timeout_trace": True},
            {"server_gc_candidate": True}, {"worker_wait_diagnostic": True}, {"worker_long_run": True},
            {"worker_timeout_diagnostic": True}, {"material_candidate": "worker"}, {"gc_trial_policy": "baseline"},
            {"role_config": "unused"}, {"tcp_nodelay": False}, {"commit_policy": "serial"}):
        with pytest.raises(ValueError):
            bench.run_continuous_observation(**(base | change))
    for name, value in (("isenabled", False), ("get_threshold", (701, 10, 10)),
                        ("get_freeze_count", 1), ("get_debug", 1), ("callbacks", [object()])):
        with monkeypatch.context() as patcher:
            patcher.setattr(gc, name, value if name == "callbacks" else lambda value=value: value)
            with pytest.raises(ValueError):
                bench.run_continuous_observation(**base)
    calls = []
    monkeypatch.setattr(bench, "_run_material_comparison", lambda options, candidate, **kw:
        calls.append((options, candidate, kw)) or {})
    bench.run_continuous_observation(**base)
    assert calls[0][1:] == ("worker", {"target_steps": 4000})
    assert calls[0][0]["stage_wait_diagnostic"] and not calls[0][0]["diagnostic"]
    assert "server_gc_candidate" not in calls[0][0] and not calls[0][0]["timeout_trace"]


def test_s12_native_partial_frames_keep_entry_first_error_and_never_retry(monkeypatch):
    _qpc_fake_readable(monkeypatch)
    import struct

    from secure_control.execution import localhost_transport as transport
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments.communication_benchmark import _StageWaitDiagnostic

    for operation, fail_at, part in (("recv", 2, "header"), ("recv", 4, "body"), ("send", 2, "header_and_body")):
        observer = _StageWaitDiagnostic("Client", (101, 102, 103))
        sock = _S10Socket(struct.pack("!I", 5)+b"abcde", fail_at)
        deadline = _CycleDeadline(time.perf_counter_ns()+1_000_000_000)
        before = _s12_hook_snapshot()
        with observer.installed(), pytest.raises(transport.LocalhostTransportTimeout) as caught:
            if operation == "recv":
                transport.receive_frame(sock, deadline=deadline, limit=10)
            else:
                transport.send_frame(sock, b"abcde", deadline=deadline, limit=10)
        assert caught.value.__cause__ is sock.failure and len(sock.calls) == fail_at
        assert _s12_hook_snapshot() == before
        first = dict(zip(observer.FIELDS, observer.first_failure, strict=True))
        entry = dict(zip(observer.ENTRY_FIELDS, first["entry"], strict=True))
        assert first["operation"] == operation and first["frame_part"] == part and first["peer"] == "P2"
        assert first["error_type"] == "TimeoutError" and first["native_progress_unknown"]
        assert first["native_in_flight"] is False  # 事件在原调用已抛出之后保存
        assert entry["native_called"] and entry["remaining_at_entry_ns"] > 0
        assert entry["clock_domain"] == "qpc_cycle" and entry["monotonic_entry_ns"] is None
        assert entry["confirmed_bytes_before"] == 2 and entry["requested_timeout_s"] == entry["observed_timeout_s"]
        assert entry["requested_timeout_s"] == 0 if operation == "recv" else entry["requested_timeout_s"] > 0
        saved = observer.first_failure
        observer.marker("runtime_close_begin")
        observer.failed(tuple(None for _ in observer.FIELDS))
        assert observer.first_failure is saved
        report = observer.report()
        assert report["events"] == [] and report["in_flight"] == []  # 非stage只保留首错
        assert report["hooks_restored"] and "private" not in str(report)


def test_s12_expired_precheck_and_native_eof_have_different_first_error_evidence(monkeypatch):
    _qpc_fake_readable(monkeypatch)
    from secure_control.execution import localhost_transport as transport
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments.communication_benchmark import _StageWaitDiagnostic

    for expired in (True, False):
        observer = _StageWaitDiagnostic("Client", (101, 102, 103))
        sock = _S10Socket()
        deadline = _CycleDeadline(time.perf_counter_ns()+(-1_000_000 if expired else 1_000_000_000))
        expected = transport.LocalhostTransportTimeout if expired else transport.LocalhostTransportDisconnected
        with observer.installed(), pytest.raises(expected):
            transport.receive_frame(sock, deadline=deadline, limit=10)
        first = dict(zip(observer.FIELDS, observer.first_failure, strict=True))
        entry = dict(zip(observer.ENTRY_FIELDS, first["entry"], strict=True))
        assert entry["native_called"] == (not expired)
        if expired:
            assert not sock.calls and entry["remaining_at_entry_ns"] < 0
            assert first["timeout_origin"] == "absolute_precheck"
        else:
            assert sock.calls == [("recv", 4)] and first["last_native_returned_bytes"] == 0
            assert not first["native_progress_unknown"] and first["error_type"] == "LocalhostTransportDisconnected"


def test_s12_real_client_stage_methods_separate_frame_return_from_validated_receipt(monkeypatch):
    _qpc_fake_readable(monkeypatch)
    import struct

    import numpy as np

    from secure_control.execution._localhost_workers import _ClientPartyEndpoint
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.execution.localhost_codec import PartyStageResult
    from secure_control.experiments.communication_benchmark import _StageWaitDiagnostic
    from secure_control.protocol.messages import ControlShareMessage, Protocol3StageReceipt

    plan = SimpleNamespace(session_id="public-session", round_id="public-round", step=7)
    receipt = Protocol3StageReceipt(0, plan.session_id, plan.round_id, 7, 1, 1)
    share = ControlShareMessage(0, plan.session_id, plan.round_id, 7, 8, AdditiveShare(np.array([123456789], dtype=object)))
    reply = WireEnvelope(SCHEMA_VERSION, "reply", "P1", "Client", 5, "endpoint",
        plan.session_id, plan.round_id, 7, None, PartyStageResult(receipt, share))
    encoded = encode_envelope(reply)
    sock = _S10Socket(struct.pack("!I", len(encoded))+encoded)
    sock.getpeername = lambda: ("127.0.0.1", 101)
    def sent(value):
        sock.calls.append(("send", len(value)))
        return len(value)
    def received(length):
        sock.calls.append(("recv", length))
        value = bytes(sock.data[:length])
        del sock.data[:length]
        return value
    sock.send, sock.recv = sent, received
    endpoint = _ClientPartyEndpoint(sock, 0, plan, 5, 10000, 30,
                                    _CycleDeadline(time.perf_counter_ns()+1_000_000_000))
    observer = _StageWaitDiagnostic("Client", (101, 102, 103))
    before = _s12_hook_snapshot()
    with observer.installed():
        assert endpoint.start_stage_batch() is None
        assert endpoint.finish_stage_batch() == receipt
    assert _s12_hook_snapshot() == before and len(sock.calls) == 3
    report = observer.report()
    events = [dict(zip(observer.FIELDS, row, strict=True)) for row in report["events"]]
    phases = [e for e in events if e["kind"] == "phase"]
    assert {e["operation"] for e in phases} == {"start_stage_batch", "finish_stage_batch"}
    assert all(report["contexts"][e["context"]][8] == 5 for e in phases)
    body = next(e for e in events if e["operation"] == "frame_recv" and e["frame_part"] == "body")
    completed = next(e for e in phases if e["operation"] == "finish_stage_batch" and e["end_qpc_ns"] is not None)
    assert body["end_qpc_ns"] <= completed["end_qpc_ns"] and completed["error_type"] is None
    assert report["first_failure"] is None and report["encoded_bytes"] <= 65536
    assert "123456789" not in str(report) and endpoint.share == share


def test_s12_party_stage_peer_and_reply_forward_each_original_once(monkeypatch):
    from secure_control.execution import _localhost_peer, lan_runtime
    from secure_control.experiments.communication_benchmark import _StageWaitDiagnostic

    plan = SimpleNamespace(session_id="session", round_id="round", step=3)
    peer = SimpleNamespace(_peer="P2")
    endpoint = SimpleNamespace(plan=plan)
    answer, calls = object(), []
    def exchange(self, value, masks):
        assert self is peer and value is plan and masks is answer
        calls.append("peer")
        return answer
    def stage(ep, port):
        assert ep is endpoint and port is peer
        calls.append("stage")
        assert _localhost_peer.LocalhostProtocol3PeerPort.exchange_products(peer, plan, answer) is answer
        return answer
    def reply(sock, request, value, timeout, *, deadline=None):
        assert value is answer and timeout == 30 and deadline == 123
        calls.append("reply")
        return answer
    monkeypatch.setattr(lan_runtime, "stage_protocol3_batch", stage)
    monkeypatch.setattr(lan_runtime, "_party_reply", reply)
    monkeypatch.setattr(_localhost_peer.LocalhostProtocol3PeerPort, "exchange_products", exchange)
    before = _s12_hook_snapshot()
    observer = _StageWaitDiagnostic("P1", (101, 102, 103))
    request = SimpleNamespace(operation="endpoint", payload=SimpleNamespace(operation="stage_batch"),
        sender="Client", recipient="P1", session_id="session", round_id="round", step=3, sequence=9)
    with observer.installed():
        assert lan_runtime.stage_protocol3_batch(endpoint, peer) is answer
        assert lan_runtime._party_reply(object(), request, answer, 30, deadline=123) is answer
    assert calls == ["stage", "peer", "reply"] and _s12_hook_snapshot() == before
    events = [dict(zip(observer.FIELDS, row, strict=True)) for row in observer.report()["events"]]
    assert {e["operation"] for e in events} == {"party_stage", "exchange_products", "stage_reply"}
    assert all(e["peer"] == "Client" for e in events if e["operation"] == "stage_reply")


def test_s12_legacy_entry_never_uses_qpc_as_legacy_deadline_clock():
    import struct

    from secure_control.execution import localhost_transport as transport
    from secure_control.experiments.communication_benchmark import _StageWaitDiagnostic

    observer = _StageWaitDiagnostic("P2", (101, 102, 103), wall=lambda: 10**18)
    sock = _S10Socket(struct.pack("!I", 1)+b"a", fail_at=1)
    sock.getsockname = lambda: ("127.0.0.1", 102)
    sock.getpeername = lambda: ("127.0.0.1", 9000)
    observer.contexts[("Client", "P2")] = ("old", "Client", "P2", "online", None, "old-session", "old-round", 2, 1)
    with observer.installed(), pytest.raises(transport.LocalhostTransportTimeout):
        transport.receive_frame(sock, deadline=time.monotonic()+1, limit=10)
    row = dict(zip(observer.FIELDS, observer.first_failure, strict=True))
    entry = dict(zip(observer.ENTRY_FIELDS, row["entry"], strict=True))
    assert entry["clock_domain"] == "legacy_monotonic" and entry["remaining_at_entry_ns"] > 0
    assert entry["entry_qpc_ns"] == 10**18 and entry["monotonic_entry_ns"] != 10**18
    assert row["context"] is None  # 解码前不能拿旧round补造当前身份


def test_s12_bounded_stage_history_retains_first_error_through_eviction_and_encoding():
    from secure_control.experiments.communication_benchmark import _StageWaitDiagnostic

    observer = _StageWaitDiagnostic("Client", (101, 102, 103))
    observer.state.phase = "finish_stage_batch"
    row = ("io", "recv", 1, 2, 1, 1, "P1", "P1->Client", "body", None,
           "finish_stage_batch", (1, "qpc_cycle", 100, 99, .01, .01, True, 10, 2, None, 1, 1),
           None, "TimeoutError", None, None, None, "socket_recv", True, None, False)
    observer.failed(row)
    for _ in range(1000):
        observer.put("socket", row)
    saved = observer.first_failure
    report = observer.report()
    assert len(report["events"]) == 128 and report["evicted_count"] == 872
    assert report["first_failure"][11] == row[11] and observer.first_failure is saved
    assert report["encoded_bytes"] <= 65536
    # 仅退出编码预算压力，独立首错必须保留，普通历史省略需显式标记。
    observer.slots = [row[:2]+(10**300, 10**300+1)+row[4:]]*128
    pressured = observer.report()
    assert pressured["budget_failed"] and pressured["encoded_omitted"] > 0
    assert pressured["first_failure"][11] == row[11] and pressured["encoded_bytes"] <= 65536


def test_s12_clock_observation_failure_does_not_replace_successful_io():
    from secure_control.execution import localhost_transport as transport
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments.communication_benchmark import _StageWaitDiagnostic

    def broken_clock():
        raise OSError("private observer clock failure")
    observer = _StageWaitDiagnostic("Client", (101, 102, 103), wall=broken_clock)
    sock = _S10Socket()
    with observer.installed():
        transport.send_frame(sock, b"hello", deadline=_CycleDeadline(time.perf_counter_ns()+1_000_000_000), limit=10)
    assert len(sock.calls) == 5 and observer.first_failure is None
    assert observer.report()["observation_error_type"] == "OSError"
    assert "private" not in str(observer.report())


def test_s12_role_report_encoding_fault_preserves_control_error_and_restores_both_roles(monkeypatch):
    import gc

    from secure_control.experiments import communication_benchmark as bench

    def run(config, *, batch):
        raise RuntimeError("private primary control failure")
    def report(self):
        raise OSError("private report encoding failure")
    monkeypatch.setattr(bench, "run_party_single_step", run)
    monkeypatch.setattr(bench._StageWaitDiagnostic, "report", report)
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 1024})
    monkeypatch.setattr(gc, "collect", lambda generation: 0)
    for role in ("P1", "P2"):
        before = _s12_hook_snapshot()
        queue = Queue()
        bench._party_job(SimpleNamespace(role=role), (101, 102, 103), 0, True, queue,
            material_comparison=True, stage_wait_diagnostic=True)
        result = queue.get_nowait()
        assert result["error_type"] == "RuntimeError" and result["stage_wait"]["observation_error_type"] == "OSError"
        assert _s12_hook_snapshot() == before and "private" not in str(result)


def _s12_software_observer(role):
    """只生成公开软件fixture，未启动角色/材料/端口或主动GC。"""
    from secure_control.experiments import communication_benchmark as bench

    gc_observer = bench._ServerGCObservation(role)
    gc_observer.gc_before = gc_observer.gc_after = gc_observer.state()
    gc_observer.restored = True
    if role != "Client":
        gc_observer.startup_attempted = True
        gc_observer.startup = {"start_ns": 1, "end_ns": 2, "completed": True, "collected": 0, "error_type": None}
    observer = bench._StageWaitDiagnostic(role, (101, 102, 103), gc_observer=gc_observer)
    observer.trace_restored = True
    return observer


def test_s12_result_never_grants_any_qualification_and_rejects_incomplete_evidence():
    import json
    from copy import deepcopy

    from secure_control.experiments import communication_benchmark as bench

    original, numeric = _s11_public_result()
    for party in original["party_outcomes"]:
        party.pop("server_gc")
        party["stage_wait"] = _s12_software_observer(party["role"]).report()
    sample = {"memory_guard_failed": False, "cleanup_failed": False, "producer_exited": True}
    for fault in ("normal", "missing", "hooks", "gc", "pending", "memory", "worker", "control"):
        result = deepcopy(original)
        observer = _s12_software_observer("Client")
        report = dict(sample)
        if fault == "missing":
            result["party_outcomes"][0].pop("stage_wait")
        elif fault == "hooks":
            observer.trace_restored = False
        elif fault == "gc":
            observer.gc_observer.gc_after = observer.gc_observer.state() | {"enabled": False}
        elif fault == "pending":
            observer.gc_observer.pending = (1, 1)
        elif fault == "memory":
            report["memory_guard_failed"] = True
        elif fault == "worker":
            result["material_summary"]["worker_exited"] = False
        elif fault == "control":
            result.update(status="uncertain", failure_category="OSError", failed_phase="ROUND_IN_FLIGHT", failed_attempts=1)
        metadata = {"format_version": 1, "maximum_attempts": 4000, "numeric_contract": numeric["numeric_contract"]}
        cycles = result["cycles"]
        bench._finish_stage_wait(result, report, metadata, [observer])
        assert result["cycles"] is cycles and metadata["evidence_complete"] == (fault in {"normal", "control"})
        assert result["diagnostic"] and result["comparison_only"] and metadata["actual_attempts"] == 4000
        assert metadata["encoded_bytes"] <= 192 * 1024 and metadata["invocation_budget_consumed"]
        assert result["timeout_trace"] is None
        if fault == "normal":
            def size(value):
                return len(json.dumps(value, separators=(",", ":"), allow_nan=False).encode())
            for role in metadata["roles"]:
                assert role["gc"]["encoded_bytes"] == size(role["gc"])
                assert role["encoded_bytes"] == size(role)
            assert metadata["encoded_bytes"] == size({"stage_wait_diagnostic": metadata,
                                                      "diagnostic_report": result["diagnostic_report"]})
        assert not any(result[k] for k in ("server_gc_candidate_gate_pass", "candidate_gate_pass", "worker_long_run_gate_pass",
                                           "stage_pass", "qualification_pass"))
        if fault == "control":
            assert result["failure_category"] == "OSError" and result["failed_phase"] == "ROUND_IN_FLIGHT"
            assert metadata["control_failure_observed"]

    # 实际编码压力，不伪造编码器计数；超大公开时间模拟坏观察数据，不能丢独立首错。
    result = deepcopy(original)
    client = _s12_software_observer("Client")
    first = ["io", "recv", 1, 2, 1, 1, "P1", "P1->Client", "body", 1, "finish_stage_batch",
             [1, "qpc_cycle", 100, 99, .01, .01, True, 10, 2, None, 1, 1], None,
             "TimeoutError", None, None, None, "socket_recv", True, None, False]
    for party in result["party_outcomes"]:
        role = party["stage_wait"]
        role.update(contexts=[("unused",), ("expected-stage",)], first_failure=list(first),
                    events=[first[:2]+[10**500, 10**500+1]+first[4:]]*128)
    result.update(status="uncertain", failure_category="LocalhostTransportTimeout", failed_phase="ROUND_IN_FLIGHT", failed_attempts=1)
    metadata = {"format_version": 1, "maximum_attempts": 4000, "numeric_contract": numeric["numeric_contract"]}
    bench._finish_stage_wait(result, sample, metadata, [client])
    assert metadata["budget_failed"] and not metadata["evidence_complete"] and metadata["encoded_bytes"] <= 192*1024
    assert result["failure_category"] == "LocalhostTransportTimeout" and result["failed_phase"] == "ROUND_IN_FLIGHT"
    for role in metadata["roles"]:
        if role["role"] != "Client":
            assert role["first_failure"][11] == first[11] and role["events"] == []
            assert role["contexts"] == [("expected-stage",)] and role["first_failure"][9] == 0


def test_s12_initialization_failure_closes_queue_and_all_observers_without_starting_roles(monkeypatch):
    from secure_control.execution import lan_runtime
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_continuous_profile

    for fault in ("control", "profile"):
        with monkeypatch.context() as patcher:
            closed = []
            before = _s12_hook_snapshot()
            def failed(*args, **kwargs):
                raise OSError("private startup failure")
            def forbidden(*args, **kwargs):
                pytest.fail("S12软件检查不得启动真实角色")
            context = SimpleNamespace(Queue=lambda closed=closed: SimpleNamespace(close=lambda: closed.append(True)),
                Process=lambda **kwargs: SimpleNamespace(start=forbidden, join=forbidden, is_alive=lambda: False))
            patcher.setattr(bench.mp, "get_context", lambda method, context=context: context)
            patcher.setattr(bench, "_ports", lambda: (101, 102, 103))
            patcher.setattr(lan_runtime if fault == "control" else lan_continuous_profile,
                "RunControl" if fault == "control" else "load_segmented_experiment", failed)
            result = bench.run_continuous_observation(steps=4000, delay_ms=0, segment_steps=400,
                optimized=True, recording_mode="light", stage_wait_diagnostic=True)
            assert result["failure_category"] == "OSError" and result["cycles"] == [] and closed == [True]
            assert result["stage_wait_diagnostic"]["actual_attempts"] == 0
            assert result["stage_wait_diagnostic"]["evidence_complete"] is False
            assert result["diagnostic"] and "private" not in str(result)
            assert _s12_hook_snapshot() == before


def test_s12_cli_rejects_other_routes_and_transfers_only_stage_flag(tmp_path, monkeypatch):
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_runner

    calls = []
    monkeypatch.setattr(bench, "run_continuous_observation", lambda **kw:
        calls.append(kw) or {"status": "stopped", "cycle_timing": {"p50_ms": 1.}})
    base = ["secure-control", "benchmark", "--stage-wait-diagnostic", "--steps", "4000",
            "--recording", "light", "--output", str(tmp_path / "raw.json")]
    for route in (["--case", "dynamic"], ["--case", "cycle", "--mode", "legacy"], ["--case", "full-observation"]):
        monkeypatch.setattr("sys.argv", base + route)
        assert lan_runner._run() == 5 and not calls and not (tmp_path / "raw.json").exists()
    monkeypatch.setattr("sys.argv", base + ["--case", "cycle", "--mode", "batch"])
    assert lan_runner._run() == 0 and calls[0]["stage_wait_diagnostic"] is True
    assert calls[0]["server_gc_candidate"] is False and calls[0]["worker_wait_diagnostic"] is False


def test_s13_fixed_history_preserves_types_presence_precision_and_atomic_prefix():
    import struct

    from secure_control.experiments import communication_benchmark as bench

    table = bench._HistoryTable(3, {("n",): "u", ("f",): "d", ("s",): 4, ("m",): "m", ("m", "n"): "u"})
    values = [{"n": 2**63+17, "f": -0.0, "s": "汉a", "m": {"n": None}},
              {"n": None, "f": 0.1, "m": {}}, {"n": 0}]
    for row in values:
        table.append(row.items())
    assert table.expand() == values
    assert struct.pack('>d', table.expand()[0]['f']) == struct.pack('>d', -0.0)
    assert len(table.buffer) == table.capacity * table.row_bytes
    with pytest.raises(RuntimeError):
        table.append({"n": 1}.items())
    assert table.count == 3 and table.expand() == values and table.error_type is not None

    for bad in (True, -1, 2**64, 1.5):
        broken = bench._HistoryTable(2, {("n",): "u"})
        broken.append({"n": 7}.items())
        with pytest.raises(RuntimeError):
            broken.append({"n": bad}.items())
        assert broken.count == 1 and broken.expand() == [{"n": 7}]
    for bad in ({"s": "汉汉"}, {"unknown": 1}, {"m": {"unknown": 1}}):
        broken = bench._HistoryTable(1, {("s",): 4, ("m",): "m", ("m", "n"): "u"})
        with pytest.raises(RuntimeError):
            broken.append(bad.items())
        assert broken.count == 0 and broken.expand() == []


def test_compact_v2_history_preserves_advance_and_original_layout():
    from secure_control.execution.cycle_timing import CycleTiming
    from secure_control.experiments import communication_benchmark as bench

    assert bench._CompactHistory.layout("Client", 10000, qualification=True)["reserved_bound_bytes"] == 31159895
    history = bench._CompactHistory("Client", steps=2, wire_profile="control-dynamic-compact-v2")
    timing = CycleTiming("run", "session", "epoch", 0, 399, "round", 20_000_000,
        1_000_000_000, 1_000_000_001, 1_020_000_000, status="miss_after_apply",
        phase_durations_ns={"maintenance": 6_000_000, "maintenance_advance": 5_000_000})
    history.cycle(timing, {}, {})
    rows = history.expand()
    phases = rows["cycles"][0]["phase_durations_ns"]
    assert phases == timing.phase_durations_ns
    assert "maintenance_end" not in phases and "maintenance_begin" not in phases
    assert rows["cycles"][0]["cycle_completed_ns"] is None
    report = history.report()
    assert report["format_version"] == 2 and report["representation_complete"]
    assert report["layout"]["reserved_bound_bytes"] < report["layout"]["limit_bytes"]


def test_s13_complete_synthetic_history_matches_original_fields_and_retains_no_input():
    import struct
    import weakref
    from dataclasses import asdict

    from secure_control.execution.cycle_timing import CycleTiming
    from secure_control.experiments import communication_benchmark as bench

    class Public:
        pass
    history = bench._CompactHistory("Client")
    buffers = {k: (id(t.buffer), len(t.buffer), len(t.fields)) for k, t in history.tables.items()}
    expected_cycles, expected_steps, expected_events = [], [], []
    activity = {k: .125 for k in history.ACTIVITY}
    before = {k: 0. for k in activity}
    storage = {k: 0 if k.endswith("count") else 0. for k in history.STORAGE}
    counts = {"Client->P1": {"frames": 2, "application_bytes": 100},
              "Client->P2": {"frames": 2, "application_bytes": 101}}
    for step in range(4000):
        start = 2**53+17+step*20000000
        phases = {"input": 0, "stage": 123}
        if step % 400 == 399 and step < 3999:
            phases.update(maintenance=123, maintenance_end=1, maintenance_source=2, maintenance_begin=3)
        timing = CycleTiming("run", "session", "epoch", step//400, step, f"round-{step}",
            20000000, start, start+1, start+20000000, start+2, start+3, start+4,
            "confirmed", None, step+1, step+1, phase_durations_ns=phases, queue_levels={"material_slots": 16})
        expected = asdict(timing)
        expected.update(public_frame_counts={k: v["frames"] for k, v in counts.items()},
                        public_byte_counts={k: v["application_bytes"] for k, v in counts.items()})
        expected_cycles.append(expected)
        history.cycle(timing, counts, {})
        record = Public()
        record.protocol = SimpleNamespace(global_step=step, segment_index=step//400,
                                          session_id="session", round_id=f"round-{step}")
        ref = weakref.ref(record)
        duration = -0.0 if step == 0 else 0.1
        marks = {"material_bind_ms": 0.125, "prepare_end_ns": start}
        history.step(record, duration=duration, marks=marks, activity=activity, before_activity=before,
            counts=counts, before_counts={}, storage=storage, before_storage=storage)
        expected_steps.append({"global_step": step, "segment_index": step//400, "session_id": "session",
            "round_id": f"round-{step}", "status": "confirmed", "duration_ms": duration,
            "components_ms": {"material_bind_ms": .125}, "activity": dict(activity), "sent": counts,
            "storage": {k: None if k in ("fsync_ms", "fsync_count", "checkpoint_ms") else v for k, v in storage.items()}})
        del record
        assert ref() is None
        for phase in ("INPUT", "ROUND_IN_FLIGHT", "AWAITING_PLANT", "RECORDING_STEP"):
            history.event(phase, .1, step)
            expected_events.append({"phase": phase, "duration_ms": .1, "attempt": step})
    expanded = history.expand()
    assert expanded == {"steps": expected_steps, "events": expected_events, "cycles": expected_cycles}
    assert struct.pack('>d', expanded['steps'][0]['duration_ms']) == struct.pack('>d', -0.0)
    assert buffers == {k: (id(t.buffer), len(t.buffer), len(t.fields)) for k, t in history.tables.items()}
    assert history.report()["representation_complete"] and history.report()["layout"]["reserved_bound_bytes"] <= 16*1024**2
    assert sum(bench._CompactHistory.layout(r)["reserved_bound_bytes"] for r in ("Client", "P1", "P2")) <= 48*1024**2

    for role in ("P1", "P2"):
        party = bench._CompactHistory(role, 1)
        request = SimpleNamespace(step=2**53+7, round_id="原始公开身份")
        party.party_step(request, activity, before, counts, {})
        assert party.expand()["steps"] == [{"step": request.step, "round_id": request.round_id,
                                            "activity_ms": activity, "sent": counts}]


def test_s13_corrupt_or_partial_expansion_reports_valid_prefix_and_preserves_other_tables(monkeypatch):
    from secure_control.experiments import communication_benchmark as bench

    history = bench._CompactHistory("Client", 2)
    history.event("INPUT", 0., None)
    history.event("RUNNING", 1., 0)
    table = history.tables["events"]
    table.buffer[table.row_bytes] = 3
    expanded = history.expand()
    assert expanded["events"] == [{"phase": "INPUT", "duration_ms": 0., "attempt": None}]
    assert table.count == 2 and table.expanded_count == 1 and table.expansion_error_type == "ValueError"
    assert not history.report()["representation_complete"]
    def failed():
        raise OSError("private expansion message")
    monkeypatch.setattr(history.tables["cycles"], "expand", failed)
    assert history.expand()["cycles"] == [] and history.error_type == "OSError"
    assert "private" not in str(history.report())


def test_s13_guard_and_cli_reject_conflicts_before_resources(tmp_path, monkeypatch):
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_runner

    def forbidden(*args, **kwargs):
        pytest.fail("软件guard不得启动候选或端口")
    monkeypatch.setattr(bench, "_ports", forbidden)
    monkeypatch.setattr(bench, "_run_material_comparison", forbidden)
    base = {"steps": 4000, "delay_ms": 0, "segment_steps": 400, "optimized": True, "recording_mode": "light",
            "compact_history_candidate": True}
    for change in ({"compact_history_candidate": 1}, {"stage_wait_diagnostic": True}, {"server_gc_candidate": True},
            {"worker_wait_diagnostic": True}, {"worker_long_run": True}, {"worker_timeout_diagnostic": True},
            {"gc_trial_policy": "baseline"}, {"timeout_trace": True}, {"material_candidate": "worker"},
            {"diagnostic": True}, {"steps": 20}, {"steps": 4000.}, {"segment_steps": True},
            {"material_slots": 4}, {"preload_steps": 16}, {"preload_execution": "staged"}, {"role_config": "other"},
            {"tcp_nodelay": False}, {"commit_policy": "serial"}, {"recording_mode": "full"},
            {"optimized": False}, {"delay_ms": False}):
        with pytest.raises((ValueError, TypeError)):
            bench.run_continuous_observation(**(base | change))
    calls = []
    monkeypatch.setattr(bench, "run_continuous_observation", lambda **kw:
        calls.append(kw) or {"status": "stopped", "cycle_timing": {"p50_ms": 1.}})
    args = ["secure-control", "benchmark", "--compact-history-candidate", "--steps", "4000",
            "--recording", "light", "--output", str(tmp_path / "raw.json")]
    for route in (["--case", "dynamic"], ["--case", "cycle", "--mode", "legacy"], ["--case", "full-observation"]):
        monkeypatch.setattr("sys.argv", args+route)
        assert lan_runner._run() == 5 and not calls and not (tmp_path / "raw.json").exists()
    monkeypatch.setattr("sys.argv", args+["--case", "cycle", "--mode", "batch"])
    assert lan_runner._run() == 0 and calls[0]["compact_history_candidate"] is True
    assert calls[0]["stage_wait_diagnostic"] is False


def test_s13_thread_registry_uses_only_original_factory_identity_and_observed_lifetime(monkeypatch):
    from secure_control.experiments import communication_benchmark as bench

    stamp = [10]
    monkeypatch.setattr(bench.time, "perf_counter_ns", lambda: stamp[0])
    history = bench._CompactHistory("Client", 1)
    alive = [True]
    pool = SimpleNamespace(_receiver=SimpleNamespace(native_id=111, ident=222, is_alive=lambda: alive[0]),
        _notifier=SimpleNamespace(native_id=333, ident=444, is_alive=lambda: alive[0]))
    history.worker_threads(pool)
    stamp[0], alive[0] = 100, False
    history.worker_threads(pool, ending=True)
    history.expand()
    registry = history.report()["threads"]
    assert [(r["thread_role"], r["native_id"]) for r in registry][1:] == [("material-receiver", 111), ("material-credit", 333)]
    assert all(r["registered_at_qpc_ns"] == 10 and r["observation_end_qpc_ns"] == 100 for r in registry)
    assert [r["alive_at_observation_end"] for r in registry] == [True, False, False]
    assert all(pool is not value and pool._receiver is not value for value in history.__dict__.values())
    with pytest.raises(RuntimeError):
        history.worker_threads(pool)


def _check_history_real_callbacks(monkeypatch, fault, *, qpc=False):
    from secure_control.execution import lan_runtime
    from secure_control.execution.cycle_timing import (
        AbsoluteCycleClock,
        CycleTiming,
        check_deadline,
    )
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_continuous_profile, lan_runner
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    prepared = lan_continuous_profile.load_segmented_experiment(
        bench._config("Client", (101, 102, 103)).experiment_config, 400, InteractiveSession())
    original_runner = lan_runner._run_prepared_segmented
    original_replace = bench.replace
    original_asdict = bench.asdict
    def exercise(compact):
        with monkeypatch.context() as patcher:
            now, samples = [2**53+17], [0]
            captured_history, gc_events, stop_entries, runner_results = [], [], [], []
            continuing = [False]
            original_cycle = bench._CompactHistory.cycle
            class Runtime:
                def __init__(self, *args, **kwargs):
                    self.phase, self.run_id = "RUNNING", "run"
                    self.confirmed_step_count = self.protocol_committed_count = 0
                    self.resource_counts = {"products_consumed": 0, "truncations_consumed": 0}
                    self.public_setup = None
                    self.cycle_phase_ns, self.cycle_queue_levels = {}, {}
                    self.segment = SimpleNamespace(_material_pool=None, _sockets=[], _preloaded=None)
                def snapshot(self):
                    n = self.confirmed_step_count
                    return lan_runtime.LanLifecycleSnapshot(self.phase, "run", "session", "epoch", 0, 0,
                        n, f"round-{n}", self.protocol_committed_count, n, 30*n, 4*n, 0)
                @property
                def segment_full(self):
                    return fault == "maintenance" and self.confirmed_step_count == 2 and not continuing[0]
                def end_segment(self, **kwargs):
                    now[0] += 1000
                    if kwargs.get("deadline_ns") is None:
                        self.phase = "STOPPED"
                    return lan_runtime.SegmentRecord(None, "session", (), (), None, 0., None, None, None)
                def next_segment(self, **kwargs):
                    continuing[0] = True
                def step(self, value, **kwargs):
                    n = self.confirmed_step_count
                    if n == 2 and fault == "transport":
                        self.phase = "UNCERTAIN"
                        raise OSError("private protocol failure")
                    self.protocol_committed_count += 1
                    return SimpleNamespace(global_step=n, raw_control=(0.,), round_id=f"round-{n}",
                                           segment_index=0, session_id="session")
                def enable_material_preparation(self, **kwargs):
                    assert kwargs == {"slots": 16, "_candidate": "worker"}
                def _begin_material_control(self):
                    pass
                def confirm_applied(self, identity):
                    self.confirmed_step_count += 1
                    self.resource_counts = {"products_consumed": 30*self.confirmed_step_count,
                                            "truncations_consumed": 4*self.confirmed_step_count}
                def close(self):
                    lan_runtime.LanContinuousRuntime.close(self.segment)
            def controller_input():
                n = samples[0]
                samples[0] += 1
                now[0] += 21000000 if n == 2 and fault == "input" else 1000
                return [0.]
            def advance(*args, **kwargs):
                now[0] += 1000
                return {}
            scene = SimpleNamespace(period=.02, controller_input=controller_input, advance=advance,
                                    terminal_summary=dict)
            def runner(*args, **kwargs):
                callback = kwargs["on_cycle"]
                original_phase = kwargs["phase"]
                def phase(name):
                    if name == "STOPPING":
                        stop_entries.append(now[0])
                    original_phase(name)
                    if name == "ENDING_SEGMENT":
                        assert not captured_history or captured_history[0].normal_stop_start_qpc_ns is None
                    if name == "STOPPING":
                        assert not compact or captured_history[0].normal_stop_start_qpc_ns == now[0]
                        gc_events.append((now[0]+1, now[0]+500, 1, 2, 0, 0))
                        now[0] += 1000
                def cycle(timing):
                    callback(timing)
                    if timing.global_step == 2 and fault == "after_apply":
                        now[0] += 20000000  # 原runner的回调后期限检查/唯一尾部校正。
                    if timing.global_step == 2 and fault in ("stop", "maintenance", "callback_gc"):
                        kwargs["control"].request_stop()
                result = original_runner(*args, **(kwargs | {"on_cycle": cycle, "phase": phase}))
                runner_results.append(result)
                return result
            def history_cycle(self, timing, counts, before):
                if not captured_history:
                    captured_history.append(self)
                if fault in ("callback_gc", "callback_miss"):
                    gc_events.append((now[0]+1, now[0]+500, 1, 2, 0, 0))
                    now[0] += 20000000 if fault == "callback_miss" and timing.global_step == 2 else 1000
                return original_cycle(self, timing, counts, before)
            def no_asdict(value):
                assert not isinstance(value, CycleTiming)
                return original_asdict(value)
            def no_timing_replace(value, **kwargs):
                assert not isinstance(value, CycleTiming)
                return original_replace(value, **kwargs)
            context = SimpleNamespace(Queue=lambda: SimpleNamespace(close=lambda: None),
                Process=lambda **kwargs: SimpleNamespace(start=lambda: None, join=lambda **kwargs: None,
                                                         is_alive=lambda: False))
            patcher.setattr(bench.mp, "get_context", lambda method: context)
            patcher.setattr(bench, "_party_outcomes", lambda queue: [{"role": r, "directions": {}} for r in ("P1", "P2")])
            patcher.setattr(bench, "_ports", lambda: (101, 102, 103))
            patcher.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 1024})
            patcher.setattr(lan_runner, "LanSegmentedRuntime", Runtime)
            patcher.setattr(lan_runner, "_run_prepared_segmented", runner)
            patcher.setattr(bench.time, "perf_counter_ns", lambda: now[0])
            patcher.setattr(lan_runner, "perf_counter_ns", lambda: now[0])
            patcher.setattr(lan_runner, "AbsoluteCycleClock", lambda period:
                AbsoluteCycleClock(period, now=lambda: now[0], sleep=lambda seconds:
                                   now.__setitem__(0, now[0]+round(seconds*1e9))))
            patcher.setattr(lan_runner, "check_deadline", lambda deadline, phase:
                check_deadline(deadline, phase, now=lambda: now[0]))
            patcher.setattr(lan_runner.gc, "collect", lambda generation: 0)
            patcher.setattr(lan_continuous_profile, "load_segmented_experiment", lambda *args: replace(prepared, scene=scene))
            before = _s12_hook_snapshot()
            if compact:
                patcher.setattr(bench, "asdict", no_asdict)
                patcher.setattr(bench, "replace", no_timing_replace)
                patcher.setattr(bench._CompactHistory, "cycle", history_cycle)
            result = bench.run_continuous_observation(steps=1000 if qpc and compact else 4000,
                delay_ms=0, segment_steps=400, optimized=True, recording_mode="light",
                **({"qpc_stage_receive_candidate" if qpc else "compact_history_candidate": True}
                    if compact else {"stage_wait_diagnostic": True}))
            assert _s12_hook_snapshot() == before and samples[0] == 3
            assert len(result["cycles"]) == 3 and not result["qualification_pass"]
            successful = fault in ("stop", "maintenance", "callback_gc")
            if successful:
                assert runner_results[0]["status"] == "stopped" and result["failed_attempts"] == 0 and len(stop_entries) == 1
                # 未启动真实角色的fixture缺少其报告，不能获得实际候选完整门禁。
                assert result["failure_category"] == "StageWaitObservation"
                if fault == "maintenance":
                    assert continuing[0] and "maintenance" in result["cycles"][1]["phase_durations_ns"]
            else:
                assert result["cycles"][-1]["cycle_completed_ns"] is None
                assert result["failure_category"] == ("OSError" if fault == "transport" else "CycleDeadlineExceeded")
                assert result["failed_attempts"] == 1
            if fault in ("after_apply", "callback_miss"):
                assert result["cycles"][-1]["status"] == "miss_after_apply"
                assert result["failed_phase"] == "CYCLE_OBSERVATION" and len(result["steps"]) == 3
            if compact:
                meta = result["qpc_stage_receive_candidate" if qpc else "compact_history_candidate"]
                assert meta["invocation_budget_consumed"] and not meta["finite_sample_pass"]
                assert meta["roles"][0]["tables"]["cycles"]["captured"] == 3
                if qpc:
                    assert meta["roles"][0]["layout"]["tables"]["cycles"]["capacity"] == 1001
                boundary = meta["control_observation_boundary"]
                assert boundary["control_boundary_valid"]
                assert boundary["last_confirmed_step"] == (2 if successful or fault in ("after_apply", "callback_miss") else 1)
                assert boundary["normal_stop_start_qpc_ns"] == (stop_entries[0] if successful else None)
                if fault == "callback_gc":
                    assert all(e[1] <= boundary["confirmed_observation_end_qpc_ns"] for e in gc_events[:-1])
                    assert result["cycles"][-1]["cycle_completed_ns"] < gc_events[-2][0]
            return {k: result[k] for k in ("steps", "events", "cycles", "cycle_summary",
                "failure_category", "failed_phase", "successful_steps", "failed_attempts",
                "protocol_committed_count", "physically_confirmed_count", "resource_counts")}
    if fault in ("callback_gc", "callback_miss"):
        exercise(True)  # 真实on_cycle内注入公开虚拟GC时段，不启动角色或主动GC。
    else:
        assert exercise(False) == exercise(True)


@pytest.mark.parametrize("fault", ("input", "transport", "after_apply", "stop", "maintenance", "callback_gc", "callback_miss"))
def test_s13_real_callbacks_match_original_and_canonical_late_tail_without_live_roles(monkeypatch, fault):
    _check_history_real_callbacks(monkeypatch, fault)


@pytest.mark.parametrize("fault", ("input", "transport", "after_apply"))
def test_s15_real_runner_preserves_failure_prefix_and_observation_deadline(monkeypatch, fault):
    _check_history_real_callbacks(monkeypatch, fault, qpc=True)


def test_s13_role_export_failure_keeps_original_control_error_and_restores_hooks(monkeypatch):
    from secure_control.experiments import communication_benchmark as bench

    def run(*args, **kwargs):
        raise OSError("private control failure")
    def expand(self):
        raise ValueError("private export failure")
    monkeypatch.setattr(bench, "run_party_single_step", run)
    monkeypatch.setattr(bench._CompactHistory, "expand", expand)
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 1024})
    for role in ("P1", "P2"):
        before = _s12_hook_snapshot()
        queue = Queue()
        bench._party_job(SimpleNamespace(role=role), (101, 102, 103), 0, True, queue,
            material_comparison=True, stage_wait_diagnostic=True, compact_history_candidate=True)
        result = queue.get_nowait()
        assert result["error_type"] == "OSError" and result["status"] == "failed"
        assert result["compact_history"]["error_type"] == "ValueError"
        assert not result["compact_history"]["representation_complete"] and "private" not in str(result)
        assert _s12_hook_snapshot() == before


def test_s13_finite_sample_is_independent_of_gc_coverage_and_rejects_bad_evidence():
    from copy import deepcopy

    from secure_control.experiments import communication_benchmark as bench

    initial, numeric = _s11_public_result()
    initial["steps"] = [{"global_step": c["global_step"], "session_id": c["session_id"],
        "round_id": c["round_id"], "status": "confirmed"} for c in initial["cycles"]]
    initial["numeric_profile"] = {"fractional_bits": 32, "security_parameter": 80, "period_s": .02,
        "modulus_bits": 256, "state_dimension": 4, "input_dimension": 2, "output_dimension": 1}
    sample = {"memory_guard_failed": False, "cleanup_failed": False, "producer_exited": True}
    def history_report(role):
        threads = []
        for name, native in (("control", 1), ("material-receiver", 99), ("material-credit", 100)):
            if role != "Client" and name != "control":
                continue
            threads.append({"thread_role": name, "pid": 10, "native_id": native,
                "registered_at_qpc_ns": 0, "observation_end_qpc_ns": 80000000000})
        return {"role": role, "representation_complete": True, "layout": {"reserved_bound_bytes": 100},
            "tables": {k: {"captured": 4000, "expanded": 4000} for k in ("steps", "cycles")}, "threads": threads}
    for fault in ("normal", "covered", "normal_stop", "missing", "overflow", "thread", "numeric", "phase", "bad_stop",
                  "bool", "missing_step", "missing_capture", "control", "partial_commit", "cleanup"):
        result, report = deepcopy(initial), dict(sample)
        client = history_report("Client")
        last = result["cycles"][-1]
        observed_end = last["cycle_completed_ns"] + 10
        client["control_observation"] = {"last_confirmed_step": 3999,
            "last_confirmed_return_qpc_ns": observed_end, "normal_stop_start_qpc_ns": observed_end + 10}
        observer = _s12_software_observer("Client")
        if fault == "covered":
            observer.gc_observer.slots[0] = (100, 200, 99, 2, 0, 0)
            observer.gc_observer.count = 1
        elif fault == "normal_stop":
            assert observed_end + 40 < last["deadline_ns"]
            observer.gc_observer.slots[0] = (observed_end + 20, observed_end + 30, 1, 2, 0, 0)
            observer.gc_observer.count = 1
        for party in result["party_outcomes"]:
            party.pop("server_gc")
            stage = _s12_software_observer(party["role"])
            stage.gc_observer.normal_stop_ack_sent = True
            party["stage_wait"] = stage.report()
            party["compact_history"] = history_report(party["role"])
        if fault == "missing":
            result["party_outcomes"][0].pop("compact_history")
        elif fault == "overflow":
            client["representation_complete"] = False
        elif fault == "thread":
            client["threads"][1]["native_id"] = None
        elif fault == "phase":
            result["cycles"][799].pop("phase_durations_ns")
        elif fault == "bad_stop":
            result["party_outcomes"][0]["stage_wait"]["gc"]["normal_stop_ack_sent"] = False
        elif fault == "bool":
            result["cycles"][0]["global_step"] = False
        elif fault == "missing_step":
            result["steps"].pop()
        elif fault == "missing_capture":
            client["tables"]["cycles"]["captured"] = 3999
        elif fault == "partial_commit":
            result["last_commit_observation"]["parties"]["P2"]["valid_ack_received"] = False
        elif fault == "control":
            result.update(status="uncertain", failure_category="OSError", failed_phase="ROUND_IN_FLIGHT", failed_attempts=1)
        elif fault == "cleanup":
            report["cleanup_failed"] = True
        meta = deepcopy(numeric)
        if fault == "numeric":
            meta["numeric_contract"]["runtime_payload_bits"] = 45
        bench._finish_stage_wait(result, report, meta, [observer])
        original_cycles = result["cycles"]
        bench._finish_compact_history(result, report, SimpleNamespace(expansion_ns=1, report=lambda client=client: client))
        compact = result["compact_history_candidate"]
        assert compact["finite_sample_pass"] == (fault in ("normal", "covered", "normal_stop")), fault
        assert compact["runtime_gen2_coverage"]["Client"] == (fault == "covered")
        if fault == "covered":
            assert compact["gc_thread_matches"][0]["thread_role"] == "material-receiver"
        assert result["cycles"] is original_cycles
        assert result["diagnostic"] and result["comparison_only"]
        assert not any(result[k] for k in ("server_gc_candidate_gate_pass", "candidate_gate_pass", "worker_long_run_gate_pass",
                                           "stage_pass", "qualification_pass"))
        if fault == "control":
            assert result["failure_category"] == "OSError" and result["failed_phase"] == "ROUND_IN_FLIGHT"


@pytest.mark.parametrize("case", ("control", "callback", "stop", "startup", "touch_start", "touch_end",
    "cross_start", "cross_end", "gap", "cross_stop", "missing", "no_cycles", "wrong_step", "bool",
    "reverse", "late_stop", "pending", "evicted", "unpaired", "omitted", "disabled", "unknown_thread",
    "failed_io", "stop_io"))
def test_rv003_gc_classification_retains_unknown_and_never_extends_to_cleanup(case):
    from copy import deepcopy

    from secure_control.experiments import communication_benchmark as bench

    cycles = [{"global_step": 0, "scheduled_start_ns": 100, "cycle_completed_ns": 800,
               "deadline_ns": 2000, "status": "confirmed"}]
    boundary = {"last_confirmed_step": 0, "last_confirmed_return_qpc_ns": 900,
                "normal_stop_start_qpc_ns": 1000}
    event = {"startup": (10, 90), "touch_start": (100, 200), "touch_end": (800, 900),
             "cross_start": (90, 110), "cross_end": (890, 910), "gap": (920, 950),
             "cross_stop": (990, 1010), "stop": (1100, 1200), "callback": (810, 850),
             "stop_io": (1100, 1200), "failed_io": (1100, 1200)}.get(case, (200, 300))
    observer = _s12_software_observer("Client")
    gc_record = observer.gc_observer
    gc_record.slots[0], gc_record.count = (*event, 1, 2, 0, 0), 1
    if case in ("pending", "evicted", "unpaired"):
        setattr(gc_record, {"pending": "pending", "evicted": "evicted", "unpaired": "unpaired"}[case],
                (400, 1) if case == "pending" else 1)
    stage_role = observer.report()
    if case == "omitted":
        stage_role["gc"]["encoded_omitted"] = 1
    if case == "disabled":
        stage_role["gc"]["gc_after"]["enabled"] = False
    if case == "missing":
        boundary.pop("last_confirmed_return_qpc_ns")
    elif case == "no_cycles":
        cycles.clear()
    elif case == "wrong_step":
        boundary["last_confirmed_step"] = 1
    elif case == "bool":
        boundary["last_confirmed_return_qpc_ns"] = True
    elif case == "reverse":
        boundary["normal_stop_start_qpc_ns"] = 899
    elif case == "late_stop":
        boundary["normal_stop_start_qpc_ns"] = 5001
    if case == "failed_io":
        boundary["normal_stop_start_qpc_ns"] = None
        cycles.append({"global_step": 1, "scheduled_start_ns": 1050, "deadline_ns": 3050,
                       "cycle_completed_ns": None, "status": "miss_before_apply"})
    if case in ("failed_io", "stop_io"):
        stage_role["first_failure"] = ["frame_recv", 1100, 1300]  # 不用未核验首错延长窗口。
    threads = [{"thread_role": "control", "pid": 10, "native_id": 99 if case == "unknown_thread" else 1,
                "registered_at_qpc_ns": 0, "observation_end_qpc_ns": 5000}]
    history = {"role": "Client", "threads": threads, "control_observation": boundary}
    complete = case not in ("pending", "evicted", "unpaired", "omitted", "disabled")
    result = {"status": "uncertain", "failure_category": "OSError", "failed_phase": "ROUND_IN_FLIGHT",
              "cycles": cycles, "stage_wait_diagnostic": {"roles": [stage_role], "evidence_complete": complete}}
    original = deepcopy(result)
    bench._finish_compact_history(result, {}, SimpleNamespace(expansion_ns=1, report=lambda: history))
    meta = result["compact_history_candidate"]
    known = case in ("control", "callback", "touch_start", "touch_end", "unknown_thread")
    assert meta["runtime_gen2_coverage"]["Client"] == known
    match = meta["gc_thread_matches"][0]
    expected = ("control" if known or not complete else "normal_stop" if case in ("stop", "stop_io")
                else "outside" if case == "startup" else "overlap_or_unknown")
    assert match["classification"] == expected
    assert match["thread_role"] == (None if case == "unknown_thread" else "control")
    assert result["cycles"] == original["cycles"] and result["stage_wait_diagnostic"] == original["stage_wait_diagnostic"]
    assert result["failure_category"] == "OSError" and result["failed_phase"] == "ROUND_IN_FLIGHT"
    assert not meta["finite_sample_pass"] and not result["qualification_pass"]


def test_s13_initialization_failure_does_not_start_roles_and_restores_factory(monkeypatch):
    from secure_control.execution import lan_runtime
    from secure_control.experiments import communication_benchmark as bench

    before = _s12_hook_snapshot()
    factory = lan_runtime._MaterialWorkerPool.__init__
    def forbidden(*args, **kwargs):
        pytest.fail("初始化失败不得启动端口或角色")
    monkeypatch.setattr(bench, "_ports", forbidden)
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 257*1024**2})
    result = bench.run_continuous_observation(steps=4000, delay_ms=0, segment_steps=400,
        optimized=True, recording_mode="light", compact_history_candidate=True)
    assert result["failure_category"] == "RuntimeError" and result["cycles"] == []
    assert result["compact_history_candidate"]["actual_attempts"] == 0
    assert not result["compact_history_candidate"]["finite_sample_pass"]
    assert result["compact_history_candidate"]["invocation_budget_consumed"]
    assert _s12_hook_snapshot() == before and lan_runtime._MaterialWorkerPool.__init__ is factory


def test_s17_qualification_guard_layout_and_cli_never_start_unapproved_routes(monkeypatch, tmp_path):
    import sys
    from pathlib import Path

    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_runner

    common = {"steps": 10000, "delay_ms": 0, "segment_steps": 400, "optimized": True,
              "material_slots": 16, "recording_mode": "light", "qpc_dynamic_qualification": True}
    def forbidden(*args, **kwargs):
        pytest.fail("软件门禁不得打开端口或启动资格")
    monkeypatch.setattr(bench, "_ports", forbidden)
    for changes in ({"steps": 1000}, {"steps": True}, {"qpc_dynamic_qualification": 1},
                    {"qpc_stage_receive_candidate": True}, {"compact_history_candidate": True},
                    {"worker_long_run": True}, {"preload_steps": 1}, {"material_slots": 4},
                    {"recording_mode": "full"}, {"delay_ms": 1}, {"role_config": Path("unused.yaml")}):
        with pytest.raises((ValueError, TypeError)):
            bench.run_continuous_observation(**(common | changes))
    layouts = {r: bench._CompactHistory.layout(r, 10000, qualification=True) for r in ("Client", "P1", "P2")}
    assert [layouts[r]["reserved_bound_bytes"] for r in ("Client", "P1", "P2")] == [31159895, 3894625, 3894625]
    assert sum(x["reserved_bound_bytes"] for x in layouts.values()) == 38949145
    assert layouts["Client"]["limit_bytes"] == 32*1024**2 and layouts["P1"]["limit_bytes"] == 16*1024**2
    with pytest.raises(ValueError):
        bench._CompactHistory.layout("Client", 10000)
    with pytest.raises(ValueError):
        bench._CompactHistory.layout("Client", 1000, qualification=True)
    captured = []
    def selected(options, candidate, *, target_steps):
        captured.append((options, candidate, target_steps))
        return {"status": "stopped", "cycle_timing": {"p50_ms": 0}}
    monkeypatch.setattr(bench, "_run_material_comparison", selected)
    result = bench.run_continuous_observation(**common)
    assert result["status"] == "stopped" and captured[0][1:] == ("worker", 10000)
    assert captured[0][0]["qpc_dynamic_qualification"] is True
    monkeypatch.setattr(sys, "argv", ["secure-control", "benchmark", "--case", "cycle", "--mode", "batch",
        "--steps", "10000", "--delay-ms", "0", "--segment-steps", "400", "--material-slots", "16",
        "--preload-steps", "0", "--recording", "light", "--qpc-dynamic-qualification", "--output", str(tmp_path/"software.json")])
    assert lan_runner._run() == 0 and len(captured) == 2


def test_s17_qualification_preallocation_failure_never_launches_roles(monkeypatch):
    from secure_control.experiments import communication_benchmark as bench

    before = _s12_hook_snapshot()
    monkeypatch.setattr(bench, "_ports", lambda: pytest.fail("RSS guard后不得建端口"))
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 257*1024**2})
    result = bench.run_continuous_observation(steps=10000, delay_ms=0, segment_steps=400,
        optimized=True, recording_mode="light", qpc_dynamic_qualification=True)
    assert result["cycles"] == [] and result["failure_category"] == "RuntimeError"
    assert not result["local_dynamic_qualification_pass"] and not result["qpc_dynamic_qualification"]["finite_sample_pass"]
    assert result["stage_wait_diagnostic"]["profile"] == "canonical-qpc-receive-v1"
    assert _s12_hook_snapshot() == before


def test_s17_qualification_gate_requires_full_10000_route_layout_and_24_maintenance():
    """纯公开fixture/布局，无端口/材料/控制；拒绝不完整资格，不改旧oracle。"""
    from copy import deepcopy

    from secure_control.experiments import communication_benchmark as bench

    base = _s9_public_result()
    _, metadata = _s11_public_result()
    metadata.update(profile="canonical-qpc-receive-v1", target_steps=10000, maximum_attempts=10000)
    base.pop("worker_long_run")
    base["numeric_profile"] = {"fractional_bits": 32, "security_parameter": 80, "period_s": .02,
        "modulus_bits": 256, "state_dimension": 4, "input_dimension": 2, "output_dimension": 1}
    base["steps"] = [{"global_step": c["global_step"], "session_id": c["session_id"],
        "round_id": c["round_id"], "status": "confirmed"} for c in base["cycles"]]
    for step in range(399, 9999, 400):
        base["cycles"][step]["phase_durations_ns"] = {"maintenance": 1}
    def history_report(role):
        end = base["cycles"][-1]["deadline_ns"]+100
        return {"role": role, "representation_complete": True,
            "layout": bench._CompactHistory.layout(role, 10000, qualification=True),
            "tables": {k: {"captured": 10000, "expanded": 10000} for k in ("steps", "cycles")},
            "threads": [{"thread_role": name, "pid": 10, "native_id": i,
                "registered_at_qpc_ns": 0, "observation_end_qpc_ns": end}
                for i, name in enumerate(("control", "material-receiver", "material-credit"), 1)
                if role == "Client" or name == "control"],
            "control_observation": {"last_confirmed_step": 9999,
                "last_confirmed_return_qpc_ns": base["cycles"][-1]["cycle_completed_ns"]+1,
                "normal_stop_start_qpc_ns": base["cycles"][-1]["cycle_completed_ns"]+2}}
    sample = {"memory_guard_failed": False, "cleanup_failed": False, "producer_exited": True}
    for fault in ("normal", "partial_route", "profile", "layout", "maintenance", "late", "restore", "float_route", "missing_history"):
        result, numeric = deepcopy(base), deepcopy(metadata)
        observer = bench._StageWaitDiagnostic("Client", (101, 102, 103),
            gc_observer=_s12_software_observer("Client").gc_observer,
            qpc_receive_candidate=True, all_qpc_receives=True)
        observer.trace_restored = True
        observer.qpc_calls = observer.qpc_completed = 120192
        for party in result["party_outcomes"]:
            stage = _s12_software_observer(party["role"])
            stage.gc_observer.normal_stop_ack_sent = True
            party["stage_wait"], party["compact_history"] = stage.report(), history_report(party["role"])
        client_history = history_report("Client")
        if fault == "partial_route":
            observer.qpc_completed -= 1
        elif fault == "profile":
            numeric["profile"] = "stage-wait-light-v1"
        elif fault == "layout":
            client_history["layout"]["limit_bytes"] = 16*1024**2
        elif fault == "maintenance":
            result["cycles"][9599].pop("phase_durations_ns")
        elif fault == "late":
            result["cycles"][0]["cycle_completed_ns"] = result["cycles"][0]["deadline_ns"]
        elif fault == "restore":
            observer.qpc_restore_error_type = "OSError"
        elif fault == "float_route":
            observer.qpc_calls = 120192.
        elif fault == "missing_history":
            result["party_outcomes"][0].pop("compact_history")
        bench._finish_stage_wait(result, sample, numeric, [observer])
        history = SimpleNamespace(expansion_ns=1, report=lambda client_history=client_history: client_history)
        bench._finish_compact_history(result, sample, history, qpc_dynamic_qualification=True)
        assert result["local_dynamic_qualification_pass"] == (fault == "normal"), fault
        assert result["qpc_dynamic_qualification"]["target_steps"] == 10000
        assert not any(result[k] for k in ("candidate_gate_pass", "worker_long_run_gate_pass", "stage_pass", "qualification_pass"))


def test_s17_all_cycle_reply_observation_delegates_same_canonical_algorithm(monkeypatch):
    from secure_control.execution import localhost_transport as transport

    original, calls = transport._receive_qpc_exact, []
    def delegated(sock, length, deadline, **kwargs):
        calls.append((sock, length, deadline, kwargs.get("_observe")))
        return original(sock, length, deadline, **kwargs)
    monkeypatch.setattr(transport, "_receive_qpc_exact", delegated)
    for phase in (None, "online_reply", "finish_stage_batch"):
        f = _s15_receive_fixture(monkeypatch, [b"data"], all_qpc_receives=True,
                                 waits=[(3000000, "empty"), (4000000, "ready")])
        f.observer.state.phase = phase
        assert f.observer.qpc_receive(f.original, f.probe, 4, f.deadline) == b"data"
        assert f.observer.qpc_calls == f.observer.qpc_completed == 1 and f.observer.qpc_empty == 1
        assert f.observer.report()["profile"] == "canonical-qpc-receive-v1" and f.raw.timeout == .5
        assert calls[-1][:3] == (f.probe, 4, f.deadline) and callable(calls[-1][3])
    assert len(calls) == 3
    assert f.observer.qpc_receive(lambda *args: b"legacy", f.probe, 4, 1.0) == b"legacy"
    assert len(calls) == 3
    failure = OSError(9, "private select error")
    f = _s15_receive_fixture(monkeypatch, [BlockingIOError()], all_qpc_receives=True,
                             waits=[(1000000, "ready"), (1000000, failure)])
    with pytest.raises(transport.LocalhostTransportDisconnected) as caught:
        f.observer.qpc_receive(f.original, f.probe, 4, f.deadline)
    assert caught.value.__cause__ is failure and f.raw.read_lengths == [4] and f.raw.timeout == .5
    assert f.observer.first_failure[17] == "qpc_select" and f.observer.first_failure[11] is None


def test_s15_early_empty_continues_same_frame_under_original_deadline(monkeypatch):
    f = _s15_receive_fixture(monkeypatch, [b"test"], waits=[(3000000, "empty"), (4000000, "ready")])
    assert f.observer.qpc_receive(f.original, f.probe, 4, f.deadline) == b"test"
    assert f.raw.read_lengths == [4] and f.raw.timeout == .5 and [r[1] for r in f.selected] == [.011, .008]
    report = f.observer.report()
    assert report["profile"] == "qpc-stage-receive-v1" and report["qpc_receive"]["empty_count"] == 1
    assert report["qpc_receive"]["completed_exact_calls"] == 1
    assert report["qpc_receive"]["first_exception"] is None


def _s15_receive_fixture(monkeypatch, chunks, *, deadline_ns=11000000, waits=(), restore_error=None,
                         recv_delay_ns=0, restore_delay_ns=0, all_qpc_receives=False):
    """可控时钟/假裸socket，只调用真实观察与framing，不打开网络或执行控制。"""
    from secure_control.execution.cycle_timing import _CycleDeadline
    from secure_control.experiments import communication_benchmark as bench

    now, selected, remaining_chunks, remaining_waits = [0], [], list(chunks), list(waits)
    class RawSocket:
        def __init__(self):
            self.timeout, self.read_lengths, self.mode_changes = .5, [], []
        def gettimeout(self):
            return self.timeout
        def getpeername(self):
            return "127.0.0.1", 101
        def getsockname(self):
            return "127.0.0.1", 9000
        def settimeout(self, value):
            self.mode_changes.append(value)
            if value == .5:
                now[0] += restore_delay_ns
                if restore_error is not None:
                    raise restore_error
            self.timeout = value
        def recv(self, length):
            assert self.timeout == 0
            self.read_lengths.append(length)
            now[0] += recv_delay_ns
            assert remaining_chunks, "不能重读/重发或超出批准的同一frame数据"
            value = remaining_chunks.pop(0)
            if isinstance(value, BaseException):
                raise value
            assert len(value) <= length
            return value
        def send(self, *args):
            pytest.fail("候选接收不得重发事务")
    raw = RawSocket()
    def ready(read, write, errors, timeout):
        assert len(read) == 1 and read[0].sock is raw and not write and not errors and timeout > 0 and raw.timeout == 0
        selected.append((now[0], timeout))
        delta, kind = remaining_waits.pop(0) if remaining_waits else (1000000, "ready")
        now[0] += delta
        if isinstance(kind, BaseException):
            raise kind
        return (read if kind == "ready" else [], [], [])
    monkeypatch.setattr(bench.socket, "socket", RawSocket)
    from secure_control.execution import localhost_transport

    monkeypatch.setattr(localhost_transport.select, "select", ready)
    monkeypatch.setattr(bench.time, "perf_counter_ns", lambda: now[0])
    observer = bench._StageWaitDiagnostic("Client", (101, 102, 103), qpc_receive_candidate=True,
                                         all_qpc_receives=all_qpc_receives)
    context = ("expected_from_validated_stage_plan", "Client", "P1", "stage", None,
               "session", "round", 0, 1, "run", "epoch", 0, 0)
    observer.state.phase, observer.state.context = "finish_stage_batch", context
    probe = bench._StageTraceSocket(raw, observer, "P1")
    probe.context = ("expected_from_last_request", "Client", "P1", "endpoint", "stage_batch", *context[5:])
    probe.direction, probe.part, probe.deadline = "P1->Client", "header", _CycleDeadline(deadline_ns)
    probe.frame_requested = 4
    def forbidden(*args):
        pytest.fail("选择当前候选后不能回退原生timeout循环")
    return SimpleNamespace(now=now, raw=raw, observer=observer, probe=probe, deadline=probe.deadline,
                           selected=selected, original=forbidden, remaining_chunks=remaining_chunks)


@pytest.mark.parametrize("case", ("expired", "select_equal", "select_late", "recv_equal", "recv_late", "restore_equal"))
def test_s15_original_deadline_checked_before_after_wait_read_and_restore(monkeypatch, case):
    from secure_control.execution.localhost_transport import LocalhostTransportTimeout

    waits = [(11000000 if case == "select_equal" else 12000000, "ready")] if case.startswith("select") else ()
    f = _s15_receive_fixture(monkeypatch, [b"data"], waits=waits,
        recv_delay_ns=10000000 if case == "recv_equal" else 11000000 if case == "recv_late" else 0,
        restore_delay_ns=10000000 if case == "restore_equal" else 0)
    if case == "expired":
        f.now[0] = 11000000
    with pytest.raises(LocalhostTransportTimeout):
        f.observer.qpc_receive(f.original, f.probe, 4, f.deadline)
    assert len(f.raw.read_lengths) == (1 if case.startswith("recv") or case == "restore_equal" else 0)
    assert f.raw.timeout == .5 and f.observer.qpc_completed == 0
    report = f.observer.report()
    row = dict(zip(f.observer.QPC_FIELDS, report["qpc_receive"]["first_exception"], strict=True))
    assert row["outcome"] == "deadline" and row["deadline_ns"] == 11000000


@pytest.mark.parametrize("case", ("empty_guard", "would_block_guard", "eof", "native_timeout", "native_oserror",
                                  "select_error", "restore_only", "primary_and_restore", "progress_resets"))
def test_s15_no_progress_errors_and_restoration_preserve_first_error(monkeypatch, case):
    from secure_control.execution.localhost_transport import (
        LocalhostTransportDisconnected,
        LocalhostTransportError,
        LocalhostTransportTimeout,
    )

    original = TimeoutError("private native text") if case in ("native_timeout", "primary_and_restore") else OSError(10054, "private socket text")
    restore = OSError(9, "private restore text") if case in ("restore_only", "primary_and_restore") else None
    chunks, waits, expected = [b"data"], (), OSError
    if case == "empty_guard":
        chunks, waits, expected = [], [(1000000, "empty")] * 8, LocalhostTransportError
    elif case == "would_block_guard":
        chunks, expected = [BlockingIOError()] * 8, LocalhostTransportError
    elif case == "eof":
        chunks, expected = [b"ab", b""], LocalhostTransportDisconnected
    elif case in ("native_timeout", "primary_and_restore"):
        chunks, expected = [original], LocalhostTransportTimeout
    elif case == "native_oserror":
        chunks, expected = [b"a", original], LocalhostTransportDisconnected
    elif case == "select_error":
        chunks, waits, expected = [], [(1000000, original)], LocalhostTransportDisconnected
    elif case == "progress_resets":
        chunks = [BlockingIOError()] * 7 + [b"ab"] + [BlockingIOError()] * 7 + [b"cd"]
    f = _s15_receive_fixture(monkeypatch, chunks, waits=waits, restore_error=restore,
                            deadline_ns=100000000 if case == "progress_resets" else 11000000)
    if case == "progress_resets":
        assert f.observer.qpc_receive(f.original, f.probe, 4, f.deadline) == b"abcd"
        assert len(f.selected) == 16 and f.observer.qpc_would_block == 14 and f.observer.first_failure is None
    else:
        with pytest.raises(expected) as caught:
            f.observer.qpc_receive(f.original, f.probe, 4, f.deadline)
        if case in ("native_timeout", "primary_and_restore", "native_oserror", "select_error"):
            assert caught.value.__cause__ is original
        if case in ("empty_guard", "would_block_guard"):
            assert type(caught.value) is LocalhostTransportError and len(f.selected) == 8 and f.now[0] < 11000000
        if case == "primary_and_restore":
            assert f.observer.first_failure[13] == "TimeoutError"
        assert f.observer.qpc_completed == 0
    report = f.observer.report()
    assert len(report["qpc_receive"]["events"]) <= 16 and report["qpc_receive"]["encoded_omitted"] == 0
    assert report["qpc_receive"]["restore_error_type"] == ("OSError" if restore else None)
    assert f.raw.timeout == (0 if restore else .5)
    assert "private" not in str(report)


def test_s15_real_framing_partial_header_body_meter_and_restore(monkeypatch):
    import struct

    from secure_control.execution import localhost_transport

    f = _s15_receive_fixture(monkeypatch, [b"\x00", b"\x00\x00\x04", b"d", b"at", b"a"], deadline_ns=100000000)
    monkeypatch.setattr(localhost_transport, "_receive_exact", lambda sock, length, deadline:
        f.observer.frame(lambda probe, n, d: f.observer.qpc_receive(f.original, probe, n, d),
                         sock, length, deadline, sending=False))
    f.observer.contexts[("Client", "P1")] = f.probe.context
    assert localhost_transport.receive_frame(f.raw, deadline=f.deadline, limit=4) == b"data"
    assert f.raw.read_lengths == [4, 3, 4, 3, 1] and f.observer.qpc_completed == 2 and f.raw.timeout == .5
    for header in (0, 5):
        f = _s15_receive_fixture(monkeypatch, [struct.pack("!I", header)], deadline_ns=100000000)
        f.observer.contexts[("Client", "P1")] = f.probe.context
        with pytest.raises(localhost_transport.LocalhostTransportProtocolError):
            localhost_transport.receive_frame(f.raw, deadline=f.deadline, limit=4)
        assert f.raw.read_lengths == [4]


def test_s15_scope_and_default_guard_before_ports_and_cli(monkeypatch, tmp_path):
    import sys

    from secure_control.experiments import communication_benchmark as bench
    from secure_control.experiments import lan_runner

    def forbidden(*args, **kwargs):
        pytest.fail("非法选择不得建端口/角色/材料")
    monkeypatch.setattr(bench, "_ports", forbidden)
    valid = {"steps": 1000, "delay_ms": 0, "segment_steps": 400, "material_slots": 16,
             "recording_mode": "light", "optimized": True, "qpc_stage_receive_candidate": True}
    for change in ({"qpc_stage_receive_candidate": 1}, {"steps": 1001}, {"steps": True}, {"steps": 0},
                   {"compact_history_candidate": True}, {"stage_wait_diagnostic": True}, {"server_gc_candidate": True},
                   {"worker_long_run": True}, {"diagnostic": True}, {"timeout_trace": True}, {"preload_steps": 1},
                   {"preload_execution": "staged"}, {"role_config": "tls.yaml"}, {"tcp_nodelay": False},
                   {"segment_steps": 1000}, {"material_slots": 4}, {"delay_ms": 1}, {"recording_mode": "full"}):
        with pytest.raises((TypeError, ValueError)):
            bench.run_continuous_observation(**(valid | change))
    selected = []
    monkeypatch.setattr(bench, "_run_material_comparison", lambda options, candidate, **kwargs:
        selected.append((options, candidate, kwargs)) or {"status": "stopped"})
    bench.run_continuous_observation(**valid)
    assert selected[0][1:] == ("worker", {"target_steps": 1000}) and selected[0][0]["qpc_stage_receive_candidate"]
    calls = []
    monkeypatch.setattr(bench, "run_continuous_observation", lambda **kwargs:
        calls.append(kwargs) or {"status": "stopped", "cycle_timing": {"p50_ms": None}})
    args = ["secure-control", "benchmark", "--qpc-stage-receive-candidate", "--steps", "1000", "--output", str(tmp_path / "result.json")]
    for bad in (["--case", "dynamic"], ["--case", "cycle", "--mode", "legacy"], ["--case", "cycle", "--fixed-proof-cache"]):
        monkeypatch.setattr(sys, "argv", args + bad)
        assert lan_runner._run() == 5 and not calls
    monkeypatch.setattr(sys, "argv", args + ["--case", "cycle", "--mode", "batch"])
    assert lan_runner._run() == 0 and calls[0]["qpc_stage_receive_candidate"] is True


def test_s15_meter_keeps_original_receive_cost_and_restores_hooks(monkeypatch):
    from secure_control.execution import localhost_transport
    from secure_control.experiments import communication_benchmark as bench

    f = _s15_receive_fixture(monkeypatch, [b"\x00\x00\x00\x04", b"data"])
    before = _s12_hook_snapshot()
    _, activity, restore = bench._meter("Client", (101, 102, 103), 0, qpc_receiver=f.observer.qpc_receive)
    try:
        with f.observer.installed():
            f.observer.contexts[("Client", "P1")] = f.probe.context
            assert localhost_transport.receive_frame(f.raw, deadline=f.deadline, limit=4) == b"data"
    finally:
        restore()
    assert _s12_hook_snapshot() == before and activity["receive_ms"] == 2.0 and f.observer.qpc_completed == 2
    report = f.observer.report()
    assert report["hooks_restored"] and report["first_failure"] is None and f.raw.timeout == .5
    native = [dict(zip(f.observer.FIELDS, e, strict=True)) for e in report["events"] if e[1] == "recv"]
    assert len(native) == 2
    assert all(dict(zip(f.observer.ENTRY_FIELDS, e["entry"], strict=True))["observed_timeout_s"] == 0 for e in native)
    assert all(dict(zip(f.observer.ENTRY_FIELDS, e["entry"], strict=True))["requested_timeout_s"] == 0 for e in native)


@pytest.mark.parametrize("case", ("phase", "off", "peer", "legacy", "bool_deadline", "context", "tls", "foreign_socket"))
def test_s15_exact_scope_rejects_unknown_and_passes_unselected_once(monkeypatch, case):
    f = _s15_receive_fixture(monkeypatch, [b"data"])
    marker, calls = object(), []
    def original(*args):
        calls.append(args)
        return marker
    if case == "phase":
        f.observer.state.phase = "online_wait_P1"
    elif case == "off":
        f.observer.qpc_receive_candidate = False
    elif case == "peer":
        f.probe.peer = "unknown"
    elif case == "legacy":
        f.deadline = 3.
    elif case == "bool_deadline":
        f.deadline.deadline_ns = True
    elif case == "context":
        f.probe.context = (*f.probe.context[:6], "other-round", *f.probe.context[7:])
    elif case == "tls":
        class TLS(type(f.raw)):
            pass
        f.raw.__class__ = TLS
    elif case == "foreign_socket":
        f.raw.getpeername = lambda: ("127.0.0.1", 9999)
    if case in ("phase", "off"):
        assert f.observer.qpc_receive(original, f.probe, 4, f.deadline) is marker and len(calls) == 1
    else:
        with pytest.raises(ValueError):
            f.observer.qpc_receive(original, f.probe, 4, f.deadline)
        assert not calls
    assert not f.selected and not f.raw.mode_changes


def test_s15_startup_failure_keeps_new_profile_and_never_starts_roles(monkeypatch):
    from secure_control.execution import lan_runtime
    from secure_control.experiments import communication_benchmark as bench

    before, factory = _s12_hook_snapshot(), lan_runtime._MaterialWorkerPool.__init__
    def forbidden(*args):
        pytest.fail("预分配保护失败不能启动角色/网络")
    monkeypatch.setattr(bench, "_ports", forbidden)
    monkeypatch.setattr(bench, "_process_memory", lambda: {"current_rss_bytes": 257*1024**2})
    result = bench.run_continuous_observation(steps=1000, delay_ms=0, segment_steps=400,
        optimized=True, recording_mode="light", qpc_stage_receive_candidate=True)
    assert result["failure_category"] == "RuntimeError" and result["cycles"] == []
    meta = result["qpc_stage_receive_candidate"]
    assert meta["profile"] == "qpc-stage-receive-v1" and meta["target_steps"] == meta["maximum_attempts"] == 1000
    assert not meta["finite_sample_pass"] and meta["actual_attempts"] == 0
    assert "compact_history_candidate" not in result and _s12_hook_snapshot() == before
    assert lan_runtime._MaterialWorkerPool.__init__ is factory


def test_s15_finite_gate_requires_own_profile_full_route_and_maintenance_without_weakening_s13():
    from copy import deepcopy

    from secure_control.experiments import communication_benchmark as bench

    base, numeric = _s11_public_result()
    base["cycles"] = base["cycles"][:1000]
    base.update(requested_steps=1000, successful_steps=1000, protocol_committed_count=1000,
        physically_confirmed_count=1000, cycle_summary={"attempts": 1000, "misses": 0},
        resource_counts={"products_consumed": 30000, "truncations_consumed": 4000},
        numeric_profile={"fractional_bits": 32, "security_parameter": 80, "period_s": .02,
                         "modulus_bits": 256, "state_dimension": 4, "input_dimension": 2, "output_dimension": 1})
    base["steps"] = [{"global_step": c["global_step"], "session_id": c["session_id"],
                      "round_id": c["round_id"], "status": "confirmed"} for c in base["cycles"]]
    base["material_summary"].update(claimed=1000, generated_received=1016)
    base["last_commit_observation"].update(round_id="round-999", step=999, global_step=999)
    def history_report(role):
        threads = [{"thread_role": name, "pid": 10, "native_id": native, "registered_at_qpc_ns": 0,
                    "observation_end_qpc_ns": 80000000000} for name, native in
                   (("control", 1), ("material-receiver", 99), ("material-credit", 100))
                   if role == "Client" or name == "control"]
        return {"role": role, "representation_complete": True, "layout": {"reserved_bound_bytes": 100},
            "tables": {k: {"captured": 1000, "expanded": 1000} for k in ("steps", "cycles")}, "threads": threads,
            "control_observation": {"last_confirmed_step": 999,
                "last_confirmed_return_qpc_ns": base["cycles"][-1]["cycle_completed_ns"]+1,
                "normal_stop_start_qpc_ns": base["cycles"][-1]["cycle_completed_ns"]+2}}
    sample = {"memory_guard_failed": False, "cleanup_failed": False, "producer_exited": True}
    for fault in ("normal", "missing_route", "incomplete_route", "restore", "guard", "maintenance", "bool",
                  "bool_route", "exception", "profile", "s13"):
        result, metadata = deepcopy(base), deepcopy(numeric)
        metadata.update(profile="qpc-stage-receive-v1", target_steps=1000, maximum_attempts=1000)
        observer = bench._StageWaitDiagnostic("Client", (101, 102, 103),
            gc_observer=_s12_software_observer("Client").gc_observer, qpc_receive_candidate=True)
        observer.trace_restored = True
        observer.qpc_calls = observer.qpc_completed = 4000
        for party in result["party_outcomes"]:
            party.pop("server_gc")
            party["steps"] = party["steps"][:1000]
            stage = _s12_software_observer(party["role"])
            stage.gc_observer.normal_stop_ack_sent = True
            party["stage_wait"] = stage.report()
            party["compact_history"] = history_report(party["role"])
        if fault == "missing_route":
            observer.qpc_calls = observer.qpc_completed = 0
        elif fault == "incomplete_route":
            observer.qpc_completed -= 1
        elif fault == "restore":
            observer.qpc_restore_error_type = "OSError"
        elif fault == "guard":
            observer.qpc_guards = 1
        elif fault == "maintenance":
            result["cycles"][799].pop("phase_durations_ns")
        elif fault == "bool":
            result["cycles"][0]["protocol_committed_count"] = True
        elif fault == "bool_route":
            observer.qpc_completed = 4000.
        elif fault == "exception":
            observer.qpc_first_exception = ("failure", 0, 1, "P1", "header", None, 11000000,
                11000000, None, None, 0, 0, "native_error", "TimeoutError", None, None)
        elif fault in ("profile", "s13"):
            metadata["profile"] = "stage-wait-light-v1"
            if fault == "s13":
                observer.qpc_receive_candidate = False
        bench._finish_stage_wait(result, sample, metadata, [observer])
        if fault == "s13":
            assert metadata["evidence_complete"] and result["status"] == "stopped"
        history = SimpleNamespace(expansion_ns=1, report=lambda: history_report("Client"))
        bench._finish_compact_history(result, sample, history, qpc_stage_receive_candidate=fault != "s13")
        meta = result["compact_history_candidate" if fault == "s13" else "qpc_stage_receive_candidate"]
        assert meta["finite_sample_pass"] == (fault == "normal"), fault
        assert meta["target_steps"] == (4000 if fault == "s13" else 1000)
        assert not any(result[k] for k in ("server_gc_candidate_gate_pass", "candidate_gate_pass", "worker_long_run_gate_pass",
                                         "stage_pass", "qualification_pass"))


def test_s15_budget_never_silently_omits_first_error_gc_or_qpc_exception():
    from secure_control.experiments import communication_benchmark as bench

    observer = bench._StageWaitDiagnostic("Client", (101, 102, 103),
        gc_observer=_s12_software_observer("Client").gc_observer, qpc_receive_candidate=True)
    def context(step):
        return ("expected_from_validated_stage_plan", "Client", "P1", "stage", None,
                "s"*128, (str(step)+"r"*128)[:128], step, step, "u"*128, "e"*128, 0, step)
    for step in range(128):
        observer.slots[step] = ("phase", "finish_stage_batch", step, step+1, 1, 1, "P1", None, None,
            context(step), "finish_stage_batch", None, None, None, None, None, None, None, False, None, False)
    observer.seen = 128
    for step in range(16):
        observer.qpc_slots[step] = ("select", step, step+1, "P1", "header", context(step),
                                  20000000, 10000000, 10000000, 0, 0, 1, "empty", None, None, None)
    observer.qpc_seen = 16
    observer.qpc_first_anomaly = observer.qpc_slots[0]
    observer.qpc_first_exception = observer.qpc_slots[1]
    observer.first_failure = (*observer.slots[0][:13], "TimeoutError", None, None, None, "socket_recv", True, None, False)
    gc_observer = observer.gc_observer
    gc_observer.slots = [(step*10, step*10+1, 1, 2, 0, 0) for step in range(64)]
    gc_observer.count = 64
    result = observer.report()
    assert result["budget_failed"] and result["encoded_omitted"] > 0 and result["encoded_bytes"] <= 64*1024
    assert result["first_failure"] is not None and len(result["gc"]["events"]) == 64
    assert result["qpc_receive"]["first_exception"] is not None and len(result["qpc_receive"]["events"]) == 16
    assert result["gc"]["encoded_omitted"] == result["qpc_receive"]["encoded_omitted"] == 0
    # 总预算拒绝/重建context表时也不能留下指向旧表的QPC identity索引。
    aggregate = {"status": "uncertain", "failure_category": "OSError", "cycles": [], "failed_attempts": 1}
    metadata = {"format_version": 1, "profile": "qpc-stage-receive-v1", "scope_fixture": "x"*200000}
    bench._finish_stage_wait(aggregate, {"cleanup_failed": False, "memory_guard_failed": False}, metadata, [observer])
    client = aggregate["stage_wait_diagnostic"]["roles"][0]
    assert metadata["budget_failed"] and not metadata["evidence_complete"]
    assert len(client["gc"]["events"]) == 64 and client["first_failure"] is not None
    for row in client["qpc_receive"]["events"]:
        assert client["contexts"][row[5]] == list(context(row[1])) or client["contexts"][row[5]] == context(row[1])


@pytest.mark.parametrize("valid_identity", (True, False))
def test_s15_real_endpoint_preserves_reply_validation_and_never_resends(monkeypatch, valid_identity):
    import struct

    import numpy as np

    from secure_control.execution._localhost_workers import _ClientPartyEndpoint
    from secure_control.execution.localhost_codec import PartyStageResult
    from secure_control.experiments import communication_benchmark as bench
    from secure_control.protocol.messages import ControlShareMessage, Protocol3StageReceipt

    reply_round = "round" if valid_identity else "other-round"
    receipt = Protocol3StageReceipt(0, "session", reply_round, 0, 1, 1)
    share = ControlShareMessage(0, "session", reply_round, 0, 8, AdditiveShare(np.array([123456789], dtype=object)))
    reply = WireEnvelope(SCHEMA_VERSION, "reply", "P1", "Client", 5, "endpoint", "session", reply_round,
                         0, None, PartyStageResult(receipt, share))
    encoded = encode_envelope(reply)
    header = struct.pack("!I", len(encoded))
    f = _s15_receive_fixture(monkeypatch, [header[:1], header[1:], encoded[:2], encoded[2:]],
                            waits=[(3000000, "empty")])
    sent = []
    def send(data):
        sent.append(bytes(data))
        return len(data)
    f.raw.send = send
    endpoint = _ClientPartyEndpoint(f.raw, 0, SimpleNamespace(session_id="session", round_id="round", step=0),
                                    5, 10000, 30., f.deadline)
    f.observer.state.phase = f.observer.state.context = None
    before = _s12_hook_snapshot()
    _, activity, restore = bench._meter("Client", (101, 102, 103), 0, qpc_receiver=f.observer.qpc_receive)
    try:
        with f.observer.installed():
            endpoint.start_stage_batch()
            if valid_identity:
                assert endpoint.finish_stage_batch() == receipt and endpoint.share == share
                assert endpoint._pending_batch is None
            else:
                with pytest.raises(ValueError):
                    endpoint.finish_stage_batch()
                assert endpoint._pending_batch is not None
    finally:
        restore()
    assert _s12_hook_snapshot() == before and len(sent) == 1
    assert f.observer.qpc_completed == 2 and f.observer.qpc_empty == 1 and activity["receive_ms"] == 7.0
    report = f.observer.report()
    assert "123456789" not in str(report) and report["qpc_receive"]["first_exception"] is None
    assert report["profile"] == "qpc-stage-receive-v1" and report["encoded_bytes"] <= 65536
