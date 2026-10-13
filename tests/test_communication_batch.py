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


def test_timeout_trace_forwards_partial_frames_native_errors_and_never_retries():
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


@pytest.mark.parametrize("fault", ("bad_last_member", "lost_product_barrier"))
def test_dynamic_batch_fault_burns_all_resources_without_stage_or_state_change(fault):
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
    endpoint = LocalProtocol3PartyEndpoint(role, local, shares.append)
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
