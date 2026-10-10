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
