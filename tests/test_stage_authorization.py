"""Client 汇总局部暂存事实的授权边界，不执行性能观察。"""

import random
import socket
from dataclasses import replace
from threading import Event, Thread

import numpy as np
import pytest
from test_two_party_protocol import make_stack

from secure_control.crypto.truncation import _MaskLifecycle
from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
from secure_control.execution._localhost_workers import _ClientPartyEndpoint, _complete_client_round
from secure_control.execution.localhost_codec import (
    PartyStageResult,
    decode_envelope,
)
from secure_control.execution.localhost_transport import (
    deadline_after,
    receive_envelope,
)
from secure_control.protocol import P1, P2
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
    Protocol3CommitAuthorization,
    Protocol3LocalStageReceipt,
    Protocol3StageReceipt,
)


def test_local_p2_finish_does_not_invent_p1_reconstruction():
    lifecycle = _MaskLifecycle(object(), observation_party=1)
    lifecycle.claim_mask(1)
    lifecycle.claim_p2_send()
    assert not lifecycle.claim_finish(1)
    assert not lifecycle.p1_reconstructed
    assert lifecycle.masked_parties == {1}
    assert lifecycle.finished_parties == {1}
    assert not lifecycle.consumed
    lifecycle.attest_peer_finish(1)
    assert lifecycle.consumed
    assert lifecycle.finished_parties == {1}
    assert not lifecycle.p1_reconstructed
    with pytest.raises(ValueError):
        lifecycle.attest_peer_finish(1)


def test_shared_truncation_still_requires_observed_p1_reconstruction():
    lifecycle = _MaskLifecycle(object())
    lifecycle.claim_mask(0)
    lifecycle.claim_mask(1)
    lifecycle.claim_p2_send()
    with pytest.raises(ValueError):
        lifecycle.claim_finish(1)


@pytest.mark.parametrize("field,value", [
    ("party", True), ("party", 2), ("session_id", ""),
    ("round_id", ""), ("step", True), ("step", -1),
    ("products", True), ("truncations", -1), ("plan_sha256", "x"),
    ("scope", "global_complete"),
])
def test_local_receipt_requires_canonical_public_fields(field, value):
    values = {"party": 0, "session_id": "s", "round_id": "r", "step": 0,
              "products": 30, "truncations": 4, "plan_sha256": "a" * 64}
    values[field] = value
    with pytest.raises((ValueError, TypeError)):
        Protocol3LocalStageReceipt(**values)


@pytest.mark.parametrize("parties", [(0,), (1, 0), (0, 0), (False, 1), [0, 1]])
def test_authorization_requires_both_distinct_canonical_parties(parties):
    with pytest.raises((ValueError, TypeError)):
        Protocol3CommitAuthorization("a" * 64, parties, 30, 4)


@pytest.fixture
def local_round():
    """材料隔离重建与生产路径相同；资源领取只在单方原 owner 中发生。"""
    client, _, _, _, distribution = make_stack()
    current = client.prepare_online(distribution, [.25], step=0, rng=random.Random(100))
    roles, rounds, outputs = [], [], [[], []]
    for role_type, offline, inp, resources in (
            (P1, distribution.p1, current.p1_input, current.p1_resources),
            (P2, distribution.p2, current.p2_input, current.p2_resources)):
        roles.append(role_type(rehydrate_offline_material(PartyOfflineMaterial.from_message(offline),
                                                         distribution.range_contract)))
        rounds.append(rehydrate_online_material(PartyOnlineMaterial.from_round(PartyOnlineRound(inp, resources)),
            modulus=client.fixed_point.modulus, security_parameter=8))
    endpoints = [LocalProtocol3PartyEndpoint(roles[i], rounds[i], outputs[i].append,
                                            completion_strategy="client_authorized") for i in (0, 1)]
    peers = [LocalhostProtocol3PeerPort(sock, f"P{i+1}", 8*1024*1024, 5., batch_enabled=True,
                                      wire_profile="control-dynamic-compact-v3")
             for i, sock in enumerate(socket.socketpair())]
    plan = rounds[0].resources.plan
    for peer in peers:
        peer.bind(plan.session_id)
        peer.set_batch_round(plan, modulus=client.fixed_point.modulus, run_id="run", epoch_id="epoch")
    yield client, roles, rounds, endpoints, peers, outputs
    for peer in peers:
        peer.close()
    for endpoint in endpoints:
        endpoint.abort()
    if (current.session_id, current.round_id, current.step) in client._issued_rounds:
        client.abort_round(current)


def _stage_threads(endpoints, peers):
    receipts, errors = [None, None], []
    def run(i):
        try:
            receipts[i] = stage_protocol3_batch(endpoints[i], peers[i])
        except BaseException as error:  # noqa: BLE001 - 主线程断言原始异常。
            errors.append(error)
    threads = [Thread(target=run, args=(i,)) for i in (0, 1)]
    for thread in threads:
        thread.start()
    return threads, receipts, errors


@pytest.mark.parametrize("held_party", [0, 1])
def test_local_stage_has_no_hidden_barrier_or_fabricated_remote_finish(local_round, monkeypatch, held_party):
    client, roles, rounds, endpoints, peers, outputs = local_round
    release, entered = Event(), Event()
    owner = peers[0] if held_party == 0 else endpoints[1]
    name = "receive_truncations" if held_party == 0 else "finish_truncation_p2"
    original = getattr(owner, name)
    def held(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)
    monkeypatch.setattr(owner, name, held)
    for peer in peers:
        monkeypatch.setattr(peer, "product_complete", lambda *_: pytest.fail("隐藏 product barrier"))
        monkeypatch.setattr(peer, "state_complete", lambda *_: pytest.fail("隐藏 state barrier"))
    before = [role.state_share for role in roles]
    threads, receipts, errors = _stage_threads(endpoints, peers)
    try:
        assert entered.wait(5)
        threads[1-held_party].join(2)
        assert not threads[1-held_party].is_alive() and not errors
        assert receipts[held_party] is None
        assert type(receipts[1-held_party]) is Protocol3LocalStageReceipt
        assert all(item.resources.consumed_count == 0 for item in rounds)
        assert all(role.state_share is state for role, state in zip(roles, before, strict=True))
        for resource in rounds[1].resources.state_truncation_resources:
            assert not resource.truncation._lifecycle.p1_reconstructed
        with pytest.raises(ValueError):
            Protocol3Orchestrator(completion_strategy="client_authorized").authorize(tuple(receipts), endpoints[0].plan)
    finally:
        release.set()
        for thread in threads:
            thread.join(5)
    assert not errors and not any(thread.is_alive() for thread in threads)
    plan = endpoints[0].plan
    orchestrator = Protocol3Orchestrator(completion_strategy="client_authorized")
    # 独立整数 oracle：旧状态输出与每方 Trunc 公式，不调用协议聚合/缩放 helper。
    assert client.reconstruct_control(outputs[0][0], outputs[1][0]) == pytest.approx([.625])
    q, scale = client.fixed_point.modulus, 1 << client.fixed_point.fractional_bits
    for row in range(2):
        raw = [int(endpoint.raw_state_share.value[row]) for endpoint in endpoints]
        aux = [rounds[i].resources.state_truncation_resources[row].truncation for i in (0, 1)]
        masked = (sum(raw)+scale*sum(int(item.r.value) for item in aux)
                  +sum(int(item.r_prime.value) for item in aux)+scale//2) % q
        centered = masked if masked <= q//2 else masked-q
        low = (centered-scale//2+scale//2) % scale-scale//2
        expected = [(raw[0]+int(aux[0].r_prime.value)-low)*pow(scale, -1, q) % q,
                    (raw[1]+int(aux[1].r_prime.value))*pow(scale, -1, q) % q]
        assert [int(endpoint.next_state_share.value[row]) for endpoint in endpoints] == expected
    authorization = orchestrator.authorize(tuple(receipts), plan)
    for endpoint in endpoints:
        endpoint.commit_staged(authorization)
        with pytest.raises(ValueError):
            endpoint.commit_staged(authorization)
    assert all(item.resources.consumed_count == plan.triple_count+plan.truncation_count for item in rounds)
    assert all(resource.truncation._lifecycle.finished_parties == {i}
        for i in (0, 1) for resource in rounds[i].resources.state_truncation_resources)


@pytest.mark.parametrize("fault", ["bare", "early", "digest", "count"])
def test_bad_authorization_never_changes_state(local_round, fault):
    _, roles, rounds, endpoints, peers, _ = local_round
    prior = roles[0].state_share
    if fault != "early":
        threads, _receipts, errors = _stage_threads(endpoints, peers)
        for thread in threads:
            thread.join(5)
        assert not errors
    plan = endpoints[0].plan
    from secure_control.protocol.messages import public_step_plan_sha256
    authorization = Protocol3CommitAuthorization(public_step_plan_sha256(plan), (0, 1),
                                                 plan.triple_count, plan.truncation_count)
    if fault == "digest":
        authorization = replace(authorization, plan_sha256="0"*64)
    if fault == "count":
        authorization = replace(authorization, products=authorization.products+1)
    with pytest.raises(ValueError):
        endpoints[0].commit() if fault == "bare" else endpoints[0].commit_staged(authorization)
    assert roles[0].state_share is prior
    assert rounds[0].resources.consumed_count == 0


@pytest.mark.parametrize("fault", ["party", "session", "round", "step", "digest", "products", "truncations", "old"])
def test_receipt_pair_must_match_same_live_plan(local_round, fault):
    *_, endpoints, _peers, _outputs = local_round
    plan = endpoints[0].plan
    from secure_control.protocol.messages import public_step_plan_sha256
    receipts = [Protocol3LocalStageReceipt(i, plan.session_id, plan.round_id, plan.step,
        plan.triple_count, plan.truncation_count, public_step_plan_sha256(plan)) for i in (0, 1)]
    edits = {"party": {"party": 0}, "session": {"session_id": "other"}, "round": {"round_id": "other"},
        "step": {"step": 1}, "digest": {"plan_sha256": "0"*64}, "products": {"products": plan.triple_count+1},
        "truncations": {"truncations": plan.truncation_count+1}}
    if fault == "old":
        receipts[1] = Protocol3StageReceipt(1, plan.session_id, plan.round_id, plan.step,
                                            plan.triple_count, plan.truncation_count)
    else:
        receipts[1] = replace(receipts[1], **edits[fault])
    with pytest.raises(ValueError):
        Protocol3Orchestrator(completion_strategy="client_authorized").authorize(tuple(receipts), plan)


def test_peer_rejects_removed_phases_early_truncation_and_round_replay(local_round):
    *_, endpoints, peers, _ = local_round
    plan = endpoints[0].plan
    for peer in peers:
        with pytest.raises(ValueError):
            peer.product_complete(plan)
        with pytest.raises(ValueError):
            peer.state_complete(plan)
        with pytest.raises(ValueError):
            peer.set_batch_round(plan, modulus=2147483647, run_id="run", epoch_id="epoch")
    with pytest.raises(ValueError):
        peers[0].receive_truncations(plan)
    with pytest.raises(ValueError):
        peers[1].send_truncations(plan, ())


@pytest.mark.parametrize("fault", [None, "output", "lost_ack", "short_p1", "short_p2", "late"])
def test_actual_client_and_peer_frames_keep_double_ack_owner(local_round, monkeypatch, fault):
    """真实 socket 编解码计数；任何提交不确定都不能签发控制结果。"""
    from collections import Counter
    from threading import get_ident, main_thread

    import secure_control.execution._localhost_peer as peer_module
    import secure_control.execution._localhost_workers as workers
    from secure_control.protocol import coordinator
    digest_calls = Counter()
    authorization_objects = Counter()
    canonical_digest = coordinator.public_step_plan_sha256
    def counted_digest(plan):
        digest_calls[get_ident()] += 1
        return canonical_digest(plan)
    monkeypatch.setattr(coordinator, "public_step_plan_sha256", counted_digest)
    original_init = Protocol3CommitAuthorization.__post_init__
    def counted_authorization(self):
        authorization_objects[get_ident()] += 1
        original_init(self)
    monkeypatch.setattr(Protocol3CommitAuthorization, "__post_init__", counted_authorization)
    client, _roles, rounds, local, peers, outputs = local_round
    connections = [socket.socketpair(), socket.socketpair()]
    endpoints = [_ClientPartyEndpoint(pair[0], i, local[i].plan, 1, 8*1024*1024, 5.,
                                     completion_strategy="client_authorized")
                 for i, pair in enumerate(connections)]
    frames, errors = [], []
    peer_send, exchange, client_send = peer_module.send_envelope, peer_module._exchange_frame, workers.send_envelope
    def sent(sock, envelope, **kwargs):
        frames.append((envelope.sender, envelope.recipient, getattr(envelope.payload, "operation", envelope.operation)))
        return client_send(sock, envelope, **kwargs)
    def exchanged(sock, data, **kwargs):
        frame = decode_envelope(data)
        frames.append((frame.sender, frame.recipient, frame.payload.phase))
        return exchange(sock, data, **kwargs)
    def peer_sent(sock, envelope, **kwargs):
        frames.append((envelope.sender, envelope.recipient, envelope.payload.phase))
        return peer_send(sock, envelope, **kwargs)
    def client_sent(sock, envelope, **kwargs):
        if (fault == "short_p1" and envelope.recipient == "P1"
                or fault == "short_p2" and envelope.recipient == "P2") and getattr(envelope.payload, "operation", None) == "commit_staged":
            raise TimeoutError("short write")
        return sent(sock, envelope, **kwargs)
    monkeypatch.setattr(workers, "send_envelope", client_sent)
    monkeypatch.setattr(peer_module, "send_envelope", peer_sent)
    monkeypatch.setattr(peer_module, "_exchange_frame", exchanged)
    if fault == "output":
        monkeypatch.setattr(client, "reconstruct_control", lambda *_: np.array([np.nan]))
    def party(i):
        sock = connections[i][1]
        try:
            request = receive_envelope(sock, deadline=deadline_after(5), limit=8*1024*1024)
            receipt = stage_protocol3_batch(local[i], peers[i])
            reply = replace(request, sender=f"P{i+1}", recipient="Client", kind="reply",
                            payload=PartyStageResult(receipt, outputs[i][0]))
            sent(sock, reply, deadline=deadline_after(5), limit=8*1024*1024)
            request = receive_envelope(sock, deadline=deadline_after(5), limit=8*1024*1024)
            local[i].commit_staged(request.payload.authorization)
            if fault == "lost_ack" and i == 1:
                return
            sent(sock, replace(request, sender=f"P{i+1}", recipient="Client", kind="reply", payload=None),
                 deadline=deadline_after(5), limit=8*1024*1024)
        except Exception as error:  # noqa: BLE001 - 失败反例保留线程信息。
            errors.append(error)
        finally:
            sock.close()
    threads = [Thread(target=party, args=(i,)) for i in (0, 1)]
    for thread in threads:
        thread.start()
    try:
        def phase(name):
            if fault == "late" and name == "commit":
                raise TimeoutError("original deadline expired after double ACK")
        if fault is None:
            result = _complete_client_round(client, *endpoints, local[0].plan, batch=True, overlap_commit=True)
            assert result.output == pytest.approx([.625])
            assert all(endpoint.commit_observation["valid_ack_received"] for endpoint in endpoints)
        else:
            with pytest.raises((ValueError, OSError, TimeoutError, RuntimeError)):
                _complete_client_round(client, *endpoints, local[0].plan, on_phase=phase,
                                       batch=True, overlap_commit=True)
            if fault == "late":
                assert all(endpoint.commit_observation["valid_ack_received"] for endpoint in endpoints)
            if fault == "output":
                assert not any(name == "commit_staged" for _, _, name in frames)
            if fault == "lost_ack":
                assert endpoints[0].commit_observation["valid_ack_received"]
                assert not endpoints[1].commit_observation["valid_ack_received"]
    finally:
        for pair in connections:
            pair[0].close()
        for thread in threads:
            thread.join(6)
    assert not any(thread.is_alive() for thread in threads)
    if fault is None:
        assert not errors and len(frames) == 11
        assert sum(sender != "Client" and recipient != "Client" for sender, recipient, _ in frames) == 3
        assert all(item.resources.consumed_count > 0 for item in rounds)
        assert digest_calls[main_thread().ident] == 1
        assert sorted(digest_calls.values()) == [1, 1, 1]
        assert authorization_objects[main_thread().ident] == 1
        assert sorted(authorization_objects.values()) == [1, 1, 1]  # 发送1份，两方分别decode；无期望对象。
        assert all(endpoint._authorization_cache is None for endpoint in local)


def _receipts(plan):
    from secure_control.protocol.messages import public_step_plan_sha256
    return tuple(Protocol3LocalStageReceipt(i, plan.session_id, plan.round_id, plan.step,
        plan.triple_count, plan.truncation_count, public_step_plan_sha256(plan)) for i in (0, 1))


def test_authorization_digest_reuses_only_same_deeply_immutable_plan(local_round, monkeypatch):
    from secure_control.protocol import coordinator
    from secure_control.protocol.messages import public_step_plan_sha256
    plan = local_round[3][0].plan
    owner = Protocol3Orchestrator(completion_strategy="client_authorized")
    calls = []
    canonical = coordinator.public_step_plan_sha256
    def counted(item):
        calls.append(item)
        return canonical(item)
    monkeypatch.setattr(coordinator, "public_step_plan_sha256", counted)
    assert owner.authorize(_receipts(plan), plan).plan_sha256 == public_step_plan_sha256(plan)
    assert owner.authorize(_receipts(plan), plan).plan_sha256 == public_step_plan_sha256(plan)
    assert len(calls) == 1
    # 身份相同也不能把不同布局、资源次序/ID、尺度对象当作同一项。
    changed = [replace(plan), replace(plan, round_id="new-round"),
        replace(plan, state_shape=(3,)), replace(plan, product_resources=plan.product_resources[::-1]),
        replace(plan, product_resources=(replace(plan.product_resources[0], resource_id="new-id"),
                                        *plan.product_resources[1:])),
        replace(plan, scale_ledger=replace(plan.scale_ledger, C=0, D=0, output_accumulator=8, output=8))]
    for item in changed:
        prior = len(calls)
        assert owner.authorize(_receipts(item), item).plan_sha256 == public_step_plan_sha256(item)
        owner.authorize(_receipts(item), item)
        assert len(calls) == prior+1
    owner.authorize(_receipts(plan), plan)
    assert len(calls) == len(changed)+2  # 单项缓存不保留旧轮集合。


def test_cached_plan_does_not_cache_receipt_success_or_change_canonical_bytes(local_round):
    import json
    from dataclasses import asdict
    from hashlib import sha256
    plan = local_round[3][0].plan
    owner = Protocol3Orchestrator(completion_strategy="client_authorized")
    receipts = _receipts(plan)
    authorized = owner.authorize(receipts, plan)
    reference = json.dumps(asdict(plan), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False).encode("utf-8")
    assert authorized.plan_sha256 == sha256(b"control-batch-v1-plan\0"+reference).hexdigest()
    for edits in ({"party": 0}, {"plan_sha256": "0"*64}, {"step": 1},
                  {"products": plan.triple_count+1}, {"round_id": "other"}):
        with pytest.raises(ValueError):
            owner.authorize((receipts[0], replace(receipts[1], **edits)), plan)
    assert owner.authorize(receipts, plan) == authorized
    local_round[3][0].abort()
    assert local_round[3][0]._authorization_cache is None


def test_canonical_dynamic_30_4_plan_qualifies_without_changing_digest(monkeypatch):
    """正式数值配置的纯材料/计划功能检查；不建连、不执行周期或计时。"""
    from pathlib import Path

    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.protocol import Client, coordinator
    from secure_control.protocol.messages import (
        _deeply_immutable_public_plan,
        public_step_plan_sha256,
    )
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession
    prepared = load_segmented_experiment(Path(__file__).resolve().parents[1]/"configs/cart_pole_observer_lan.example.yaml",
                                         400, InteractiveSession())
    from secure_control.crypto import TwoPartySharing
    client = Client(prepared.context, TwoPartySharing(prepared.context.modulus),
                    security_parameter=prepared.security_parameter, modulus_evidence=prepared.evidence)
    distribution = client.distribute_controller(prepared.spec, prepared.contract, rng=random.Random(10))
    current = client.prepare_online(distribution, [0., 0.], step=0, rng=random.Random(20))
    plan = current.p1_resources.plan
    assert (plan.triple_count, plan.truncation_count) == (30, 4)
    assert _deeply_immutable_public_plan(plan)
    calls = []
    def digest(item):
        calls.append(item)
        return public_step_plan_sha256(item)
    monkeypatch.setattr(coordinator, "public_step_plan_sha256", digest)
    owner = Protocol3Orchestrator(completion_strategy="client_authorized")
    for _ in range(2):
        assert owner.authorize(_receipts(plan), plan).plan_sha256 == public_step_plan_sha256(plan)
    assert len(calls) == 1
    client.abort_round(current)


@pytest.mark.parametrize("nested", ["resources", "shape", "index", "ledger_subclass", "plan_subclass"])
def test_mutable_or_noncanonical_plan_never_returns_stale_digest(local_round, monkeypatch, nested):
    from secure_control.protocol import coordinator
    from secure_control.protocol.messages import (
        ControllerScaleLedger,
        StepResourcePlan,
        public_step_plan_sha256,
    )
    original = local_round[3][0].plan
    if nested == "resources":
        mutable = list(original.product_resources)
        plan = replace(original, product_resources=mutable)
        mutate = lambda: mutable.reverse()
    elif nested == "shape":
        mutable = [2]
        plan = replace(original, state_shape=mutable)
        mutate = lambda: mutable.append(3)
    elif nested == "index":
        mutable = list(original.product_resources[0].index)
        plan = replace(original, product_resources=(replace(original.product_resources[0], index=mutable),
                                                   *original.product_resources[1:]))
        mutate = lambda: mutable.append(2)
    elif nested == "ledger_subclass":
        class Ledger(ControllerScaleLedger):
            pass
        ledger = Ledger(**{name: getattr(original.scale_ledger, name)
                           for name in original.scale_ledger.__dataclass_fields__})
        plan = replace(original, scale_ledger=ledger)
        mutate = lambda: None
    else:
        class Plan(StepResourcePlan):
            pass
        plan = Plan(**{name: getattr(original, name) for name in original.__dataclass_fields__})
        mutate = lambda: None
    calls = []
    def counted(item):
        calls.append(item)
        return public_step_plan_sha256(item)
    monkeypatch.setattr(coordinator, "public_step_plan_sha256", counted)
    owner = Protocol3Orchestrator(completion_strategy="client_authorized")
    first = owner.authorize(_receipts(plan), plan)
    owner.authorize(_receipts(plan), plan)
    assert len(calls) >= 2  # 兼容域仍即时摘要，绝不把浅冻结当作缓存许可。
    mutate()
    second = owner.authorize(_receipts(plan), plan)
    assert second.plan_sha256 == public_step_plan_sha256(plan)
    if nested in ("resources", "shape", "index"):
        assert second.plan_sha256 != first.plan_sha256
        with pytest.raises(ValueError):
            owner.authorize(tuple(replace(item, plan_sha256=first.plan_sha256) for item in _receipts(plan)), plan)


def test_new_wire_types_round_trip_and_old_receipt_cannot_authorize():
    from secure_control.execution.localhost_codec import _decode_value, _encode_value
    from secure_control.protocol.messages import Protocol3EndpointCommand
    receipt = Protocol3LocalStageReceipt(0, "s", "r", 0, 30, 4, "a"*64)
    authorization = Protocol3CommitAuthorization("a"*64, (0, 1), 30, 4)
    for value in (receipt, authorization, Protocol3EndpointCommand("commit_staged", authorization=authorization)):
        assert _decode_value(_encode_value(value)) == value
    assert set(_encode_value(Protocol3EndpointCommand("commit"))) == {
        "type", "operation", "metadata", "product_mask", "truncation_mask", "p2_truncation"}
    with pytest.raises(ValueError):
        Protocol3Orchestrator(completion_strategy="client_authorized")._validate_receipts(
            (Protocol3StageReceipt(0, "s", "r", 0, 30, 4),)*2, None)


def test_two_removed_peer_waits_have_deterministic_dependency_gain():
    """虚拟单向传播单位=7，不等价真实毫秒；执行原 stage 调度而非只数调用。"""
    from threading import Condition
    propagation = 7
    completed = []
    for strategy in ("peer_barriers", "client_authorized"):
        client, _, _, _, distribution = make_stack()
        current = client.prepare_online(distribution, [.25], step=0, rng=random.Random(100))
        endpoints = []
        for i, role_type, offline, inp, resources in (
                (0, P1, distribution.p1, current.p1_input, current.p1_resources),
                (1, P2, distribution.p2, current.p2_input, current.p2_resources)):
            role = role_type(rehydrate_offline_material(PartyOfflineMaterial.from_message(offline), distribution.range_contract))
            local = rehydrate_online_material(PartyOnlineMaterial.from_round(PartyOnlineRound(inp, resources)),
                modulus=client.fixed_point.modulus, security_parameter=8)
            endpoints.append(LocalProtocol3PartyEndpoint(role, local, lambda _: None, completion_strategy=strategy))
        condition, messages = Condition(), {}
        class Port:
            def __init__(self, party, condition, messages):
                self.party, self.now = party, 0
                self.condition, self.messages = condition, messages
            def send(self, phase, value):
                with self.condition:
                    self.messages[(phase, self.party)] = (self.now+propagation, value)
                    self.condition.notify_all()
            def receive(self, phase):
                with self.condition:
                    assert self.condition.wait_for(lambda: (phase, 1-self.party) in self.messages, 5)
                    arrival, value = self.messages[(phase, 1-self.party)]
                self.now = max(self.now, arrival)
                return value
            def exchange_products(self, plan, masks):
                self.send("product", masks)
                return self.receive("product")
            def product_complete(self, plan):
                self.send("product_complete", None)
                self.receive("product_complete")
            def send_truncations(self, plan, values):
                self.send("truncation", values)
            def receive_truncations(self, plan):
                return self.receive("truncation")
            def state_complete(self, plan):
                self.send("state_complete", None)
                self.receive("state_complete")
        ports = [Port(i, condition, messages) for i in (0, 1)]
        threads, _, errors = _stage_threads(endpoints, ports)
        for thread in threads:
            thread.join(5)
        assert not errors and not any(thread.is_alive() for thread in threads)
        completed.append(max(port.now for port in ports)+4*propagation)
        client.abort_round(current)
    assert completed == [8*propagation, 6*propagation]
