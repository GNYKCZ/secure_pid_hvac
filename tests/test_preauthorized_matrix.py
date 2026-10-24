"""D132-8：独立整数公式、一次性能力、真实短会话及提交后拒绝。"""

import multiprocessing as mp
import random
from dataclasses import replace

import numpy as np
import pytest

from secure_control.crypto import AdditiveShare, TwoPartySharing
from secure_control.crypto.beaver import _TripleLifecycle
from secure_control.crypto.matrix_beaver import (
    MatrixBeaverMultiplier,
    MatrixPrefix,
    MatrixTripleShare,
)
from secure_control.crypto.seeded_material import PREAUTHORIZED_PROFILE
from secure_control.protocol.messages import CommittedStepReply, ReadyReceipt, StepAdvancePermit


def permit(**changes):
    return replace(StepAdvancePermit('run', 'session', 'epoch', 0, 0, 'round',
                                    'a'*32, 'b'*64, 0, 0), **changes)


@pytest.mark.parametrize('field,value', [('global_step', True), ('segment_index', 1.),
    ('expected_state_version', 1), ('previous_physically_confirmed_count', 1),
    ('permit_id', 'G'*32), ('policy', 'already_checked'), ('version', 'old'), ('plan_sha256', 'G'*64)])
def test_permit_rejects_ambiguous_identity(field, value):
    with pytest.raises(ValueError):
        permit(**{field: value})


def mat(a, b, q):
    return np.array([[sum(int(a[i, k])*int(b[k, 0]) for k in range(len(b))) % q]
                     for i in range(len(a))], dtype=object)


@pytest.mark.parametrize('n,m,p', [(1, 1, 1), (2, 3, 1), (4, 2, 1)])
@pytest.mark.parametrize('q', [127, 2**61-1, 2**256-189])
def test_prefix_exact_party_shares_and_integer_oracle(n, m, p, q):
    rng = random.Random(42)
    sharing = TwoPartySharing(q)
    owner = MatrixBeaverMultiplier(sharing)
    triples = owner.create_triple(n+p, n+m, rng=rng)
    matrix = np.array([[rng.choice((0, 1, q-1, q//2)) for _ in range(n+m)]
                       for _ in range(n+p)], dtype=object)
    vector = np.array([[rng.choice((0, 1, q-1, q//2))] for _ in range(n+m)], dtype=object)
    matrices, vectors = sharing.share(matrix, rng=rng), sharing.share(vector, rng=rng)
    prefixes = []
    for party, old in enumerate(triples):
        local_owner = MatrixBeaverMultiplier(sharing)
        triple = MatrixTripleShare(old.u, old.v, old.w, party, n+p, n+m, _TripleLifecycle(local_owner))
        prefix = MatrixPrefix(local_owner, triple, matrices[party], AdditiveShare(vectors[party].value[:n]))
        with pytest.raises(ValueError):
            local_owner.mask_inputs(matrices[party], vectors[party], triple)
        prefixes.append(prefix)
    for party, prefix in enumerate(prefixes):
        other = prefixes[1-party]
        prefix.open_prefix(AdditiveShare(other.e_share), AdditiveShare(other.fx_share))
        token = prefix.triple._lifecycle
        assert prefix.bind(triples[party].w)._lifecycle is token
        with pytest.raises(ValueError):
            prefix.bind(triples[party].w)
    suffixes = [prefix.mask_suffix(AdditiveShare(vectors[i].value[n:])) for i, prefix in enumerate(prefixes)]
    results = [prefix.finish(suffixes[1-i]).value for i, prefix in enumerate(prefixes)]
    u = (triples[0].u.value+triples[1].u.value) % q
    v = (triples[0].v.value+triples[1].v.value) % q
    e, f = (matrix-u) % q, (vector-v) % q
    for i, triple in enumerate(triples):
        expected = (triple.w.value+mat(triple.u.value, f, q)+mat(e, triple.v.value, q)
                    +(mat(e, f, q) if i == 0 else 0)) % q
        assert np.array_equal(results[i], expected)
        with pytest.raises(ValueError):
            prefixes[i].finish(suffixes[1-i])
        prefixes[i].abort()
        with pytest.raises(ValueError):
            prefixes[i].mask_suffix(AdditiveShare(vector[n:]))
    assert np.array_equal((results[0]+results[1]) % q, mat(matrix, vector, q))


def test_permit_wire_reply_retains_commit_when_output_is_invalid():
    from secure_control.execution.localhost_codec import decode_wire_value, encode_wire_value
    first, second = ReadyReceipt(permit(), 0, 4), ReadyReceipt(permit(), 1, 4)
    reply = CommittedStepReply(first, second, 1, 1, b'bad output JSON')
    restored = decode_wire_value(encode_wire_value(reply))
    assert restored == reply and restored.commit_status == 'committed'
    assert 'bad output' not in repr(restored)
    with pytest.raises(ValueError):
        decode_wire_value(restored.output)
    for changed in (replace(second, permit=permit(permit_id='c'*32)), first):
        with pytest.raises(ValueError):
            replace(reply, peer_ready=changed)


def _party(config, ports, queue, fault=None):
    from secure_control.execution import lan_runtime
    from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
    from secure_control.experiments.communication_benchmark import _party_job
    from secure_control.protocol.coordinator import (
        LocalProtocol3PartyEndpoint,
        _OnlineMaterialRecovery,
    )
    if config.role == 'P2' and fault == 'first_prefix':
        def first_prefix(*args):
            raise ValueError('test first prefix failure')
        _OnlineMaterialRecovery.prepare_prefix = first_prefix
    if fault is None:
        original_commit = LocalProtocol3PartyEndpoint.commit_ready
        def check_commit(endpoint, peer):
            assert endpoint._staged and endpoint.ready_receipt().permit == peer.permit
            before = endpoint._role.state_version
            original_commit(endpoint, peer)
            assert endpoint._role.state_version == before+1 and endpoint._closed
            for item in (*endpoint._products.values(), *endpoint._truncations.values()):
                assert item._lifecycle.status == 'consumed' and item._lifecycle.peer_ready
                assert not item._lifecycle.client_attested
                token = (item.triple if hasattr(item, 'triple') else item.truncation)._lifecycle
                assert token.peer_ready_parties == {1-endpoint.party}
                assert token.client_attested_parties == set()
        LocalProtocol3PartyEndpoint.commit_ready = check_commit
    if config.role == 'P2' and fault == 'stage_failed':
        def stage(*args):
            raise ValueError('test P2 stage failure')
        lan_runtime.stage_protocol3_batch = stage
    if config.role == 'P2' and fault in ('ready_missing', 'ready_mismatch'):
        original = LocalhostProtocol3PeerPort.exchange_ready
        def ready(port, value):
            if fault == 'ready_missing':
                raise OSError('test missing READY')
            return original(port, replace(value, permit=replace(value.permit, permit_id='d'*32)))
        LocalhostProtocol3PeerPort.exchange_ready = ready
    if config.role == 'P2' and fault == 'after_ready_exit':
        def commit(*args):
            raise OSError('test crash after both READY, before local commit')
        LocalProtocol3PartyEndpoint.commit_ready = commit
    _party_job(config, ports, 0, True, queue, wire_profile=PREAUTHORIZED_PROFILE)


@pytest.mark.parametrize('segment_steps', [1, 2])
@pytest.mark.parametrize('fault', [None, 'lost_final', 'bad_output', 'late_after_commit', 'partial_send',
                                  'stage_failed', 'ready_missing', 'ready_mismatch', 'after_ready_exit', 'first_prefix'])
def test_real_short_sessions_single_exchange_and_failure_accounting(monkeypatch, segment_steps, fault):
    from secure_control.execution import lan_runtime, localhost_transport
    from secure_control.execution.localhost_codec import decode_envelope
    from secure_control.experiments.communication_benchmark import _config, _ports
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    ports = _ports()
    ctx = mp.get_context('spawn')
    queue = ctx.Queue()
    parties = [ctx.Process(target=_party, args=(_config(role, ports), ports, queue, fault)) for role in ('P1', 'P2')]
    runtime = None
    try:
        prepared = load_segmented_experiment(_config('Client', ports).experiment_config,
                                              segment_steps, InteractiveSession())
        for party in parties:
            party.start()
        runtime = lan_runtime.LanSegmentedRuntime(_config('Client', ports), prepared.spec, prepared.context,
            prepared.contract, prepared.security_parameter, prepared.evidence, control=lan_runtime.RunControl(),
            segment_capacity=segment_steps, wire_profile=PREAUTHORIZED_PROFILE)
        if fault == 'first_prefix':
            with pytest.raises((OSError, RuntimeError, ValueError)):
                runtime.enable_material_preparation(slots=4, _candidate='worker')
            assert runtime.protocol_committed_count == runtime.confirmed_step_count == 0
            assert runtime.phase == 'FAILED' and runtime.material_summary['worker_exited']
            with pytest.raises(RuntimeError):
                runtime.step(np.zeros(2))
            return
        runtime.enable_material_preparation(slots=4, _candidate='worker')
        sent = []
        original_send = localhost_transport.send_frame
        def send(sock, data, **kwargs):
            message = decode_envelope(data)
            sent.append(message.operation)
            if fault == 'partial_send' and message.operation == 'online_permit' and message.recipient == 'P2':
                raise OSError('test second request send failure')
            return original_send(sock, data, **kwargs)
        monkeypatch.setattr(localhost_transport, 'send_frame', send)
        original_receive = lan_runtime.receive_envelope
        received = []
        def receive(sock, **kwargs):
            response = original_receive(sock, **kwargs)
            received.append(response.operation)
            if response.operation == 'online_permit' and response.sender == 'P2':
                if fault == 'lost_final':
                    raise OSError('test dropped final response')
                if fault == 'bad_output':
                    return replace(response, payload=replace(response.payload, output=b'not JSON'))
            return response
        monkeypatch.setattr(lan_runtime, 'receive_envelope', receive)
        if fault == 'late_after_commit':
            original_check = lan_runtime.check_deadline
            def check(deadline, phase):
                if phase == 'AFTER_COMMIT':
                    from secure_control.execution.cycle_timing import CycleDeadlineExceeded
                    raise CycleDeadlineExceeded(phase)
                return original_check(deadline, phase)
            monkeypatch.setattr(lan_runtime, 'check_deadline', check)
        if fault:
            with pytest.raises((OSError, ValueError, TimeoutError, RuntimeError)):
                runtime.step(np.zeros(2))
            assert runtime.confirmed_step_count == 0
            assert runtime.protocol_committed_count == (1 if fault in ('bad_output', 'late_after_commit') else 0)
            observation = runtime.last_commit_observation
            assert observation['parties']['P1']['valid_ack_received'] == (
                fault in ('lost_final', 'bad_output', 'late_after_commit', 'after_ready_exit'))
            if fault in ('bad_output', 'late_after_commit'):
                assert runtime.phase == 'FAILED_AFTER_COMMIT'
                assert runtime.resource_counts['matrix_products_consumed'] == 1
            with pytest.raises(RuntimeError):
                runtime.step(np.zeros(2))
        else:
            state = np.array(prepared.spec.x0, dtype=float)
            for step in range(5):
                if runtime.segment_full:
                    runtime.end_segment()
                    runtime.next_segment()
                sent.clear()
                received.clear()
                result = runtime.step(np.zeros(2))
                assert sent == ['online_permit', 'online_permit']
                assert received == ['online_permit', 'online_permit']
                assert runtime.protocol_committed_count == step+1
                np.testing.assert_allclose(result.raw_control, np.asarray(prepared.spec.C)@state, atol=1e-5, rtol=0)
                assert 'single_exchange' in runtime.cycle_phase_ns
                assert 'stage' not in runtime.cycle_phase_ns and 'commit' not in runtime.cycle_phase_ns
                state = np.asarray(prepared.spec.A)@state
                runtime.confirm_applied(result)
            runtime.control.request_stop()
            runtime.end_segment()
            assert runtime.confirmed_step_count == 5
        runtime.close()
        assert runtime.material_summary['worker_exited']
    finally:
        if runtime is not None:
            runtime.close()
        for party in parties:
            if party.pid:
                party.join(5)
                if party.is_alive():
                    party.terminate()
                    party.join(5)
        queue.close()
        queue.join_thread()


@pytest.mark.parametrize('fault', ['wrong_version', 'wrong_segment', 'wrong_epoch', 'duplicate_bind'])
def test_protocol_prefix_binding_keeps_original_token_and_burns_failed_round(fault):
    from test_two_party_protocol import make_stack

    from secure_control.protocol import P1, Client
    from secure_control.protocol.coordinator import _OnlineMaterialRecovery
    from secure_control.protocol.messages import InputShareMessage, public_step_plan_sha256
    from secure_control.protocol.roles import _seeded_context
    client, _, _, _, distribution = make_stack()
    offline = distribution.p1
    q = client.fixed_point.modulus
    recovery = _OnlineMaterialRecovery(offline, modulus=q, security_parameter=8, modulus_evidence=None)
    context = _seeded_context(offline.layout, 'run', offline.session_id, 'epoch', 0, q, 8,
                              PREAUTHORIZED_PROFILE)
    recovery.install_seeded(context, bytes(range(32)))
    role = P1(offline)
    class Peer:
        def exchange_prefix(self, identity, e, fx, modulus):
            return AdditiveShare(np.zeros_like(e)), AdditiveShare(np.zeros_like(fx))
    recovery.prepare_prefix(role, Peer(), 0)
    prefix = recovery._prefix[0]
    token = prefix.triple._lifecycle
    assert token.masked_parties == {0, 1} and not token.opened
    plan = Client._resource_plan(offline.layout, offline.session_id, 'round', 0,
                                 encoding_profile=PREAUTHORIZED_PROFILE)
    inp = InputShareMessage(0, plan.session_id, plan.round_id, 0, AdditiveShare(np.zeros(1, dtype=object)))
    material = recovery.claim_seeded(inp, plan, ())
    selected = replace(permit(), session_id=offline.session_id, plan_sha256=public_step_plan_sha256(plan))
    if fault == 'wrong_version':
        role.state_version = 1
    if fault == 'wrong_segment':
        selected = replace(selected, segment_index=1)
    if fault == 'wrong_epoch':
        selected = replace(selected, controller_epoch='wrong')
    if fault == 'duplicate_bind':
        online, bound = recovery.restore_preauthorized(material, selected, role)
        assert online.resources.product_resources[0].triple._lifecycle is token
        assert bound is prefix and token.masked_parties == {0, 1}
    with pytest.raises(ValueError):
        recovery.restore_preauthorized(material, selected, role)
    assert recovery._prefix is None and recovery._seeded_key is None
    with pytest.raises(ValueError):
        prefix.bind(material.product_resources[0].w)


def test_preauthorized_next_prepare_failure_preserves_prior_double_commit():
    from test_seeded_material import (
        test_seeded_ack_then_prepare_failure_belongs_to_next_round_only as exercise,
    )
    exercise(profile=PREAUTHORIZED_PROFILE)


def test_seed_profile_domains_are_distinct_and_mixed_contexts_are_rejected():
    from test_two_party_protocol import make_stack

    from secure_control.crypto.seeded_material import SEEDED_PROFILE, dealer_corrections
    from secure_control.protocol.roles import _seeded_context
    client, _, _, _, distribution = make_stack()
    c = _seeded_context(distribution.p1.layout, 'run', distribution.session_id, 'epoch', 0,
                         client.fixed_point.modulus, 8)
    assert c.profile == SEEDED_PROFILE and c.digest() != replace(c, profile=PREAUTHORIZED_PROFILE).digest()
    with pytest.raises(ValueError, match='上下文'):
        dealer_corrections((bytes(32), bytes([1])*32),
            (c, replace(c, party=1, profile=PREAUTHORIZED_PROFILE)), 0, client.truncation)


@pytest.mark.parametrize('fault', ['cancel_after_commit', 'plant_failure'])
def test_original_headless_runner_never_counts_failed_or_cancelled_physical_step(monkeypatch, fault):
    from secure_control.execution import lan_runtime
    from secure_control.experiments.communication_benchmark import _config, _ports
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.experiments.lan_runner import _run_prepared_segmented
    from secure_control.experiments.live_timing import LiveTimingCollector
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    ports = _ports()
    ctx = mp.get_context('spawn')
    queue = ctx.Queue()
    parties = [ctx.Process(target=_party, args=(_config(role, ports), ports, queue)) for role in ('P1', 'P2')]
    session = InteractiveSession()
    selected = replace(_config('Client', ports), wire_profile=PREAUTHORIZED_PROFILE)
    prepared = load_segmented_experiment(selected.experiment_config, 2, session)
    advance_calls = []
    original_advance = prepared.scene.advance
    def advance(*args, **kwargs):
        advance_calls.append(1)
        if fault == 'plant_failure':
            raise RuntimeError('test device failure')
        return original_advance(*args, **kwargs)
    monkeypatch.setattr(prepared.scene, 'advance', advance)
    original_receive = lan_runtime.receive_envelope
    def receive(sock, **kwargs):
        result = original_receive(sock, **kwargs)
        if fault == 'cancel_after_commit' and result.operation == 'online_permit' and result.sender == 'P2':
            session.cancelled.set()
        return result
    monkeypatch.setattr(lan_runtime, 'receive_envelope', receive)
    collector = LiveTimingCollector('samples', sample_limit=2)
    try:
        for party in parties:
            party.start()
        result = _run_prepared_segmented(selected, prepared, control=lan_runtime.RunControl(), session=session,
            non_realtime=True, material_slots=4, timing_observer=collector)
        assert result['status'] == ('cancelled' if fault == 'cancel_after_commit' else 'failed')
        assert result['protocol_committed_count'] == 1 and result['confirmed_step_count'] == 0
        assert result['resource_counts']['matrix_products_consumed'] == 1
        assert advance_calls == ([] if fault == 'cancel_after_commit' else [1])
        samples = collector.report()['raw']['samples']
        assert len(samples) == 1 and samples[0]['control_applied_ns'] is None
        assert samples[0]['work_elapsed_ns'] is None
        assert 'single_exchange' in samples[0]['phase_durations_ns']
    finally:
        for party in parties:
            if party.pid:
                party.join(5)
                if party.is_alive():
                    party.terminate()
                    party.join(5)
        queue.close()
        queue.join_thread()
