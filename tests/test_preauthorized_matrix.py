"""D132-8：独立整数公式、一次性能力、真实短会话及提交后拒绝。"""

import json
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
from secure_control.crypto.seeded_material import (
    PREAUTHORIZED_PROFILE,
    PREAUTHORIZED_PROFILE_V2,
    PREAUTHORIZED_PROFILES,
)
from secure_control.protocol.messages import CommittedStepReply, ReadyReceipt, StepAdvancePermit


def _wire_fixture(profile, dimensions=(4, 2, 1), identity_length=32, step=400):
    """固定公开布局和非零边界 residue；只编码完整六方向帧，不运行控制或计时。"""
    from secure_control.execution import localhost_codec as c
    from secure_control.protocol import Client
    from secure_control.protocol.messages import (
        ControllerLayout,
        ControllerScaleLedger,
        ControlShareMessage,
        InputShareMessage,
        MatrixCommitAuthorization,
        MatrixLocalStageReceipt,
        Protocol3EndpointCommand,
        public_step_plan_sha256,
    )
    n, m, p = dimensions
    q = 2**256-189
    run, session, epoch, round_id = (letter*identity_length for letter in 'rset')
    layout = ControllerLayout(n, m, p, ControllerScaleLedger(32,32,32,32,32,32,64,32,64,64))
    plan = Client._resource_plan(layout, session, round_id, step, encoding_profile=profile)
    digest = public_step_plan_sha256(plan)
    values = lambda count: tuple((q-1, q//2, 1, 0)[i % 4] for i in range(count))
    block = lambda count: c._encode_integer_residues(values(count), count, q)
    frames = []
    def frame(sender, recipient, operation, payload, *, kind='request', prefix=False, sequence=1234):
        frames.append(c.WireEnvelope(c.SCHEMA_VERSION, kind, sender, recipient, sequence,
            operation, session, None if prefix else round_id, step, None, payload))
    selected = StepAdvancePermit(run, session, epoch, step//400, step, round_id, 'a'*32,
        digest, step, step, version=profile if profile in PREAUTHORIZED_PROFILES else PREAUTHORIZED_PROFILE)
    ready = tuple(ReadyReceipt(selected, party, n) for party in (0, 1))
    for party in (0, 1):
        role = f'P{party+1}'
        inp = InputShareMessage(party, session, round_id, step, AdditiveShare(np.array(values(m), dtype=object)))
        online = c._CompactOnlinePayload(inp, run, epoch, digest, b'' if party == 0 else block(n+p+2*n), profile)
        output = ControlShareMessage(party, session, round_id, step, 64,
                                     AdditiveShare(np.array(values(p), dtype=object)))
        if profile in PREAUTHORIZED_PROFILES:
            frame('Client', role, 'online_permit', c._PreauthorizedOnlinePayload(online, selected))
            context = c._PermitContext(selected) if profile == PREAUTHORIZED_PROFILE_V2 else None
            reply = (c._compact_committed_reply(context, ready[party], ready[1-party], step+1, step+1,
                output, plan, q) if context is not None else CommittedStepReply(ready[party], ready[1-party],
                  step+1, step+1, c.encode_wire_value(output)))
            frame(role, 'Client', 'online_permit', reply, kind='reply')
            peer = f'P{2-party}'
            identity = (run, session, epoch, step//400, step, step, 'c'*64)
            frame(role, peer, 'peer_prefix', c._PrefixPayload(identity, party, block((n+p)*(n+m)+n)), prefix=True)
            frame(role, peer, 'peer_suffix', c._SuffixReference(context.permit_ref, party, block(m))
                  if context is not None else c._SuffixPayload(selected, party, block(m)))
            frame(role, peer, 'peer_ready', context.compact_ready(ready[party])
                  if context is not None else ready[party])
        else:
            frame('Client', role, 'online_stage', online)
            receipt = MatrixLocalStageReceipt(party, session, round_id, step, 1, n, digest)
            frame(role, 'Client', 'online_stage', c.PartyStageResult(receipt, output), kind='reply')
            authorization = MatrixCommitAuthorization(digest, (0, 1), 1, n)
            command = Protocol3EndpointCommand('commit_staged', authorization=authorization)
            frame('Client', role, 'endpoint', command, sequence=1235)
            frame(role, 'Client', 'endpoint', None, kind='reply', sequence=1235)
            frame(role, f'P{2-party}', 'peer_batch', c._CompactBatchPayload('product', digest,
                run, epoch, None, 0, block((n+p)*(n+m)+n+m), profile))
    frame('P2', 'P1', 'peer_batch', c._CompactBatchPayload('truncation', digest, run, epoch,
                                                        None, 2, block(n), profile))
    return frames


def _frame_sizes(frames):
    from secure_control.execution.localhost_codec import encode_envelope
    totals = {}
    for frame in frames:
        key = f'{frame.sender}->{frame.recipient}'
        item = totals.setdefault(key, {'bytes': 0, 'frames': 0})
        item['bytes'] += len(encode_envelope(frame))+4
        item['frames'] += 1
    return totals


_BYTE_CASES = [
    ((4, 2, 1), 32, 0, (1504,2096,3719,2060,2096,4454)),
    ((4, 2, 1), 32, 400, (1514,2118,3741,2070,2118,4478)),
    ((4, 2, 1), 32, 999999999, (1550,2194,3825,2106,2194,4568)),
    ((4, 2, 1), 256, 400, (3754,4954,7325,4310,4954,8958)),
    ((1, 1, 1), 32, 400, (1434,2118,2461,1606,2118,3070)),
    ((2, 3, 2), 32, 400, (1518,2222,3269,1862,2222,3922)),
    ((8, 4, 3), 256, 999999999, (3798,5142,12017,4950,5142,13828)),
]


@pytest.mark.parametrize('dimensions,identity_length,step,v1_golden', _BYTE_CASES)
def test_v2_static_six_direction_bytes_and_frame_contract(dimensions, identity_length, step, v1_golden):
    from secure_control.execution.localhost_codec import decode_envelope, encode_envelope
    old_frames = _wire_fixture(PREAUTHORIZED_PROFILE, dimensions, identity_length, step)
    new_frames = _wire_fixture(PREAUTHORIZED_PROFILE_V2, dimensions, identity_length, step)
    old, new = _frame_sizes(old_frames), _frame_sizes(new_frames)
    # v1事前冻结值，不能把改后的编码器输出当作期望值。
    assert tuple(v['bytes'] for v in old.values()) == v1_golden
    for direction in old:
        assert new[direction]['frames'] == old[direction]['frames']
        assert new[direction]['bytes'] <= old[direction]['bytes']
    ab = lambda totals: sum(v['bytes'] for k, v in totals.items() if 'Client' in k)
    total = lambda totals: sum(v['bytes'] for v in totals.values())
    if dimensions == (4, 2, 1) and identity_length == 32:
        assert ab(new) <= ab(old)*0.8
        assert total(new) <= total(old)*0.85
    assert sum(v['frames'] for k, v in new.items() if 'Client' in k) == 4
    for frames, count in ((old_frames, 10), (new_frames, 2)):
        encoded = [encode_envelope(f) for f in frames]
        assert sum(v.count(b'"type":"StepAdvancePermit"') for v in encoded) == count
        for wire in encoded:
            assert encode_envelope(decode_envelope(wire)) == wire


def test_v2_permit_golden_domain_and_every_field_binding():
    from secure_control.execution.localhost_codec import _PermitContext
    selected = permit(version=PREAUTHORIZED_PROFILE_V2)
    context = _PermitContext(selected)
    assert context.permit_ref == '9a0584ac57a8c7d086ee58324f16acf0f11e9d77bfb64f26b95e66822c324a2a'
    # 固定独立字段序列亦覆盖NUL和非ASCII；不调用被测摘要产生expected。
    from hashlib import sha256
    expected = (b'["control-dynamic-matrix-preauthorized-v2","run","session","epoch",0,0,"round",'
        b'"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
        b'0,0,"commit_after_both_ready"]')
    assert context.permit_ref == sha256(b'secure-control.preauthorized-permit.v2\x00'+expected).hexdigest()
    changed = {'version':PREAUTHORIZED_PROFILE, 'run_id':'运行', 'session_id':'other',
        'controller_epoch':'other', 'segment_index':1, 'global_step':1, 'round_id':'other',
        'permit_id':'c'*32, 'plan_sha256':'d'*64, 'expected_state_version':1,
        'previous_physically_confirmed_count':1, 'policy':'other'}
    assert set(changed) == set(StepAdvancePermit.__dataclass_fields__)
    for name, value in changed.items():
        try:
            other = _PermitContext(replace(selected, **{name:value}))
        except ValueError:
            continue
        assert other.permit_ref != context.permit_ref
        with pytest.raises(ValueError):
            context.check(other.permit_ref)
    with pytest.raises(ValueError):
        context.check(context.permit_ref.upper())


def test_v2_output_sender_checks_and_deferred_decode_keep_commit_facts():
    from secure_control.execution import localhost_codec as c
    from secure_control.protocol import Client
    frames = _wire_fixture(PREAUTHORIZED_PROFILE_V2)
    request, reply = frames[0], frames[1]
    selected = request.payload.permit
    context = c._PermitContext(selected)
    original = reply.payload
    assert len(json.loads(c.encode_wire_value(original))['output_values']) == 44
    n, m, p, q = 4, 2, 1, 2**256-189
    layout = c.ControllerLayout(n, m, p, c.ControllerScaleLedger(32,32,32,32,32,32,64,32,64,64))
    plan = Client._resource_plan(layout, selected.session_id, selected.round_id, selected.global_step,
                                 encoding_profile=PREAUTHORIZED_PROFILE_V2)
    restored = c.decode_wire_value(c.encode_wire_value(original))
    own, peer = restored.committed_facts(context)
    output = restored.restore_output(context, plan, q)
    assert output.fractional_bits == 64 and output.value.value.tolist() == [q-1]
    assert c._compact_committed_reply(context, own, peer, 401, 401, output, plan, q) == original
    invalid = [replace(output, sender=True), replace(output, session_id='wrong'),
        replace(output, round_id='wrong'), replace(output, step=True), replace(output, fractional_bits=True),
        replace(output, value=AdditiveShare(np.array([[q-1]], dtype=object))),
        replace(output, value=AdditiveShare(np.array([q], dtype=object))),
        replace(output, value=AdditiveShare(np.array([True], dtype=object)))]
    for bad in invalid:
        with pytest.raises(ValueError):
            c._compact_committed_reply(context, own, peer, 401, 401, bad, plan, q)
    for scale, values in ((True, 'AA=='), (63, 'AA=='), (64, None), (64, {}), (64, '!!!!'), (None, [])):
        wire = json.loads(c.encode_wire_value(original))
        wire.update(output_fractional_bits=scale, output_values=values)
        bad = c.decode_wire_value(json.dumps(wire).encode())
        assert bad.committed_facts(context) == (own, peer)
        assert 'output_values_json' not in repr(bad) and 'output_fractional_bits_json' not in repr(bad)
        with pytest.raises(ValueError):
            bad.restore_output(context, plan, q)
    for name in ('extra', 'state_version'):
        wire = json.loads(c.encode_wire_value(original))
        wire[name] = True
        with pytest.raises(ValueError):
            c.decode_wire_value(json.dumps(wire).encode())
    wire = c.encode_wire_value(original)
    with pytest.raises(ValueError):
        c.decode_wire_value(wire.replace(b'"commit_status":"committed"',
            b'"commit_status":"committed","commit_status":"committed"'))
    with pytest.raises(ValueError):
        c.encode_wire_value(CommittedStepReply(own, peer, 401, 401, b'not a v2 format'))


def test_v2_peer_current_slot_rejects_replay_missing_context_and_wrong_envelopes(monkeypatch):
    from secure_control.execution import _localhost_peer as module
    from secure_control.execution import localhost_codec as c
    from secure_control.protocol import Client
    layout = c.ControllerLayout(4, 2, 1, c.ControllerScaleLedger(32,32,32,32,32,32,64,32,64,64))
    plan = Client._resource_plan(layout, 'session', 'round', 0, encoding_profile=PREAUTHORIZED_PROFILE_V2)
    selected = permit(version=PREAUTHORIZED_PROFILE_V2, plan_sha256=module.public_step_plan_sha256(plan))
    class Connection:
        def shutdown(self, *args):
            pass
        def close(self):
            pass
    def port():
        result = module.LocalhostProtocol3PeerPort(Connection(), 'P1', 8*1024*1024, 1.,
            batch_enabled=True, wire_profile=PREAUTHORIZED_PROFILE_V2)
        result.bind('session')
        result.set_batch_round(plan, modulus=2**256-189, run_id='run', epoch_id='epoch')
        return result
    local = port()
    ready = ReadyReceipt(selected, 0, 4)
    local._v3_phase = 'truncated'
    with pytest.raises(ValueError, match='上下文'):
        local.exchange_ready(ready)
    local._v3_phase = 'prepared'
    context = local.install_permit(selected)
    with pytest.raises(ValueError):
        local.install_permit(selected)
    received = c._ReadyReference(context.permit_ref, c._ReadyFacts(1, 4))
    for changes in ({'sequence':2}, {'sender':'P1','recipient':'P2',
                    'payload':c._ReadyReference(context.permit_ref, c._ReadyFacts(0, 4))},
                    {'round_id':'other'}, {'step':1}, {'session_id':'other'}):
        response = c.WireEnvelope(c.SCHEMA_VERSION, 'request', 'P2', 'P1', 1,
            'peer_ready', 'session', 'round', 0, None, received)
        monkeypatch.setattr(module, '_exchange_frame',
            lambda *a, response=response, changes=changes, **k: c.encode_envelope(replace(response, **changes)))
        local._v3_phase = 'truncated'
        with pytest.raises(ValueError):
            local.exchange_ready(ready)
    for other in (replace(selected, controller_epoch='other'), replace(selected, run_id='other'),
                  replace(selected, segment_index=1), replace(selected, plan_sha256='e'*64),
                  replace(selected, global_step=1, expected_state_version=1, previous_physically_confirmed_count=1)):
        # 同permit_id不能让不同内容或旧步绑定当前槽。
        wrong = c._ReadyReference(c._PermitContext(other).permit_ref, c._ReadyFacts(1, 4))
        monkeypatch.setattr(local, '_exchange_preauthorized', lambda *a, wrong=wrong: wrong)
        local._v3_phase = 'truncated'
        with pytest.raises(ValueError):
            local.exchange_ready(ready)
    monkeypatch.setattr(local, '_exchange_preauthorized', lambda *a: received)
    local._v3_phase = 'truncated'
    assert local.exchange_ready(ready) == ReadyReceipt(selected, 1, 4)
    with pytest.raises(ValueError):
        local.exchange_ready(ready)
    local.retire_permit()
    assert local._permit_context is None
    with pytest.raises(ValueError):
        local._current_permit(selected)
    local.close()
    assert local._permit_context is None


def test_prefix_public_cache_lifetime_and_bounded_max_failure_locations(monkeypatch):
    from test_two_party_protocol import make_stack

    from secure_control.protocol import P1
    from secure_control.protocol import coordinator as module
    from secure_control.protocol.roles import _seeded_context
    client, _, _, _, distribution = make_stack()
    q = client.fixed_point.modulus
    original = module.replace
    calls = []
    def canonical(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)
    monkeypatch.setattr(module, 'replace', canonical)
    digests = []
    class Peer:
        def exchange_prefix(self, identity, e, fx, modulus):
            assert identity[-1] == digests[-1]
            return AdditiveShare(np.zeros_like(e)), AdditiveShare(np.zeros_like(fx))
    for profile, epoch, security in ((PREAUTHORIZED_PROFILE, 'epoch', 8),
            (PREAUTHORIZED_PROFILE_V2, 'epoch', 8), (PREAUTHORIZED_PROFILE_V2, 'next', 9)):
        context = _seeded_context(distribution.p1.layout, 'run', distribution.session_id,
                                  epoch, 0, q, security, profile)
        expected = replace(context, party=0).digest().hex()
        digests.append(expected)
        recovery = module._OnlineMaterialRecovery(distribution.p1, modulus=q,
            security_parameter=security, modulus_evidence=None)
        before = len(calls)
        recovery.install_seeded(context, bytes(range(32)))
        assert len(calls) == before+1 and recovery._prefix_context_sha256 == expected
        clock = iter((100, 150, 200, 600))
        with monkeypatch.context() as patch:
            patch.setattr(module.time, 'perf_counter_ns', lambda clock=clock: next(clock))
            recovery.prepare_prefix(P1(distribution.p1), Peer(), 0, 'startup')
            assert len(calls) == before+1
            recovery._seeded_next = 1
            with pytest.raises(ValueError):
                recovery.prepare_prefix(P1(distribution.p1), Peer(), 1, 'segment_advance')
        stats = recovery.prefix_statistics
        failed = {'global_step':1, 'segment_index':1, 'origin':'segment_advance'}
        assert stats['count'] == 2 and stats['sum_ns'] == 450 and stats['max_ns'] == 400
        assert stats['max_identity'] == stats['first_error_identity'] == stats['last_identity'] == failed
        assert stats['first_error'] == 'ValueError' and recovery._prefix_context_sha256 is None
        assert set(stats) == {'count', 'sum_ns', 'max_ns', 'cpu_ns', 'last_ns', 'first_error',
                             'max_identity', 'last_identity', 'first_error_identity'}
        assert recovery._prefix is None
        with pytest.raises(ValueError):
            recovery.install_seeded(context, bytes(range(32)))
        recovery.close_seeded()
    assert len(set(digests)) == 3


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


def _party(config, ports, queue, fault=None, profile=PREAUTHORIZED_PROFILE):
    from secure_control.execution import lan_runtime
    from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
    from secure_control.experiments.communication_benchmark import _party_job
    from secure_control.protocol.coordinator import (
        LocalProtocol3PartyEndpoint,
        _OnlineMaterialRecovery,
    )
    peer_operations = {'peer_prefix':0, 'peer_suffix':0, 'peer_ready':0, 'truncation':0}
    original_exchange = LocalhostProtocol3PeerPort._exchange_preauthorized
    original_send_batch = LocalhostProtocol3PeerPort._send_batch
    def exchange(port, operation, *args):
        peer_operations[operation] += 1
        return original_exchange(port, operation, *args)
    def send_batch(port, plan, phase, *args, **kwargs):
        if phase == 'truncation':
            peer_operations['truncation'] += 1
        return original_send_batch(port, plan, phase, *args, **kwargs)
    LocalhostProtocol3PeerPort._exchange_preauthorized = exchange
    LocalhostProtocol3PeerPort._send_batch = send_batch
    class ResultQueue:
        def put(self, result):
            queue.put({**result, 'peer_operations':peer_operations})
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
    _party_job(config, ports, 0, True, ResultQueue(), wire_profile=profile)


_SESSION_FAULTS = [None, 'lost_final', 'bad_output', 'late_after_commit', 'partial_send',
                  'stage_failed', 'ready_missing', 'ready_mismatch', 'after_ready_exit', 'first_prefix']
_V2_OUTPUT_FAULTS = ['bad_base64', 'null_output', 'bool_scale', 'wrong_length', 'out_of_range',
                     'wrong_output_type', 'noncanonical_base64']


@pytest.mark.parametrize('profile,fault,segment_steps',
    [(PREAUTHORIZED_PROFILE, f, s) for f in _SESSION_FAULTS for s in (1, 2)]
    +[(PREAUTHORIZED_PROFILE_V2, f, 2) for f in _SESSION_FAULTS+_V2_OUTPUT_FAULTS]
    +[(PREAUTHORIZED_PROFILE_V2, None, 1)])
def test_real_short_sessions_single_exchange_and_failure_accounting(monkeypatch, segment_steps, fault, profile):
    from secure_control.execution import lan_runtime, localhost_transport
    from secure_control.execution.localhost_codec import decode_envelope
    from secure_control.experiments.communication_benchmark import _config, _ports
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    ports = _ports()
    ctx = mp.get_context('spawn')
    queue = ctx.Queue()
    parties = [ctx.Process(target=_party, args=(_config(role, ports), ports, queue, fault, profile)) for role in ('P1', 'P2')]
    runtime = None
    try:
        prepared = load_segmented_experiment(_config('Client', ports).experiment_config,
                                              segment_steps, InteractiveSession())
        for party in parties:
            party.start()
        runtime = lan_runtime.LanSegmentedRuntime(_config('Client', ports), prepared.spec, prepared.context,
            prepared.contract, prepared.security_parameter, prepared.evidence, control=lan_runtime.RunControl(),
            segment_capacity=segment_steps, wire_profile=profile)
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
                if fault == 'bad_output' and profile == PREAUTHORIZED_PROFILE:
                    return replace(response, payload=replace(response.payload, output=b'not JSON'))
                if fault == 'bad_output' or fault in _V2_OUTPUT_FAULTS:
                    import base64

                    from secure_control.execution.localhost_codec import (
                        decode_wire_value,
                        encode_wire_value,
                    )
                    value = json.loads(encode_wire_value(response.payload))
                    if fault == 'bool_scale':
                        value['output_fractional_bits'] = True
                    else:
                        value['output_values'] = {'bad_output': '?', 'bad_base64': '!!!!', 'null_output': None,
                            'wrong_length': base64.b64encode(bytes(31)).decode(), 'out_of_range':
                            base64.b64encode(prepared.context.modulus.to_bytes(32, 'big')).decode(),
                            'wrong_output_type': {'bad': True}, 'noncanonical_base64': 'AB=='}[fault]
                    return replace(response, payload=decode_wire_value(json.dumps(value).encode()))
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
            after_commit = fault in ('bad_output', 'late_after_commit', *_V2_OUTPUT_FAULTS)
            assert runtime.protocol_committed_count == (1 if after_commit else 0)
            observation = runtime.last_commit_observation
            assert observation['parties']['P1']['valid_ack_received'] == (
                fault in ('lost_final', 'after_ready_exit') or after_commit)
            if after_commit:
                assert runtime.phase == 'FAILED_AFTER_COMMIT'
                assert runtime.resource_counts['matrix_products_consumed'] == 1
                assert runtime.resource_counts['truncations_consumed'] == prepared.spec.state_dimension
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
        if fault is None:
            outcomes = [queue.get(timeout=5) for _ in parties]
            assert all(item['status'] == 'closed' for item in outcomes), outcomes
            for item in outcomes:
                assert item['peer_operations'] == {'peer_prefix': 5 if segment_steps == 1 else 6,
                    'peer_suffix':5, 'peer_ready':5, 'truncation':5 if item['role'] == 'P2' else 0}
    finally:
        if runtime is not None:
            runtime.close()
        for party in parties:
            if party.pid:
                party.join(5)
                if party.is_alive():
                    party.terminate()
                    party.join(5)
        if fault is None:
            assert all(party.exitcode == 0 for party in parties)
        queue.close()
        queue.join_thread()


@pytest.mark.parametrize('fault', ['wrong_version', 'wrong_segment', 'wrong_epoch', 'wrong_profile', 'duplicate_bind'])
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
    if fault == 'wrong_profile':
        selected = replace(selected, version=PREAUTHORIZED_PROFILE_V2)
    if fault == 'duplicate_bind':
        online, bound = recovery.restore_preauthorized(material, selected, role)
        assert online.resources.product_resources[0].triple._lifecycle is token
        assert bound is prefix and token.masked_parties == {0, 1}
    with pytest.raises(ValueError):
        recovery.restore_preauthorized(material, selected, role)
    assert recovery._prefix is None and recovery._seeded_key is None
    with pytest.raises(ValueError):
        prefix.bind(material.product_resources[0].w)


@pytest.mark.parametrize('profile', PREAUTHORIZED_PROFILES)
def test_preauthorized_next_prepare_failure_preserves_prior_double_commit(profile):
    from test_seeded_material import (
        test_seeded_ack_then_prepare_failure_belongs_to_next_round_only as exercise,
    )
    exercise(profile=profile)


def test_seed_profile_domains_are_distinct_and_mixed_contexts_are_rejected():
    from test_two_party_protocol import make_stack

    from secure_control.crypto.seeded_material import SEEDED_PROFILE, dealer_corrections
    from secure_control.protocol.roles import _seeded_context
    client, _, _, _, distribution = make_stack()
    c = _seeded_context(distribution.p1.layout, 'run', distribution.session_id, 'epoch', 0,
                         client.fixed_point.modulus, 8)
    assert c.profile == SEEDED_PROFILE
    assert len({replace(c, profile=p).digest() for p in (SEEDED_PROFILE, *PREAUTHORIZED_PROFILES)}) == 3
    for profile in PREAUTHORIZED_PROFILES:
        with pytest.raises(ValueError, match='上下文'):
            dealer_corrections((bytes(32), bytes([1])*32),
                (c, replace(c, party=1, profile=profile)), 0, client.truncation)


@pytest.mark.parametrize('profile', PREAUTHORIZED_PROFILES)
@pytest.mark.parametrize('fault', ['cancel_after_commit', 'plant_failure'])
def test_original_headless_runner_never_counts_failed_or_cancelled_physical_step(monkeypatch, fault, profile):
    from secure_control.execution import lan_runtime
    from secure_control.experiments.communication_benchmark import _config, _ports
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.experiments.lan_runner import _run_prepared_segmented
    from secure_control.experiments.live_timing import LiveTimingCollector
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    ports = _ports()
    ctx = mp.get_context('spawn')
    queue = ctx.Queue()
    parties = [ctx.Process(target=_party, args=(_config(role, ports), ports, queue, None, profile)) for role in ('P1', 'P2')]
    session = InteractiveSession()
    selected = replace(_config('Client', ports), wire_profile=profile)
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
