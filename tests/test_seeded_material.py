"""D132-7固定向量、独立代数/Protocol 2、角色单槽及真实短联调；非性能循环。"""

import hmac
import random
from dataclasses import replace

import numpy as np
import pytest

from secure_control.crypto import AdditiveShare, SecureTruncation, TwoPartySharing
from secure_control.crypto.seeded_material import (
    SEEDED_PROFILE,
    SeededContext,
    dealer_corrections,
    expand_party,
    expand_residue,
)


def _context(party=0, q=2**61-1, ell=8, dimensions=(2,1,1), security=8):
    return SeededContext('run','session','epoch',party,q,dimensions,
        (ell,ell,ell,ell,ell,ell,2*ell,ell,2*ell,2*ell),security)


def test_seeded_rfc4231_and_fixed_encoding_vectors():
    """RFC4231§4.2原语向量；独立JSON/struct+HMAC reference锁定项目字节向量。"""
    assert hmac.digest(bytes([11])*20,b'Hi There','sha256').hex() == (
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
    context = _context()
    assert context.digest().hex() == '09828f6c636542da619a3a31f9d900a6cbb784e10294da6c09ea4bd13583d5d0'
    expected = {b'U':2092944468097547728,b'V':1148672793109831038,b'W':263392411593068148,
                b'r':1639045353779274445,b'r-prime':696733048979632239}
    for tag,value in expected.items():
        assert expand_residue(bytes(range(32)),context.digest(),7,tag,0,context.modulus) == value
    for field,value in (('run_id','other'),('session_id','other'),('epoch','other'),('party',1),
                         ('modulus',2**61-19),('dimensions',(1,2,1)),('security_parameter',9)):
        assert replace(context,**{field:value}).digest() != context.digest()
    changed = _context(ell=9)
    assert changed.digest() != context.digest()
    assert expand_residue(bytes(range(32)),context.digest(),8,b'U',0,context.modulus) != expected[b'U']
    assert expand_residue(bytes(range(32)),context.digest(),7,b'U',1,context.modulus) != expected[b'U']


def test_seeded_rejection_is_unbiased_bounded_and_never_modulo_fallback(monkeypatch):
    from secure_control.crypto import seeded_material as module

    seen = []
    def digest(key,message,name):
        seen.append(message)
        return b'\x01\x01'+bytes(30) if len(seen) == 1 else b'\x00\x01'+bytes(30)
    monkeypatch.setattr(module.hmac,'digest',digest)
    assert expand_residue(bytes(32),bytes(32),0,b'U',0,257) == 1
    assert [m[-2:] for m in seen] == [b'\0\0',b'\0\1']
    seen.clear()
    monkeypatch.setattr(module.hmac,'digest',lambda *a: (seen.append(None),b'\xff'*32)[1])
    with pytest.raises(RuntimeError,match='耗尽'):
        expand_residue(bytes(32),bytes(32),0,b'U',0,257)
    assert len(seen) == 256
    for step in (-1,True,1<<64):
        with pytest.raises(ValueError):
            expand_residue(bytes(32),bytes(32),step,b'U',0,257)
    with pytest.raises(ValueError):
        _context(q=1<<256)
    with pytest.raises(ValueError):
        _context(party=True)


@pytest.mark.parametrize('q,ell,dimensions', [(2**61-1,8,(2,1,1)),(None,32,(4,2,1))])
def test_seeded_corrections_have_independent_matrix_oracle_and_exact_material_bytes(q,ell,dimensions):
    evidence,security = None,8
    if q is None:
        from pathlib import Path

        from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
        from secure_control.scenarios.cart_pole.interactive import InteractiveSession
        prepared = load_segmented_experiment(Path('configs/cart_pole_observer_lan.example.yaml'),400,InteractiveSession())
        q,evidence,security = prepared.context.modulus,prepared.evidence,prepared.security_parameter
    contexts = (_context(q=q,ell=ell,dimensions=dimensions,security=security),
                _context(1,q,ell,dimensions,security))
    keys = (bytes(range(32)),bytes(range(32,64)))
    truncation = SecureTruncation(TwoPartySharing(q),ell,security,modulus_evidence=evidence)
    correction = dealer_corrections(keys,contexts,400,truncation)
    a,b = (expand_party(k,c,400) for k,c in zip(keys,contexts,strict=True))
    rows,inner = dimensions[0]+dimensions[2],dimensions[0]+dimensions[1]
    expected = [[sum(((int(a.u[i,j])+int(b.u[i,j]))%q)*((int(a.v[j,0])+int(b.v[j,0]))%q)
                      for j in range(inner))%q] for i in range(rows)]
    assert [[(int(a.w[i,0])+correction[i])%q] for i in range(rows)] == expected
    assert len(correction) == rows+2*dimensions[0] and b.w is None and b.truncations == ()
    for (r1,rp1),r2,rp2 in zip(a.truncations,correction[rows::2],correction[rows+1::2],strict=True):
        r,rp = (r1+r2)%q,(rp1+rp2)%q
        r = r if r < (q+1)//2 else r-q
        rp = rp if rp < (q+1)//2 else rp-q
        bits = truncation.kappa-ell+security
        assert -(1<<(bits-1)) <= r < 1<<(bits-1)
        assert -(1<<(ell-1)) <= rp < 1<<(ell-1)
    if q.bit_length() == 256:
        assert len(correction)*32 == 416
        assert 2*(rows*inner+inner+rows+2*dimensions[0])*32 == 3136
    assert all(type(v) is int for v in correction)
    assert not np.shares_memory(a.u,b.u)
    assert not np.shares_memory(a.u,expand_party(keys[0],contexts[0],401).u)
    with pytest.raises(ValueError):
        dealer_corrections((keys[0],keys[0]),contexts,400,truncation)


def test_seeded_truncation_preserves_same_bounded_masks_and_protocol_two_output():
    truncation = SecureTruncation(TwoPartySharing(2**61-1),8,8)
    q = truncation.sharing.modulus
    ordinary = truncation.create_auxiliary(rng=random.Random(95))
    supplied = truncation.create_auxiliary(rng=random.Random(95),first_shares=(AdditiveShare(0),AdditiveShare(q-1)))
    for name in ('r','r_prime'):
        assert truncation.sharing.reconstruct(*(getattr(v,name) for v in ordinary)) == (
            truncation.sharing.reconstruct(*(getattr(v,name) for v in supplied)))
    outputs = []
    for aux in (ordinary,supplied):
        shares = truncation.share_message(-16385,rng=random.Random(81))
        masked = [truncation.mask_input(shares[p],aux[p]) for p in (0,1)]
        public = truncation.p1_reconstruct_masked(masked[0],truncation.p2_send_masked(masked[1]))
        results = (truncation.finish_p1(shares[0],aux[0],public),truncation.finish_p2(shares[1],aux[1]))
        value = truncation.sharing.reconstruct(*results)
        outputs.append(value if value < (q+1)//2 else value-q)
    assert outputs[0] == outputs[1]
    assert abs(outputs[0]-truncation.paper_round_divide(-16385)) <= 1
    for bad in (True,-1,q):
        with pytest.raises((TypeError,ValueError)):
            truncation.create_auxiliary(first_shares=(AdditiveShare(bad),AdditiveShare(0)))


def test_seeded_protocol_single_slot_claim_failure_and_fresh_lifecycles(monkeypatch):
    from test_two_party_protocol import make_stack

    from secure_control.protocol import Client
    from secure_control.protocol.coordinator import _OnlineMaterialRecovery
    from secure_control.protocol.messages import InputShareMessage
    from secure_control.protocol.roles import _seeded_context

    client,_,_,_,distribution = make_stack()
    q = client.fixed_point.modulus
    recoveries,contexts = [],[]
    keys = (bytes(range(32)),bytes(range(32,64)))
    for p,offline in enumerate((distribution.p1,distribution.p2)):
        context = _seeded_context(offline.layout,'run',offline.session_id,'epoch',p,q,8)
        recovery = _OnlineMaterialRecovery(offline,modulus=q,security_parameter=8,modulus_evidence=None)
        recovery.install_seeded(context,keys[p])
        assert recovery.seeded_statistics['prepared_count'] == 1
        with pytest.raises(RuntimeError):
            recovery.prepare_seeded()
        contexts.append(context)
        recoveries.append(recovery)
    plan = Client._resource_plan(distribution.p1.layout,distribution.session_id,'round',0,encoding_profile=SEEDED_PROFILE)
    correction = dealer_corrections(keys,tuple(contexts),0,client.truncation)
    restored = []
    for p,recovery in enumerate(recoveries):
        inp = InputShareMessage(p,plan.session_id,plan.round_id,0,AdditiveShare(np.zeros(1,dtype=object)))
        material = recovery.claim_seeded(inp,plan,() if p == 0 else correction)
        restored.append(recovery.restore(material))
        assert recovery._seeded_slot is None and recovery._seeded_next == 1
        recovery.prepare_seeded()
        assert recovery.seeded_statistics['prepared_count'] == 2
        with pytest.raises(ValueError):
            recovery.claim_seeded(inp,plan,() if p == 0 else correction)
        assert recovery._seeded_key is None and recovery._seeded_slot is None
        with pytest.raises(ValueError):
            recovery.install_seeded(contexts[p],keys[p])
    assert restored[0].resources.product_resources[0].triple._lifecycle is not restored[1].resources.product_resources[0].triple._lifecycle
    def fail(*args):
        raise RuntimeError('test prepare failure')
    from secure_control.protocol import coordinator
    monkeypatch.setattr(coordinator,'expand_party',fail)
    fresh = _OnlineMaterialRecovery(distribution.p1,modulus=q,security_parameter=8,modulus_evidence=None)
    with pytest.raises(RuntimeError):
        fresh.install_seeded(contexts[0],keys[0])
    assert fresh._seeded_key is None and fresh._seeded_slot is None


def test_seeded_wire_strict_lengths_profile_and_secret_repr():
    from test_two_party_protocol import make_stack

    from secure_control.execution import localhost_codec as codec
    from secure_control.execution.lan_runtime import _restore_compact_online
    from secure_control.protocol import Client
    from secure_control.protocol.coordinator import _OnlineMaterialRecovery
    from secure_control.protocol.messages import InputShareMessage, public_step_plan_sha256
    from secure_control.protocol.roles import _seeded_context

    client,_,_,_,distribution = make_stack()
    q = client.fixed_point.modulus
    contexts = tuple(_seeded_context(distribution.p1.layout,'run',distribution.session_id,'epoch',p,q,8) for p in (0,1))
    keys = (bytes(range(32)),bytes(range(32,64)))
    correction = dealer_corrections(keys,contexts,0,client.truncation)
    plan = Client._resource_plan(distribution.p1.layout,distribution.session_id,'round',0,encoding_profile=SEEDED_PROFILE)
    for p,offline in enumerate((distribution.p1,distribution.p2)):
        seed = codec._SeedInitPayload('run','epoch',p,contexts[p].digest().hex(),keys[p])
        assert 'key=' not in repr(seed)
        assert codec.decode_wire_value(codec.encode_wire_value(seed)) == seed
        with pytest.raises(ValueError):
            codec.WireEnvelope(codec.SCHEMA_VERSION,'request','Client','P2' if p == 0 else 'P1',
                4,'seed_init',plan.session_id,None,None,None,seed)
        with pytest.raises(ValueError):
            replace(seed,key=keys[p][:-1])
        inp = InputShareMessage(p,plan.session_id,'round',0,AdditiveShare(np.zeros(1,dtype=object)))
        data = b'' if p == 0 else codec._encode_integer_residues(correction,len(correction),q)
        payload = codec._CompactOnlinePayload(inp,'run','epoch',public_step_plan_sha256(plan),data,SEEDED_PROFILE)
        assert codec.decode_wire_value(codec.encode_wire_value(payload)) == payload
        if p == 0:
            with pytest.raises(ValueError):
                replace(payload,values=b'\0')
            with pytest.raises(ValueError):
                replace(payload,version='control-dynamic-matrix-v1')
        args = {'layout':offline.layout,'session':plan.session_id,'round_id':'round','step':0,
                'modulus':q,'run_id':'run','epoch_id':'epoch','party':p,'wire_profile':SEEDED_PROFILE}
        for field,value in (('plan_sha256','0'*64),('epoch_id','wrong'),('run_id','wrong')):
            with pytest.raises(ValueError):
                _restore_compact_online(replace(payload,**{field:value}),**args)
        recovery = _OnlineMaterialRecovery(offline,modulus=q,security_parameter=8,modulus_evidence=None)
        recovery.install_seeded(contexts[p],keys[p])
        restored = _restore_compact_online(payload,**args,seeded_recovery=recovery)
        assert recovery.restore(restored).resources.plan == plan
        if p == 1:
            for malformed in (data[:-1],data+b'\0',q.to_bytes(4,'big')+data[4:]):
                with pytest.raises(ValueError):
                    _restore_compact_online(replace(payload,values=malformed),**args,seeded_recovery=recovery)


def test_seeded_preparation_respects_finite_horizon_and_worker_spec_is_public():
    from test_two_party_protocol import make_stack

    from secure_control.execution._material_worker import _WorkerSpec
    from secure_control.protocol import Client
    from secure_control.protocol.coordinator import _OnlineMaterialRecovery
    from secure_control.protocol.messages import InputShareMessage
    from secure_control.protocol.roles import _seeded_context

    client,_,_,_,distribution = make_stack()
    offline = replace(distribution.p1,range_contract=replace(distribution.range_contract,horizon_steps=1))
    q = client.fixed_point.modulus
    context = _seeded_context(offline.layout,'run',offline.session_id,'epoch',0,q,8)
    recovery = _OnlineMaterialRecovery(offline,modulus=q,security_parameter=8,modulus_evidence=None)
    recovery.install_seeded(context,bytes(32))
    plan = Client._resource_plan(offline.layout,offline.session_id,'round',0,encoding_profile=SEEDED_PROFILE)
    inp = InputShareMessage(0,plan.session_id,'round',0,AdditiveShare(np.zeros(1,dtype=object)))
    recovery.claim_seeded(inp,plan,())
    assert recovery.prepare_seeded() is False and recovery._seeded_slot is None
    assert recovery.seeded_statistics['prepared_count'] == 1
    assert not any('seed' in field or 'key' in field for field in _WorkerSpec.__dataclass_fields__)


def _party_with_next_prepare_failure(config,ports,queue):
    """只在测试子进程注入ACK后的第二槽失败，绝不修改实际用户进程。"""
    from secure_control.experiments.communication_benchmark import _party_job
    from secure_control.protocol import coordinator

    original = coordinator.expand_party
    def expand(key,context,step):
        if context.party == 0 and step == 1:
            raise RuntimeError('test next preparation failure')
        return original(key,context,step)
    coordinator.expand_party = expand
    _party_job(config,ports,0,True,queue,wire_profile=SEEDED_PROFILE)


def test_seeded_ack_then_prepare_failure_belongs_to_next_round_only():
    import multiprocessing as mp

    from secure_control.execution import lan_runtime
    from secure_control.experiments.communication_benchmark import _config, _ports
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    ports = _ports()
    context = mp.get_context('spawn')
    queue = context.Queue()
    parties = [context.Process(target=_party_with_next_prepare_failure,args=(_config(r,ports),ports,queue))
               for r in ('P1','P2')]
    runtime = None
    try:
        prepared = load_segmented_experiment(_config('Client',ports).experiment_config,2,InteractiveSession())
        for party in parties:
            party.start()
        runtime = lan_runtime.LanSegmentedRuntime(_config('Client',ports),prepared.spec,prepared.context,
            prepared.contract,prepared.security_parameter,prepared.evidence,control=lan_runtime.RunControl(),
            segment_capacity=2,wire_profile=SEEDED_PROFILE)
        runtime.enable_material_preparation(slots=4,_candidate='worker')
        first = runtime.step(np.zeros(2))
        runtime.confirm_applied(first)
        assert runtime.confirmed_step_count == runtime.protocol_committed_count == 1
        with pytest.raises(RuntimeError) as caught:
            runtime.step(np.zeros(2))
        assert caught.value.phase == 'MATERIAL_PREPARE_NEXT'
        assert runtime.confirmed_step_count == runtime.protocol_committed_count == 1
    finally:
        if runtime is not None:
            runtime.close()
        for party in parties:
            if party.pid:
                party.join(6)
                if party.is_alive():
                    party.terminate()
                    party.join(5)
        queue.close()
        queue.join_thread()


@pytest.mark.parametrize('fault',[None,'worker_exit','commit_ack','advance_ack'])
def test_seeded_spawn_worker_short_segments_and_original_failure_clearance(monkeypatch,fault):
    from test_matrix_beaver import (
        test_matrix_spawn_worker_segments_and_uncertain_failures as exercise,
    )

    exercise(monkeypatch,fault,profile=SEEDED_PROFILE)
