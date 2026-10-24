"""矩阵向量原语的独立整数oracle与一次性/形状边界。"""

import random
from dataclasses import replace

import numpy as np
import pytest

from secure_control.crypto import AdditiveShare, TwoPartySharing
from secure_control.crypto.matrix_beaver import MatrixBeaverMultiplier


def _matrix_plan_fields(n, m, p, ell, step):
    """直接列出公开字段供旧语义oracle使用，不调用待测计划构造器生成期望。"""
    from secure_control.protocol.messages import (
        ControllerScaleLedger,
        MatrixProductMetadata,
        ResourceMetadata,
    )

    session, round_id = '会话"\\', f'轮次-{step}'
    records = [{'resource_id':f'{round_id}:state[{i}]', 'session_id':session,
        'round_id':round_id, 'step':step, 'kind':'state_truncation', 'term':'state',
        'index':(i,), 'shape':(n,), 'left_fractional_bits':2*ell,
        'right_fractional_bits':None, 'output_fractional_bits':ell} for i in range(n)]
    kwargs = {'session_id':session, 'round_id':round_id, 'step':step,
        'state_shape':(n,), 'input_shape':(m,), 'output_shape':(p,),
        'scale_ledger':ControllerScaleLedger(ell, ell, ell, ell, ell, ell, 2*ell, ell, 2*ell, 2*ell),
        'product_resources':(MatrixProductMetadata(round_id+':matrix', session, round_id, step, n+p, n+m),),
        'state_truncation_resources':tuple(ResourceMetadata(**item) for item in records)}
    return kwargs, tuple(ResourceMetadata(**item) for item in records)


@pytest.mark.parametrize('dimensions,ell,step', [((1,2,1),1,0), ((2,1,3),7,3), ((4,2,1),32,2**80+3)])
def test_matrix_plan_validation_matches_old_json_and_independent_digest(dimensions, ell, step):
    """全部字段及非规范输入按旧比较裁决；摘要期望来自原始kwargs和旧JSON字节。"""
    import json
    from dataclasses import asdict, fields
    from hashlib import sha256

    from secure_control.protocol.messages import (
        MatrixStepResourcePlan,
        ResourceMetadata,
        public_step_plan_sha256,
    )

    kwargs, expected = _matrix_plan_fields(*dimensions, ell, step)
    original = kwargs['state_truncation_resources']
    def old_check(resources):
        if (type(resources) is not tuple or any(type(v) is not ResourceMetadata for v in resources)
                or json.dumps([asdict(v) for v in resources], sort_keys=True)
                   != json.dumps([asdict(v) for v in expected], sort_keys=True)):
            raise ValueError('矩阵状态截断计划错误')
    def check(resources):
        try:
            old_check(resources)
        except (TypeError, ValueError, RecursionError) as error:
            with pytest.raises(type(error)):
                MatrixStepResourcePlan(**dict(kwargs, state_truncation_resources=resources))
            return type(error)
        plan = MatrixStepResourcePlan(**dict(kwargs, state_truncation_resources=resources))
        # 不规范化历史兼容的list/子类，也不换成“当前轮”的另一个元数据对象。
        assert plan.state_truncation_resources is resources
        assert plan.session_id == kwargs['session_id'] and plan.step == step
        return None
    assert check(original) is None
    plan = MatrixStepResourcePlan(**kwargs)
    raw = dict(kwargs, scale_ledger=asdict(kwargs['scale_ledger']),
        product_resources=[asdict(v) for v in kwargs['product_resources']],
        state_truncation_resources=[asdict(v) for v in expected],
        version='matrix-dynamic-plan-v1', arithmetic_profile='matrix-beaver-v1', order='row-major/state-first')
    encoded = json.dumps(raw, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    assert public_step_plan_sha256(plan) == sha256(b'matrix-dynamic-plan-v1\0'+encoded).hexdigest()
    changes = {'resource_id':'wrong', 'session_id':'other-session', 'round_id':'other-round', 'step':step+1,
        'kind':'multiplication', 'term':'A', 'index':(-1,), 'shape':(dimensions[0]+1,),
        'left_fractional_bits':-1, 'right_fractional_bits':0, 'output_fractional_bits':ell+1}
    assert set(changes) == {f.name for f in fields(ResourceMetadata)}
    # 首/末项逐字段覆盖，不能只检查id、忽略尾部或用截断zip比较。
    for index in {0, len(original)-1}:
        for name, value in changes.items():
            changed = original[:index]+(replace(original[index], **{name:value}),)+original[index+1:]
            assert check(changed) is ValueError, (index, name)
    for resources in (original[:-1], original+(original[-1],), None, list(original), (object(),)):
        assert check(resources) is ValueError
    if len(original)>1:
        assert check(original[::-1]) is ValueError
    # Python相等会把这些数值当作原整数；旧JSON明确区分bool/float。
    for name, value in (('index',(False,)), ('index',(0.,)), ('shape',(float(dimensions[0]),)),
                        ('left_fractional_bits',float(2*ell)), ('output_fractional_bits',float(ell))):
        changed = replace(original[0], **{name:value})
        assert changed == original[0]
        assert check((changed, *original[1:])) is ValueError
    class PublicInt(int):
        pass
    class PublicString(str):
        pass
    class PublicTuple(tuple):
        pass
    class MetadataSubclass(ResourceMetadata):
        pass
    for name, value in (('index',[0]), ('shape',[dimensions[0]]), ('index',PublicTuple((0,))),
                        ('step',PublicInt(step)), ('session_id',PublicString(kwargs['session_id']))):
        assert check((replace(original[0], **{name:value}), *original[1:])) is None
    assert check((MetadataSubclass(**asdict(original[0])), *original[1:])) is ValueError
    cyclic = []
    cyclic.append(cyclic)
    for value, failure in ((object(),TypeError), (b'index',TypeError), (cyclic,RecursionError),
                            (float('nan'),ValueError)):
        assert check((replace(original[0], index=value), *original[1:])) is failure


def test_matrix_canonical_plan_validation_avoids_local_serialization(monkeypatch):
    """哨兵只约束规范构造的局部比较，完整行为另由旧语义oracle保护。"""
    from secure_control.protocol import messages

    kwargs, expected = _matrix_plan_fields(4, 2, 1, 32, 7)
    def forbidden(*args, **kwargs):
        pytest.fail('规范矩阵计划构造不应递归asdict或做内部JSON比较')
    monkeypatch.setattr(messages, 'asdict', forbidden)
    monkeypatch.setattr(messages.json, 'dumps', forbidden)
    plan = messages.MatrixStepResourcePlan(**kwargs)
    assert plan.state_truncation_resources == expected
    assert plan.product_resources[0].rows == 5 and plan.product_resources[0].inner == 6
    assert plan.fractional_bits == 32 and plan.truncation_count == 4
    assert plan.session_id == kwargs['session_id'] and plan.round_id == kwargs['round_id'] and plan.step == 7
    # 快路径必须在每次构造重查全部条目，不能复用上次成功状态。
    bad = kwargs['state_truncation_resources'][:-1]+(replace(expected[-1], output_fractional_bits=33),)
    with pytest.raises(ValueError, match='矩阵状态截断计划错误'):
        messages.MatrixStepResourcePlan(**dict(kwargs, state_truncation_resources=bad))


@pytest.mark.parametrize('rows,inner', [(1, 1), (2, 3), (5, 6)])
def test_matrix_product_independent_integer_oracle_and_one_public_cross_term(rows, inner):
    q = 2**127 - 1
    sharing = TwoPartySharing(q)
    multiplier = MatrixBeaverMultiplier(sharing)
    rng = random.Random(128)
    x = [[(q - 1 if (i+j) % 2 else 0) for j in range(inner)] for i in range(rows)]
    y = [[q-2 if j % 2 else j+1] for j in range(inner)]
    expected = [[sum(x[i][j]*y[j][0] for j in range(inner)) % q] for i in range(rows)]
    a, b = sharing.share(np.array(x, dtype=object), rng=rng), sharing.share(np.array(y, dtype=object), rng=rng)
    triples = multiplier.create_triple(rows, inner, rng=rng)
    masks = [multiplier.mask_inputs(a[i], b[i], triples[i]) for i in (0, 1)]
    public = multiplier.open_masked_differences(*masks)
    results = [multiplier.finish(t, public) for t in triples]
    assert sharing.reconstruct(*results).tolist() == expected
    # 漏掉/重复公开交叉项均改变结果，不能由新实现给自己构造期望值。
    cross = [[sum(int(public.e[i,j])*int(public.f[j,0]) for j in range(inner)) % q]
             for i in range(rows)]
    assert any(v[0] for v in cross)
    assert ((sharing.reconstruct(*results)-np.array(cross,dtype=object)) % q).tolist() != expected
    for i in (0, 1):
        with pytest.raises(ValueError):
            multiplier.mask_inputs(a[i], b[i], triples[i])
        with pytest.raises(ValueError):
            multiplier.finish(triples[i], public)


def test_matrix_rejects_wrong_owner_shape_and_noncanonical_values_before_claim():
    sharing = TwoPartySharing(257)
    owner = MatrixBeaverMultiplier(sharing)
    triple = owner.create_triple(2, 3, rng=random.Random(3))[0]
    good = AdditiveShare(np.ones((3, 1), dtype=object))
    for bad in (np.ones((2, 2), dtype=object), np.ones((6,), dtype=object),
                np.full((2,3), True, dtype=object), np.full((2,3), .5, dtype=object),
                np.full((2,3), -1, dtype=object), np.full((2,3), 257, dtype=object)):
        with pytest.raises((TypeError, ValueError)):
            owner.mask_inputs(AdditiveShare(bad), good, triple)
        assert triple._lifecycle.masked_parties == set()
    with pytest.raises(ValueError):
        MatrixBeaverMultiplier(sharing).mask_inputs(AdditiveShare(np.ones((2,3),dtype=object)), good, triple)
    with pytest.raises(ValueError):
        owner.create_triple(True, 3)
    with pytest.raises(ValueError):
        owner.create_triple(1000000, 1000000)
    with pytest.raises(ValueError):
        owner._validate(replace(triple, party_index=True))


def test_distinct_matrix_operations_cannot_mix_masks():
    sharing = TwoPartySharing(257)
    owner = MatrixBeaverMultiplier(sharing)
    a, b = owner.create_triple(1, 1), owner.create_triple(1, 1)
    x = AdditiveShare(np.array([[1]], dtype=object))
    first = owner.mask_inputs(x, x, a[0])
    other = owner.mask_inputs(x, x, b[1])
    with pytest.raises(ValueError):
        owner.open_masked_differences(first, other)


def test_matrix_256bit_oracle_fresh_random_draws_and_exact_mask_shapes():
    class CountingRandom(random.Random):
        calls = 0
        def randrange(self, *args, **kwargs):
            self.calls += 1
            return super().randrange(*args, **kwargs)
    q = 2**256-189
    sharing = TwoPartySharing(q)
    owner = MatrixBeaverMultiplier(sharing)
    rng = CountingRandom(19)
    first = owner.create_triple(2, 3, rng=rng)
    draws = rng.calls
    second = owner.create_triple(2, 3, rng=rng)
    # 每次确实调用原随机源，不以偶然的“不相等”作为新鲜性证明。
    assert draws == (6+3)+(6+3+2) and rng.calls == 2*draws
    assert first[0]._lifecycle is not second[0]._lifecycle
    x = sharing.share(np.array([[q-1, 2, q-3], [4, 0, 6]], dtype=object), rng=rng)
    y = sharing.share(np.array([[7], [q-8], [9]], dtype=object), rng=rng)
    masks = [owner.mask_inputs(x[p], y[p], first[p]) for p in (0,1)]
    for bad in (replace(masks[1], e=AdditiveShare(np.zeros((1,3),dtype=object))),
                replace(masks[1], f=AdditiveShare(np.zeros(3,dtype=object))),
                replace(masks[1], f=AdditiveShare(np.full((3,1),True,dtype=object)))):
        with pytest.raises((TypeError, ValueError)):
            owner.open_masked_differences(masks[0],bad)
        assert not first[0]._lifecycle.opened
    opened = owner.open_masked_differences(*masks)
    outputs = [owner.finish(first[p],opened) for p in (0,1)]
    assert sharing.reconstruct(*outputs).tolist() == [[(-7-16-27) % q], [(28+54) % q]]
    assert first[0]._lifecycle.consumed
    assert not second[0]._lifecycle.consumed


def test_matrix_plan_codec_material_identity_and_legacy_mixing_fail_closed():
    import socket

    from test_two_party_protocol import make_stack

    from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
    from secure_control.execution.localhost_codec import (
        _decode_preloaded_values,
        _encode_preloaded_values,
    )
    from secure_control.protocol import Client
    from secure_control.protocol.coordinator import rehydrate_online_material
    from secure_control.protocol.messages import (
        PartyOnlineMaterial,
        PartyOnlineRound,
        public_step_plan_sha256,
    )

    client, _, _, _, distribution = make_stack()
    prepared = client._material_owner(distribution).create(0, encoding_profile='control-dynamic-matrix-v1')
    current = client.bind_online_input(distribution,prepared,[.25],step=0)
    plan = current.p1_resources.plan
    legacy = Client._resource_plan(distribution.p1.layout, plan.session_id, plan.round_id, plan.step)
    assert public_step_plan_sha256(plan) != public_step_plan_sha256(legacy)
    assert public_step_plan_sha256(replace(plan, round_id='next',
        product_resources=(replace(plan.product_resources[0],round_id='next',resource_id='next:matrix'),),
        state_truncation_resources=tuple(replace(t,round_id='next',resource_id=t.resource_id.replace(plan.round_id,'next'))
                                         for t in plan.state_truncation_resources))) != public_step_plan_sha256(plan)
    for change in ({'version':'old'}, {'state_shape':(True,)}, {'order':'column-major'},
                   {'product_resources':(replace(plan.product_resources[0],resource_id='other'),)},
                   {'state_truncation_resources':(replace(plan.state_truncation_resources[0],index=(False,)),
                                                   *plan.state_truncation_resources[1:])}):
        with pytest.raises((TypeError,ValueError)):
            replace(plan,**change)
    for changes in ({'rows':True},{'step':False},{'inner':0}):
        with pytest.raises(ValueError):
            replace(plan.product_resources[0],**changes)
    encoded = _encode_preloaded_values(current.p1_resources,client.fixed_point.modulus)
    item = current.p1_resources.product_resources[0]
    for value in (np.zeros((1,9),dtype=object),np.full((3,3),True,dtype=object),
                  np.full((3,3),1.5,dtype=object)):
        bad=replace(current.p1_resources,product_resources=(replace(item,triple=replace(item.triple,u=AdditiveShare(value))),))
        with pytest.raises((TypeError,ValueError)):
            _encode_preloaded_values(bad,client.fixed_point.modulus)
    for data in (encoded[:-1],encoded+b'\0',b'\xff'*4+encoded[4:]):
        with pytest.raises((TypeError,ValueError)):
            _decode_preloaded_values(data,current.p1_input,plan,client.fixed_point.modulus)
    material = PartyOnlineMaterial.from_round(PartyOnlineRound(current.p1_input,current.p1_resources))
    item = material.product_resources[0]
    for bad in (replace(material,input_message=replace(material.input_message,step=1)),
                replace(material,product_resources=(replace(item,owner=1),)),
                replace(material,product_resources=(replace(item,u=AdditiveShare(np.zeros((1,1),dtype=object))),))):
        with pytest.raises((TypeError,ValueError)):
            rehydrate_online_material(bad,modulus=client.fixed_point.modulus,security_parameter=8)
    for wire, wrong in (('control-dynamic-compact-v3',plan),('control-dynamic-matrix-v1',legacy)):
        a,b=socket.socketpair()
        peer=LocalhostProtocol3PeerPort(a,'P1',8*1024*1024,1.,batch_enabled=True,wire_profile=wire)
        try:
            peer.bind(plan.session_id)
            with pytest.raises(ValueError):
                peer.set_batch_round(wrong,modulus=client.fixed_point.modulus)
        finally:
            peer.close();b.close()


@pytest.mark.parametrize("q", [3,257,2**256-189])
def test_matrix_integer_codec_matches_independent_bytes_and_owns_arrays(q):
    """非对称shape和手写row-major字节；不从新编码器反推期望。"""
    from types import SimpleNamespace

    from test_two_party_protocol import make_stack

    from secure_control.execution import localhost_codec as codec
    from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
    from secure_control.protocol import Client
    from secure_control.protocol.messages import (
        ControllerLayout,
        InputShareMessage,
        MatrixMaskPayload,
    )

    _,_,_,_,distribution = make_stack()
    layout = ControllerLayout(1,2,1,distribution.p1.layout.scale_ledger)
    plan = Client._resource_plan(layout,"session","round",0,encoding_profile='control-dynamic-matrix-v1')
    width = (q.bit_length()+7)//8
    # U(2,3),V(3,1),W(2,1),一份(r,r_prime)，故意不使用默认5×6。
    integers = [0,q-1,1,2,0,q-1, 1,0,q-1, 2,1, q-1,0]
    raw = b''.join(x.to_bytes(width,'big') for x in integers)
    inp = InputShareMessage(0,"session","round",0,AdditiveShare(np.zeros(2,dtype=object)))
    restored = codec._decode_preloaded_values(raw,inp,plan,q)
    next_plan = Client._resource_plan(layout,"session","next",1,encoding_profile='control-dynamic-matrix-v1')
    second = codec._decode_preloaded_values(raw,replace(inp,round_id='next',step=1),next_plan,q)
    for data in (raw[:-1],raw+b'\0',raw[:-width]+q.to_bytes(width,'big')):
        with pytest.raises(ValueError):
            codec._decode_preloaded_values(data,inp,plan,q)
    product = restored.product_resources[0]
    expected = (integers[:6],integers[6:9],integers[9:11])
    for share,values,shape in zip((product.u,product.v,product.w),expected,((2,3),(3,1),(2,1)),strict=True):
        assert share.value.dtype == object and share.value.shape == shape
        assert share.value.tolist() == np.array(values,dtype=object).reshape(shape).tolist()
    assert [(t.r.value,t.r_prime.value) for t in restored.state_truncation_resources] == [(q-1,0)]
    resource = SimpleNamespace(owner=0,metadata=plan.product_resources[0],
        triple=SimpleNamespace(u=product.u,v=product.v,w=product.w))
    from secure_control.protocol.messages import PartyResources
    material = PartyResources(0,plan,(resource,),tuple(SimpleNamespace(owner=0,metadata=t.metadata,
        truncation=SimpleNamespace(r=t.r,r_prime=t.r_prime)) for t in restored.state_truncation_resources))
    assert codec._encode_preloaded_values(material,q) == raw
    for invalid,error in ((True,TypeError),(1.5,TypeError),(-1,ValueError),(q,ValueError)):
        bad_array = product.u.value.copy()
        bad_array[0,0] = invalid
        bad = replace(material,product_resources=(SimpleNamespace(owner=0,metadata=resource.metadata,
            triple=SimpleNamespace(u=AdditiveShare(bad_array),v=product.v,w=product.w)),))
        with pytest.raises(error):
            codec._encode_preloaded_values(bad,q)
    for bad in (replace(material,recipient=True),replace(material,product_resources=(
        SimpleNamespace(owner=1,metadata=resource.metadata,triple=resource.triple),))):
        with pytest.raises(ValueError):
            codec._encode_preloaded_values(bad,q)
    # 支持矩阵Integral并先校验再转int；原标量仍不接受numpy整数。
    numpy_array = product.u.value.copy()
    numpy_array[0,0] = np.int64(0)
    numpy_material = replace(material,product_resources=(SimpleNamespace(owner=0,metadata=resource.metadata,
        triple=SimpleNamespace(u=AdditiveShare(numpy_array),v=product.v,w=product.w)),))
    assert codec._encode_preloaded_values(numpy_material,q) == raw
    with pytest.raises(ValueError):
        codec._encode_residues([AdditiveShare(np.int64(0))],q)
    product.u.value[0,0] = 1
    assert second.product_resources[0].u.value[0,0] == 0
    assert not np.shares_memory(product.u.value,product.v.value)
    # 单独核peer E/F字节与独立恢复，无须真实传输或新计时。
    sender = LocalhostProtocol3PeerPort(None,'P1',8*1024*1024,1.,batch_enabled=True,
        wire_profile='control-dynamic-matrix-v1')
    receiver = LocalhostProtocol3PeerPort(None,'P2',8*1024*1024,1.,batch_enabled=True,
        wire_profile='control-dynamic-matrix-v1')
    for peer in (sender,receiver):
        peer.bind(plan.session_id)
        peer.set_batch_round(plan,modulus=q,run_id='run',epoch_id='epoch')
    ids = tuple(item.resource_id for item in plan.product_resources)
    masks = integers[:9]
    payload = sender._batch_payload(plan,'product',ids,products=(MatrixMaskPayload(
        AdditiveShare(np.array(masks[:6],dtype=object).reshape(2,3)),
        AdditiveShare(np.array(masks[6:],dtype=object).reshape(3,1)),0),))
    compact = sender._wire_batch(payload)
    assert compact.values == b''.join(x.to_bytes(width,'big') for x in masks)
    for invalid,error in ((True,TypeError),(1.5,TypeError),(-1,ValueError),(q,ValueError)):
        e = payload.products[0].e.value.copy()
        e[0,0] = invalid
        bad = replace(payload,products=(replace(payload.products[0],e=AdditiveShare(e)),))
        with pytest.raises(error):
            sender._wire_batch(bad)
    with pytest.raises(ValueError):
        sender._wire_batch(replace(payload,products=(replace(payload.products[0],
            e=AdditiveShare(np.zeros((1,6),dtype=object))),)))
    frame = codec.WireEnvelope(codec.SCHEMA_VERSION,'request','P1','P2',1,'peer_batch',
        plan.session_id,plan.round_id,plan.step,None,compact)
    for data in (compact.values[:-1],compact.values+b'\0',q.to_bytes(width,'big')+compact.values[width:]):
        with pytest.raises(ValueError):
            receiver._validate_batch(replace(frame,payload=replace(compact,values=data)),plan,'product',ids)
        assert receiver._receive_sequence == 1
    result = receiver._validate_batch(frame,plan,'product',ids).products[0]
    assert result.e.value.dtype == result.f.value.dtype == object
    assert result.e.value.tolist() == payload.products[0].e.value.tolist()
    assert result.f.value.tolist() == payload.products[0].f.value.tolist()
    result.e.value[0,0] = 1
    assert payload.products[0].e.value[0,0] == 0


def test_local_cost_math_and_codec_with_fake_clock(monkeypatch):
    """只验证局部成本函数算术与字段；假时钟无性能样本、不调用P0入口。"""
    from types import SimpleNamespace

    from secure_control.crypto import FixedPointContext
    from secure_control.experiments import network_benchmark as network
    monkeypatch.setattr(network.time,'perf_counter_ns',lambda:0)
    monkeypatch.setattr(network.time,'process_time_ns',lambda:0)
    prepared=SimpleNamespace(context=FixedPointContext(2**61-1,32,8),security_parameter=8,evidence=None,
        spec=SimpleNamespace(A=np.eye(4)*.5,B=np.zeros((4,2)),C=np.ones((1,4)),D=np.zeros((1,2)),
                             x0=np.array([.25,-.5,0.,.75])))
    for kind,elements in (('scalar',98),('matrix',49)):
        result=network._matrix_primitive_sample(kind,prepared)
        assert result['functional_pass'] and result['material_elements_per_party']==elements
        assert result['material_bytes_both_parties']==elements*8*2
        assert result['total_wall_ns']==result['total_cpu_ns']==0


def test_matrix_round_codec_real_peer_old_state_output_and_commit():
    """真实socket peer交换、单方恢复与原Trunc/授权；不运行性能循环。"""
    import socket
    from threading import Thread

    from test_two_party_protocol import make_stack

    from secure_control.execution._localhost_peer import LocalhostProtocol3PeerPort
    from secure_control.execution.localhost_codec import (
        _decode_preloaded_values,
        _encode_preloaded_values,
        decode_wire_value,
        encode_wire_value,
    )
    from secure_control.protocol import P1, P2
    from secure_control.protocol.coordinator import (
        LocalProtocol3PartyEndpoint,
        Protocol3Orchestrator,
        rehydrate_online_material,
        stage_protocol3_batch,
    )
    from secure_control.protocol.messages import MatrixStepResourcePlan, product_operation_count

    client, _, _, _, distribution = make_stack()
    prepared = client._material_owner(distribution).create(0, rng=random.Random(82),
                                             encoding_profile='control-dynamic-matrix-v1')
    current = client.bind_online_input(distribution, prepared, [.25], step=0, rng=random.Random(71))
    plan = current.p1_resources.plan
    assert type(plan) is MatrixStepResourcePlan and product_operation_count(plan) == 1
    assert plan.scalar_equivalent_products == 9
    assert not hasattr(plan, 'triple_count')
    endpoints, outputs = [], [[], []]
    for i, role in enumerate((P1(distribution.p1), P2(distribution.p2))):
        resources = (current.p1_resources, current.p2_resources)[i]
        encoded = _encode_preloaded_values(resources, client.fixed_point.modulus)
        assert len(encoded) == (9+3+3+4)*4
        inp = (current.p1_input, current.p2_input)[i]
        material = _decode_preloaded_values(encoded, inp, plan, client.fixed_point.modulus)
        online = rehydrate_online_material(material, modulus=client.fixed_point.modulus, security_parameter=8)
        endpoints.append(LocalProtocol3PartyEndpoint(role, online, outputs[i].append,
                                                     completion_strategy='client_authorized'))
    peers = [LocalhostProtocol3PeerPort(s, f'P{i+1}', 8*1024*1024, 3., batch_enabled=True,
                                       wire_profile='control-dynamic-matrix-v1')
             for i,s in enumerate(socket.socketpair())]
    receipts, errors = [None,None], []
    for peer in peers:
        peer.bind(plan.session_id)
        peer.set_batch_round(plan, modulus=client.fixed_point.modulus, run_id='run',epoch_id='epoch')
    def stage(i):
        try:
            receipts[i] = stage_protocol3_batch(endpoints[i], peers[i])
        except BaseException as e:  # noqa: BLE001
            errors.append(e)
    threads = [Thread(target=stage,args=(i,)) for i in (0,1)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        assert not any(t.is_alive() for t in threads)
        assert not errors, errors
        assert client.reconstruct_control(outputs[0][0], outputs[1][0]).tolist() == [.625]
        orchestrator = Protocol3Orchestrator(completion_strategy='client_authorized')
        auth = orchestrator.authorize(tuple(receipts),plan)
        assert decode_wire_value(encode_wire_value(auth)) == auth
        assert all(decode_wire_value(encode_wire_value(r)) == r for r in receipts)
        for ep in endpoints:
            ep.commit_staged(auth)
        q=client.fixed_point.modulus
        state=(endpoints[0]._role.state_share.value+endpoints[1]._role.state_share.value)%q
        state=[int(v) if v<q//2 else int(v)-q for v in state]
        assert all(abs(a-b)<=1 for a,b in zip(state,[80,-16],strict=True))
        for ep in endpoints:
            with pytest.raises(ValueError):
                ep.commit_staged(auth)
    finally:
        for peer in peers:
            peer.close()
        for ep in endpoints:
            ep.abort()


@pytest.mark.parametrize('fault', [None, 'worker_exit', 'commit_ack', 'advance_ack'])
def test_matrix_spawn_worker_segments_and_uncertain_failures(monkeypatch, fault):
    """真实角色/供料进程短功能联调；无控制性能预热或长测。"""
    import multiprocessing as mp

    from secure_control.execution import lan_runtime
    from secure_control.execution._localhost_workers import _ClientPartyEndpoint
    from secure_control.experiments.communication_benchmark import _config, _party_job, _ports
    from secure_control.experiments.lan_continuous_profile import load_segmented_experiment
    from secure_control.scenarios.cart_pole.interactive import InteractiveSession

    profile = 'control-dynamic-matrix-v1'
    ports = _ports()
    context = mp.get_context('spawn')
    queue = context.Queue()
    parties = [context.Process(target=_party_job, args=(_config(r, ports), ports, 0, True, queue),
                               kwargs={'wire_profile':profile}) for r in ('P1','P2')]
    runtime = None
    try:
        prepared = load_segmented_experiment(_config('Client',ports).experiment_config,2,InteractiveSession())
        for party in parties:
            party.start()
        runtime = lan_runtime.LanSegmentedRuntime(_config('Client',ports),prepared.spec,prepared.context,
            prepared.contract,prepared.security_parameter,prepared.evidence,
            control=lan_runtime.RunControl(),segment_capacity=2,wire_profile=profile)
        runtime.enable_material_preparation(slots=4,_candidate='worker')
        pool=runtime._segment._material_pool
        worker_pid=pool._process.pid
        if fault == 'worker_exit':
            pool._process.terminate();pool._process.join(5)
            with pool._condition:
                assert pool._condition.wait_for(lambda:pool._error is not None,timeout=5)
        if fault == 'commit_ack':
            original=_ClientPartyEndpoint.finish_commit
            def fail_ack(endpoint):
                if endpoint.party==1:
                    raise OSError('test missing commit ACK')
                return original(endpoint)
            monkeypatch.setattr(_ClientPartyEndpoint,'finish_commit',fail_ack)
        if fault in ('worker_exit','commit_ack'):
            with pytest.raises((OSError,RuntimeError)):
                runtime.step(np.zeros(2))
            assert runtime.confirmed_step_count==0
            with pytest.raises(RuntimeError):
                runtime.step(np.zeros(2))
        else:
            state=np.array(prepared.spec.x0,dtype=float)
            for step in range(5):
                if runtime.segment_full:
                    if fault=='advance_ack':
                        original=lan_runtime._validate_party_reply
                        def fail_advance(response,request,original=original):
                            if request.operation=='segment_advance':
                                raise OSError('test missing advance ACK')
                            return original(response,request)
                        monkeypatch.setattr(lan_runtime,'_validate_party_reply',fail_advance)
                        with pytest.raises(OSError):
                            runtime.end_segment()
                        assert runtime.confirmed_step_count==2
                        break
                    runtime.end_segment();runtime.next_segment()
                    assert pool._process.pid==worker_pid
                identity=runtime.step(np.zeros(2))
                np.testing.assert_allclose(identity.raw_control,np.asarray(prepared.spec.C)@state,atol=1e-5,rtol=0)
                state=np.asarray(prepared.spec.A)@state
                runtime.confirm_applied(identity)
                with pool._condition:
                    assert pool._condition.wait_for(lambda:len(pool._queue)==4 or pool._error,timeout=10)
                    assert not pool._error
            if fault is None:
                runtime.control.request_stop();runtime.end_segment()
                assert runtime.resource_counts=={'matrix_products_consumed':5,
                    'scalar_equivalent_products':150,'multiplication_material_elements':205,
                    'truncations_consumed':20}
                assert runtime.confirmed_step_count==5
        runtime.close()
        assert not pool._process.is_alive()
        stats=runtime.material_summary
        assert stats['worker_exited'] and stats['receiver_exited'] and stats['credit_thread_exited']
    finally:
        if runtime is not None:
            runtime.close()
        for p in parties:
            if p.pid:
                p.join(6)
                if p.is_alive():
                    p.terminate();p.join(5)
        queue.close();queue.join_thread()
