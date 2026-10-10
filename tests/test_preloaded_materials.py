"""有限预送窗口的身份、无损算术、库存与真实三方联通回归。"""

import json
import random
from dataclasses import replace

import numpy as np
import pytest

from secure_control.crypto import AdditiveShare
from secure_control.execution.lan_runtime import _PreloadMaterialStore
from secure_control.execution.localhost_codec import (
    LocalhostCodecError,
    PreloadedBlock,
    PreloadedInputPayload,
    PreloadedReadyPayload,
    decode_wire_value,
    encode_wire_value,
)
from secure_control.protocol.coordinator import (
    DirectProtocol3PartyEndpoint,
    LocalProtocol3PartyEndpoint,
    Protocol3Orchestrator,
    _InMemoryProtocol3PeerPort,
    _OnlineMaterialRecovery,
)
from secure_control.protocol.messages import (
    InputShareMessage,
    PreloadReceipt,
    preloaded_material_budget,
    public_step_plan_sha256,
)


def _window(count=2, stage_mode="fused"):
    from test_two_party_protocol import make_stack

    stack = make_stack()
    client, _, _, _, distribution = stack
    batch = client.begin_preloaded_resources(distribution, run_id="run", controller_epoch="epoch",
                                             count=count, stage_mode=stage_mode)
    return stack, batch


def _store(manifest, party):
    return _PreloadMaterialStore(manifest, party=party, session=manifest.session_id,
        layout=manifest.layout, modulus=manifest.modulus, run_id=manifest.run_id,
        epoch=manifest.controller_epoch, count=len(manifest.round_ids), stage_mode=manifest.stage_mode)


def test_preloaded_cache_validates_every_residue_and_irreversibly_claims_all_1000_slots():
    (client, _, _, _, distribution), batch = _window(1000)
    manifest = batch.manifest
    store = _store(manifest, 0)
    row, width = store.budget["row_bytes"], store.budget["residue_bytes"]
    count = manifest.block_steps
    first = PreloadedBlock(store.receipt("block", first=0, count=count), bytes(count * row))
    bad = first.values[:-width] + manifest.modulus.to_bytes(width, "big")
    with pytest.raises(ValueError, match="residue"):
        store.load(replace(first, values=bad))
    assert store.loaded == 0 and not any(store.data)
    with pytest.raises(ValueError):
        store.seal(PreloadedReadyPayload(store.digest, 1000))
    for start in range(0, 1000, manifest.block_steps):
        count = min(manifest.block_steps, 1000 - start)
        block = PreloadedBlock(store.receipt("block", first=start, count=count), bytes(count * row))
        store.load(block)
        with pytest.raises(ValueError):
            store.load(block)
    store.seal(PreloadedReadyPayload(store.digest, 1000))
    for step in range(1000):
        plan = client._resource_plan(manifest.layout, manifest.session_id, manifest.round_ids[step], step)
        inp = InputShareMessage(0, plan.session_id, plan.round_id, step, AdditiveShare(np.array([1], dtype=object)))
        payload = PreloadedInputPayload(store.digest, inp, step, public_step_plan_sha256(plan))
        if step in (0, 99, 399, 400, 799, 800, 999):
            with pytest.raises(ValueError):
                store.claim(replace(payload, plan_sha256="0" * 64))
        material = store.claim(payload)
        with pytest.raises(ValueError):
            store.claim(payload)
        store.commit(material.plan)
    assert store.committed == store.next_slot == 1000
    with pytest.raises(ValueError):
        store.claim(replace(payload, slot_index=1000))
    store.close()
    assert not store.data and store.closed
    with pytest.raises(ValueError):
        store.claim(payload)
    client.discard_preloaded_resources(distribution, batch)


def test_preloaded_wire_rejects_extra_fields_bool_derived_and_noncanonical_base64():
    _, batch = _window()
    manifest = batch.manifest
    assert decode_wire_value(encode_wire_value(manifest)) == manifest
    data = json.loads(encode_wire_value(manifest))
    data["derived"]["count"] = True
    with pytest.raises(LocalhostCodecError):
        decode_wire_value(json.dumps(data).encode())
    receipt = PreloadReceipt(0, manifest.sha256(), "block", 0, 0, 2)
    block = PreloadedBlock(receipt, b"\0")
    assert decode_wire_value(encode_wire_value(block)) == block
    data = json.loads(encode_wire_value(block))
    for encoded in ("AB==", "AA=", "AA==\n", "_A=="):
        data["values"] = encoded
        with pytest.raises(LocalhostCodecError):
            decode_wire_value(json.dumps(data).encode())
    data["values"] = "AA=="
    data["unknown"] = None
    with pytest.raises(LocalhostCodecError):
        decode_wire_value(json.dumps(data).encode())


def test_preloaded_export_matches_original_seeded_integer_output_and_state():
    from test_two_party_protocol import make_stack

    original = make_stack()
    (client, p1, p2, _, distribution), batch = _window()
    manifest = batch.manifest
    stores = tuple(_store(manifest, party) for party in (0, 1))
    def receipts(phase, first=None, count=2):
        return tuple(PreloadReceipt(party, manifest.sha256(), phase,
            0 if first is not None else None, first, count) for party in (0, 1))
    client.record_preloaded_receipts(distribution, batch, receipts("init"))
    exports = [client.export_preloaded_step(distribution, batch, step=step, rng=random.Random(52 + step))
               for step in range(2)]
    width = stores[0].budget["residue_bytes"]
    for party, store in enumerate(stores):
        data = b"".join(v.to_bytes(width, "big") for row in exports
                        for v in (row.p1_values if party == 0 else row.p2_values))
        store.load(PreloadedBlock(receipts("block", 0)[party], data))
        store.seal(PreloadedReadyPayload(manifest.sha256(), 2))
    client.record_preloaded_receipts(distribution, batch, receipts("block", 0))
    client.record_preloaded_receipts(distribution, batch, receipts("seal"))
    recoveries = tuple(_OnlineMaterialRecovery(message, modulus=manifest.modulus,
        security_parameter=8, modulus_evidence=None) for message in (distribution.p1, distribution.p2))
    old_client, old_p1, old_p2, old_coordinator, old_distribution = original
    old_prepared = [old_client.precompute_online_resources(old_distribution, step=step,
                    rng=random.Random(52 + step)) for step in range(2)]
    for step, value in enumerate(([.25], [-.125])):
        prepared = old_prepared[step]
        old = old_client.bind_online_input(old_distribution, prepared, value, step=step, rng=random.Random(70 + step))
        old_output = old_client.reconstruct_control(*old_coordinator.execute(old_p1, old_p2, old))
        current = client.bind_preloaded_input(distribution, batch, value, step=step, rng=random.Random(70 + step))
        restored = tuple(recovery.restore(store.claim(PreloadedInputPayload(manifest.sha256(), inp,
            step, public_step_plan_sha256(current.plan)))) for recovery, store, inp in zip(
                recoveries, stores, (current.p1_input, current.p2_input), strict=True))
        output_messages, inbox = [], {}
        endpoints = tuple(DirectProtocol3PartyEndpoint(LocalProtocol3PartyEndpoint(role, material,
            output_messages.append), _InMemoryProtocol3PeerPort(party, inbox))
            for party, role, material in zip((0, 1), (p1, p2), restored, strict=True))
        orchestrator = Protocol3Orchestrator()
        orchestrator.stage(*endpoints, current.plan)
        output = client.reconstruct_control(*output_messages)
        orchestrator.commit(*endpoints)
        np.testing.assert_array_equal(output, old_output)
        np.testing.assert_array_equal(client.sharing.reconstruct(p1.state_share, p2.state_share),
                                     old_client.sharing.reconstruct(old_p1.state_share, old_p2.state_share))
        for store, material in zip(stores, restored, strict=True):
            store.commit(material.resources.plan)
        client.retire_preloaded_round(current, success=True)


def test_preload_startup_rejects_partial_two_party_ack_at_every_barrier(monkeypatch):
    from types import SimpleNamespace

    from test_two_party_protocol import make_stack

    from secure_control.execution import lan_runtime as lan
    from secure_control.execution import localhost_transport as transport

    for phase in ("init", "block", "seal"):
        client, _, _, _, distribution = make_stack()
        runtime = lan.LanContinuousRuntime.__new__(lan.LanContinuousRuntime)
        runtime.__dict__.update(_preload_steps=1, _preload_execution="fused", _preloaded=None,
            _material_pool=None, _step=0, _sockets=["p1", "p2"], _sequences=[4, 4],
            client=client, distribution=distribution, session_id=distribution.session_id,
            config=SimpleNamespace(startup_timeout=2.), setup_run_id="run",
            setup=SimpleNamespace(controller_epoch="epoch"))
        sent = []
        monkeypatch.setattr(transport, "send_frame", lambda sock, *a, sent=sent, **k: sent.append(sock))
        def reply(sock, request, *, deadline, expected_payload, limit, phase=phase, sent=sent):
            assert sent[-2:] == ["p1", "p2"]
            assert limit == 64 * 1024
            if request.operation == "preload_" + phase and sock == "p2":
                raise ValueError("bad second startup ACK")
            return expected_payload
        monkeypatch.setattr(lan, "_receive_reply", reply)
        monkeypatch.setattr(runtime, "close", lambda runtime=runtime:
            runtime.client.discard_preloaded_resources(runtime.distribution, runtime._preloaded))
        with pytest.raises(ValueError, match="startup ACK"):
            runtime.enable_material_preload()
        assert runtime._failed and not client._issued_rounds
        state = client._material_owner(distribution)._preload
        assert state.closed and state.generated == (0 if phase == "init" else 1)
        with pytest.raises(ValueError):
            client.bind_preloaded_input(distribution, runtime._preloaded, [.25], step=0)
        monkeypatch.undo()


def test_preloaded_budget_rejects_before_cache_allocation_or_generation():
    _, batch = _window()
    with pytest.raises(ValueError):
        preloaded_material_budget(batch.manifest.layout, 1 << 100000, 1000)
    with pytest.raises(ValueError):
        preloaded_material_budget(batch.manifest.layout, batch.manifest.modulus, True)
    with pytest.raises(ValueError):
        preloaded_material_budget(batch.manifest.layout, batch.manifest.modulus, 1001)
    from secure_control.experiments.communication_benchmark import run_continuous_observation
    with pytest.raises(ValueError, match="库存"):
        run_continuous_observation(steps=1001, delay_ms=0, segment_steps=400,
                                  optimized=True, preload_steps=1000)


def test_fused_activation_preflights_both_frames_and_burns_window_on_partial_failure(monkeypatch):
    from types import SimpleNamespace

    from secure_control.execution import lan_runtime as lan
    from secure_control.execution import localhost_transport as transport
    from secure_control.execution._localhost_workers import _ClientPartyEndpoint

    for mode, failure in (("staged", "encoding"), ("fused", "encoding"),
                          ("fused", "second_send"), ("fused", "second_reply"),
                          ("fused", "commit")):
        (client, _, _, _, distribution), batch = _window(1, mode)
        manifest = batch.manifest
        def receipts(phase, first=None, manifest=manifest):
            return tuple(PreloadReceipt(party, manifest.sha256(), phase,
                0 if first is not None else None, first, 1) for party in (0, 1))
        client.record_preloaded_receipts(distribution, batch, receipts("init"))
        client.export_preloaded_step(distribution, batch, step=0)
        client.record_preloaded_receipts(distribution, batch, receipts("block", 0))
        client.record_preloaded_receipts(distribution, batch, receipts("seal"))
        runtime = lan.LanContinuousRuntime.__new__(lan.LanContinuousRuntime)
        runtime.__dict__.update(_v2=True, _failed=False, _finished=False, _step=0,
            _segment_start=0, _segment_capacity=400, _preload_steps=1, _preload_execution=mode,
            _preloaded=batch, _preload_digest=manifest.sha256(), _material_pool=None,
            _sockets=["p1", "p2"], _sequences=[7, 7], _batch=True,
            client=client, distribution=distribution, spec=SimpleNamespace(input_dimension=1),
            config=SimpleNamespace(step_timeout=1.), session_id=manifest.session_id)
        events = []
        original_encode = transport.encode_envelope
        def encode(request, events=events, failure=failure, original_encode=original_encode):
            events.append("encode")
            if failure == "encoding" and request.recipient == "P2":
                raise ValueError("second encoding")
            return original_encode(request)
        def send(sock, *args, events=events, failure=failure, **kwargs):
            assert events[:2] == ["encode", "encode"]
            events.append(sock)
            if failure == "second_send" and sock == "p2":
                raise ValueError("second send")
        def finish(endpoint, events=events, failure=failure):
            events.append(f"reply{endpoint.party}")
            if failure == "second_reply" and endpoint.party == 1:
                raise ValueError("second reply")
        def complete(client, first, second, plan, failure=failure, **kwargs):
            first.start_stage_batch()
            second.start_stage_batch()
            first.finish_stage_batch()
            second.finish_stage_batch()
            if failure == "commit":
                client._issued_rounds.pop((plan.session_id, plan.round_id, plan.step))
                raise ValueError("unknown commit")
            raise AssertionError("预期故障未触发")
        monkeypatch.setattr(transport, "encode_envelope", encode)
        monkeypatch.setattr(transport, "send_frame", send)
        monkeypatch.setattr("secure_control.execution._localhost_workers.send_frame", send)
        monkeypatch.setattr(_ClientPartyEndpoint, "finish_stage_batch", finish)
        monkeypatch.setattr(lan, "_complete_client_round", complete)
        monkeypatch.setattr(runtime, "close", lambda client=client, distribution=distribution,
                           batch=batch: client.discard_preloaded_resources(distribution, batch))
        with pytest.raises(ValueError):
            runtime.step([.25])
        assert runtime._failed and not client._issued_rounds
        assert runtime._round_started is (failure != "encoding")
        if failure == "encoding":
            assert events == ["encode", "encode"]
        with pytest.raises(ValueError):
            client.bind_preloaded_input(distribution, batch, [.25], step=0)
        monkeypatch.undo()


@pytest.mark.integration
def test_preloaded_real_three_party_staged_and_fused_keep_commits_and_cross_segments():
    from secure_control.experiments.communication_benchmark import run_continuous_observation

    for mode, frames in (("staged", 19), ("fused", 15)):
        report = run_continuous_observation(steps=3, delay_ms=0, segment_steps=2,
                                           optimized=True, preload_steps=3, preload_execution=mode)
        assert report["status"] == "stopped", report["failed_phase"]
        assert report["stage_pass"] and not report["qualification_pass"]
        assert report["successful_steps"] == 3
        assert report["material_summary"]["producer_present"] is False
        # 非边界轮包含 Client、两方回执与 peer 的实际发送帧，保持原commit ACK。
        count = sum(item["frames"] for item in report["steps"][0]["sent"].values())
        count += sum(sum(item["frames"] for item in outcome["steps"][0]["sent"].values())
                     for outcome in report["party_outcomes"])
        assert count == frames
        assert all(outcome["material_summary"]["committed"] == 3 for outcome in report["party_outcomes"])
