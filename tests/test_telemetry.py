"""公开遥测 v1 的字段、顺序、损帧及消费者隔离测试。"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import numpy as np
import pytest

from secure_control.execution import LocalhostSecureStateSpaceRuntime
from secure_control.scenarios.hvac.integration import HvacScenario
from secure_control.simulation import ChannelMetadata, ScenarioMetadata
from secure_control.simulation.engine import compare_closed_loops
from secure_control.simulation.telemetry import (
    BoundedPublisher,
    EventReceiver,
    Sample,
    SessionEnded,
    SessionFault,
    SessionStarted,
    TelemetrySession,
    observe_roles,
    public_event_dict,
    public_event_json,
)


def _metadata(channels: int) -> ScenarioMetadata:
    """三组单位故意不同，防止 UI 将向量默认为一个温度值。"""
    names = tuple(f"v{i}" for i in range(channels))
    return ScenarioMetadata(
        "toy",
        ChannelMetadata(names, ("r",) * channels),
        ChannelMetadata(names, ("y",) * channels),
        ChannelMetadata(names, ("u",) * channels),
    )


@pytest.mark.parametrize("channels", [1, 3])
def test_public_schema_channels_exact_fields_and_comparison(channels: int) -> None:
    """版本、单位、严格字段集合、向量 shape 和有符号误差均固定。"""
    metadata = _metadata(channels)
    header = public_event_dict(SessionStarted("public", 0, metadata))
    assert set(header) == {
        "event_schema_version",
        "session_id",
        "event_seq",
        "roles",
        "kind",
        "channels",
        "sample_time_unit",
    }
    assert header["event_schema_version"] == 1
    assert header["sample_time_unit"] == "s"
    assert header["channels"] == {
        "reference": {"names": list(metadata.reference.names), "units": ["r"] * channels},
        "output": {"names": list(metadata.output.names), "units": ["y"] * channels},
        "control": {"names": list(metadata.control.names), "units": ["u"] * channels},
    }
    values = (1.0,) * channels
    zeros = (0.0,) * channels
    sample = Sample(
        "public",
        1,
        0,
        0.25,
        values,
        zeros,
        values,
        metadata,
        values,
        values,
        zeros,
        values,
    )
    body = public_event_dict(sample)
    assert set(body) == {
        "event_schema_version",
        "session_id",
        "event_seq",
        "roles",
        "kind",
        "step",
        "time_s",
        "reference",
        "output_secure",
        "control_secure",
        "output_ideal",
        "control_ideal",
        "control_error",
        "output_error",
        "latency_ms",
    }
    assert body["output_error"] == [1.0] * channels
    assert body["control_error"] == [0.0] * channels
    assert body["latency_ms"] == {
        "controller_round": None,
        "actuator_plant": None,
        "prepare": None,
        "stage": None,
        "commit": None,
    }
    assert json.loads(public_event_json(sample)) == body


def test_rejects_shape_nonfinite_partial_comparison_and_wrong_error() -> None:
    """事件构造处拒绝广播、NaN/Inf 和伪造 comparison。"""
    metadata = _metadata(2)
    with pytest.raises(ValueError, match="channel metadata"):
        Sample("s", 1, 0, 0.0, (1.0,), (1.0, 2.0), (1.0, 2.0), metadata)
    with pytest.raises(ValueError, match="有限"):
        Sample("s", 1, 0, float("nan"), (1.0, 2.0), (1.0, 2.0), (1.0, 2.0), metadata)
    with pytest.raises(ValueError, match="全有"):
        Sample(
            "s",
            1,
            0,
            0.0,
            (1.0, 2.0),
            (1.0, 2.0),
            (1.0, 2.0),
            metadata,
            output_ideal=(1.0, 2.0),
        )
    with pytest.raises(ValueError, match="ideal-minus-secure"):
        Sample(
            "s",
            1,
            0,
            0.0,
            (1.0, 2.0),
            (1.0, 2.0),
            (1.0, 2.0),
            metadata,
            output_ideal=(2.0, 3.0),
            control_ideal=(2.0, 3.0),
            control_error=(0.0, 0.0),
            output_error=(1.0, 1.0),
        )
    with pytest.raises(ValueError, match="非负"):
        SessionStarted("s", -1, metadata)


def test_public_whitelist_excludes_extra_payload_and_exception_text() -> None:
    """即使对象携带嵌套秘密哨兵，JSON 和公开故障不遍历它。"""
    secret = "secret-share-triple-mask-nonce-private-state-combined-share"

    class ExtraFault(SessionFault):
        pass

    fault = ExtraFault("s", 2, 1, "control")
    object.__setattr__(fault, "private_payload", {"nested": [secret]})
    encoded = public_event_json(fault)
    assert secret not in encoded
    assert set(json.loads(encoded)) == {
        "event_schema_version",
        "session_id",
        "event_seq",
        "roles",
        "kind",
        "step",
        "category",
    }
    publisher = BoundedPublisher(lambda event: None)
    with pytest.raises(TypeError, match="公开事件"):
        publisher.publish(fault)
    publisher.close()
    with pytest.raises(TypeError, match="公开"):
        public_event_dict({"share": secret})  # type: ignore[arg-type]


def test_bounded_publisher_drops_samples_and_preserves_terminal() -> None:
    """真实阻塞消费者不进入生产者调用栈，缺口与终态可观察。"""
    entered = threading.Event()
    release = threading.Event()
    delivered: list[object] = []

    def slow_consumer(event: object) -> None:
        entered.set()
        release.wait(2.0)
        delivered.append(event)

    publisher = BoundedPublisher(slow_consumer, capacity=3)
    session = TelemetrySession(publisher, session_id="public")
    metadata = _metadata(1)
    session.start(metadata)
    assert entered.wait(1.0)
    start = time.perf_counter()
    for step in range(10):
        session.sample(
            step=step,
            time_s=float(step),
            metadata=metadata,
            reference=(1.0,),
            output_secure=(0.0,),
            control_secure=(1.0,),
        )
    session.end("completed")
    elapsed = time.perf_counter() - start
    assert elapsed < 0.2
    assert publisher.status["dropped_samples"] > 0
    assert isinstance(session.current_header, SessionStarted)
    assert session.next_event_seq == 12
    release.set()
    deadline = time.monotonic() + 2.0
    while (
        not any(isinstance(event, SessionEnded) for event in delivered)
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    publisher.close()
    assert any(isinstance(event, SessionEnded) for event in delivered)
    assert [event.event_seq for event in delivered] != list(range(12))


def test_delivery_exception_is_not_control_fault_and_receiver_handles_gap() -> None:
    """异常消费者只更新派发状态；接收方去重、迟到、缺口及未知终态。"""
    called = threading.Event()

    def disconnected(event: object) -> None:
        called.set()
        raise ConnectionError("secret-share-should-never-be-logged")

    publisher = BoundedPublisher(disconnected)
    metadata = _metadata(1)
    session = TelemetrySession(publisher, session_id="public")
    session.start(metadata)
    assert called.wait(1.0)
    deadline = time.monotonic() + 1.0
    while not publisher.status["delivery_failed"] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert publisher.status["delivery_failed"] is True
    session.sample(
        step=0,
        time_s=0.0,
        metadata=metadata,
        reference=(1.0,),
        output_secure=(0.0,),
        control_secure=(1.0,),
    )
    session.end("completed")
    assert session.next_event_seq == 3
    assert publisher.status["pending"] == 0
    receiver = EventReceiver()
    header = SessionStarted("public", 0, metadata)
    end = SessionEnded("public", 2, "completed", 0)
    assert receiver.display_status("public") == "unknown/disconnected"
    assert receiver.accept(header) == "accepted"
    assert receiver.accept(header) == "duplicate"
    assert receiver.accept(end) == "gap"
    assert receiver.display_status("public") == "completed"
    assert receiver.accept(SessionFault("public", 1, 0, "control")) == "late"
    with pytest.raises(ValueError, match="冲突"):
        receiver.accept(SessionFault("public", 1, 0, "plant"))
    publisher.close()


@pytest.mark.parametrize("consumer_mode", ["slow", "disconnected"])
def test_real_localhost_client_trajectory_and_resources_ignore_consumer(
    consumer_mode: str,
) -> None:
    """真实 Client/P1/P2 固定输入多步，对照慢/断开消费者的完整八字段与资源。"""
    config = Path(__file__).parents[1] / "configs" / "hvac_dual_loop.yaml"
    baseline = HvacScenario(
        config, test_seed=905, secure_runtime_builder=LocalhostSecureStateSpaceRuntime
    ).build_plan()
    live = HvacScenario(
        config, test_seed=905, secure_runtime_builder=LocalhostSecureStateSpaceRuntime
    ).build_plan()
    release = threading.Event()
    entered = threading.Event()
    delivered: list[object] = []

    def consumer(event: object) -> None:
        entered.set()
        if consumer_mode == "slow":
            release.wait(5.0)
            delivered.append(event)
        else:
            raise ConnectionError("private-share-must-not-appear")

    publisher = BoundedPublisher(consumer, capacity=3)
    telemetry = TelemetrySession(
        publisher,
        session_id="public-localhost",
        roles=observe_roles(live.secure.runtime.topology),
    )
    try:
        expected = compare_closed_loops(baseline.ideal, baseline.secure, baseline.sample_times[:6])
        start = time.perf_counter()
        actual = compare_closed_loops(
            live.ideal, live.secure, live.sample_times[:6], telemetry=telemetry
        )
        control_elapsed = time.perf_counter() - start
        assert entered.wait(1.0)
        assert control_elapsed < 5.0
        for field in expected.__dataclass_fields__:
            np.testing.assert_array_equal(getattr(actual, field), getattr(expected, field))
        assert live.secure.runtime.resource_counts == baseline.secure.runtime.resource_counts
        assert live.secure.runtime.resource_counts["products_consumed"] > 0
        assert telemetry.next_event_seq == 8
        if consumer_mode == "slow":
            assert publisher.status["dropped_samples"] > 0
        else:
            deadline = time.monotonic() + 1.0
            while not publisher.status["delivery_failed"] and time.monotonic() < deadline:
                time.sleep(0.01)
            assert publisher.status["delivery_failed"] is True
    finally:
        release.set()
        publisher.close()
        baseline.secure.runtime.close()
        live.secure.runtime.close()
