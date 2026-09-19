"""Issue #51 诊断复现器的严格等价与透明记录回归测试。"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import numpy as np
import pytest

from secure_control.experiments.evidence_runner import _assert_exact_result, _RecordingRuntime
from secure_control.simulation import SimulationResult


class _RuntimeStub:
    """提供最小通用 runtime 行为，并允许验证 reset 委托。"""

    def __init__(self) -> None:
        self.state = 0.0

    def step(self, value: np.ndarray | float) -> np.ndarray:
        """返回独立数组，模拟会更新状态的 controller。"""
        self.state += float(np.asarray(value))
        return np.array([self.state])

    def reset(self) -> None:
        """恢复初态。"""
        self.state = 0.0


def _result() -> SimulationResult:
    """构造两个采样点的八字段结果。"""
    time = np.array([0.0, 1.0], dtype=np.float64)
    values = np.array([[1.0], [2.0]], dtype=np.float64)
    zeros = np.zeros((2, 1), dtype=np.float64)
    return SimulationResult(time, values, values, values, values, values, zeros, zeros)


def test_recording_runtime_is_transparent_returns_copies_and_resets() -> None:
    """记录 wrapper 不改变返回值，外部改写也不能污染已记录 raw control。"""
    runtime = _RuntimeStub()
    recording = _RecordingRuntime(runtime)
    returned = recording.step(0.25)
    returned[0] = 99.0
    assert np.array_equal(recording.outputs(), np.array([[0.25]]))
    recording.reset()
    assert runtime.state == 0.0
    with pytest.raises(ValueError, match="尚未记录"):
        recording.outputs()


def test_exact_result_gate_rejects_value_shape_and_dtype_changes() -> None:
    """八字段门禁同时锁定 bitwise 数值、shape 与 dtype，不能改成 tolerance。"""
    expected = _result()
    _assert_exact_result(expected, expected)

    changed = np.array(expected.control_secure, copy=True)
    changed[0, 0] = np.nextafter(changed[0, 0], np.inf)
    with pytest.raises(ValueError, match="control_secure"):
        _assert_exact_result(replace(expected, control_secure=changed), expected)

    float32 = np.asarray(expected.reference, dtype=np.float32)
    with pytest.raises(ValueError, match="reference"):
        _assert_exact_result(replace(expected, reference=float32), expected)

    shape_changed = SimpleNamespace(
        **{
            name: (np.array([0.0, 0.5, 1.0]) if name == "time" else getattr(expected, name))
            for name in (
                "time",
                "reference",
                "output_ideal",
                "output_secure",
                "control_ideal",
                "control_secure",
                "control_error",
                "output_error",
            )
        }
    )
    with pytest.raises(ValueError, match="time"):
        _assert_exact_result(shape_changed, expected)
