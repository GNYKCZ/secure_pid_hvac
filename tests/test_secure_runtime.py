"""通用安全状态空间运行时的数值、生命周期和边界测试。"""

from __future__ import annotations

import numpy as np
import pytest

from secure_control.core import ControllerScaleMetadata, ControllerSpec
from secure_control.crypto import (
    FixedPointContext,
    PocklingtonCertificate,
    PocklingtonFactorEvidence,
    PrimeModulusEvidence,
    pocklington_certificate_sha256,
)
from secure_control.execution import (
    ControllerRuntime,
    PlaintextStateSpaceRuntime,
    SecureStateSpaceRuntime,
)
from secure_control.protocol import Client, ControllerRangeContract, SingleProcessCoordinator


def general_spec() -> ControllerSpec:
    """返回需要 Protocol 2 state Trunc 的一维通用控制器。"""
    return ControllerSpec(
        A=np.array([[0.5]]),
        B=np.array([[0.25]]),
        C=np.array([[1.0]]),
        D=np.array([[0.5]]),
        x0=np.array([0.5]),
        scale_metadata=ControllerScaleMetadata(
            state=8,
            input=8,
            output=16,
            A=8,
            B=8,
            C=8,
            D=8,
        ),
    )


def integer_state_spec() -> ControllerSpec:
    """返回由 metadata 明确声明 A/B/C/D 为整数尺度的通用控制器。"""
    return ControllerSpec(
        A=np.array([[0.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[-1.0]]),
        x0=np.array([0.5]),
        scale_metadata=ControllerScaleMetadata(
            state=8,
            input=8,
            output=16,
            A=0,
            B=0,
            C=8,
            D=8,
        ),
    )


def make_secure_runtime(
    spec: ControllerSpec, *, seed: int = 100, bound: int = 128
) -> SecureStateSpaceRuntime:
    """以隔离测试 seed 创建满足公开无限时域范围的安全 runtime。"""
    return SecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(bound,) * spec.state_dimension,
            input_payload_bounds=(64,) * spec.input_dimension,
        ),
        security_parameter=8,
        test_seed=seed,
    )


def _large_prime_evidence() -> PrimeModulusEvidence:
    """返回用于 runtime 构造和 reset 传递验证的 65-bit 公开证据。"""
    certificate = PocklingtonCertificate(
        candidate=18_446_744_073_709_554_719,
        factors=(
            PocklingtonFactorEvidence(2, 1, 7),
            PocklingtonFactorEvidence(9_223_372_036_854_777_359, 1, 2),
        ),
    )
    return PrimeModulusEvidence(
        "pocklington_v1",
        "Issue #33 runtime fixture",
        "1",
        "issue33-runtime-65bit-v1",
        pocklington_certificate_sha256(certificate),
        certificate,
    )


def test_general_fixed_point_sequence_matches_plaintext_with_recorded_tolerance() -> None:
    """验证通用固定点 A/B 序列在量化与单次 Trunc 误差预算内匹配明文语义。"""
    spec = general_spec()
    plaintext = PlaintextStateSpaceRuntime(spec)
    secure = make_secure_runtime(spec, bound=256)
    inputs = (0.1, -0.2, 0.05, 0.15)

    plaintext_outputs = np.vstack([plaintext.step(value) for value in inputs])
    secure_outputs = np.vstack([secure.step(value) for value in inputs])
    maximum_error = float(np.max(np.abs(plaintext_outputs - secure_outputs)))

    assert isinstance(secure, ControllerRuntime)
    assert not hasattr(secure, "state")
    assert secure.scale_ledger.state_truncation_bits == 8
    assert secure.scale_ledger.output == 16
    assert secure_outputs.shape == (4, 1)
    assert maximum_error <= 2.0 / 256.0


def test_integer_a_b_sequence_uses_metadata_selected_no_trunc_path() -> None:
    """验证整数 A/B runtime 由尺度账本选择无 Trunc 路径并保持更新顺序。"""
    spec = integer_state_spec()
    plaintext = PlaintextStateSpaceRuntime(spec)
    secure = make_secure_runtime(spec)

    expected = np.vstack([plaintext.step(0.25), plaintext.step(-0.125)])
    actual = np.vstack([secure.step(0.25), secure.step(-0.125)])

    assert secure.scale_ledger.state_truncation_bits == 0
    assert secure.scale_ledger.output == 16
    np.testing.assert_allclose(actual, expected, atol=1.0 / 256.0)


def test_integer_dtype_spec_accepts_fractional_input_in_both_runtimes() -> None:
    """RV-11-001：输入尺度允许小数时，矩阵存储 dtype 不应使明文与安全运行时分叉。"""
    spec = ControllerSpec(
        A=np.array([[0]], dtype=np.int64),
        B=np.array([[1]], dtype=np.int64),
        C=np.array([[1]], dtype=np.int64),
        D=np.array([[1]], dtype=np.int64),
        x0=np.array([0], dtype=np.int64),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=8, A=0, B=0, C=0, D=0),
    )
    plaintext = PlaintextStateSpaceRuntime(spec)
    secure = make_secure_runtime(spec, seed=101, bound=64)

    # 第一轮直接输出输入，第二轮还须读取由小数输入更新的 state；reset 后重现第一轮。
    for value, expected in ((0.25, 0.25), (-0.125, 0.125)):
        plain_output = plaintext.step(value)
        secure_output = secure.step(value)
        np.testing.assert_allclose(plain_output, np.array([expected]), atol=1.0 / 256.0)
        np.testing.assert_allclose(secure_output, plain_output, atol=1.0 / 256.0)
    plaintext.reset()
    secure.reset()
    np.testing.assert_allclose(secure.step(0.25), plaintext.step(0.25), atol=1.0 / 256.0)


def test_review_report_feedthrough_trigger_matches_between_runtimes() -> None:
    """复现 RV-11-001 报告中的零状态递推整数规格，不让矩阵 dtype 限制 input=8。"""
    spec = ControllerSpec(
        A=np.array([[0]], dtype=np.int64),
        B=np.array([[0]], dtype=np.int64),
        C=np.array([[0]], dtype=np.int64),
        D=np.array([[1]], dtype=np.int64),
        x0=np.array([0], dtype=np.int64),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=8, A=0, B=0, C=0, D=0),
    )
    plaintext = PlaintextStateSpaceRuntime(spec)
    secure = make_secure_runtime(spec, seed=102, bound=0)

    np.testing.assert_array_equal(plaintext.step(0.25), np.array([0.25]))
    np.testing.assert_array_equal(secure.step(0.25), np.array([0.25]))


def test_column_and_flat_inputs_are_interchangeable_between_runtimes() -> None:
    """验证明文与安全 runtime 接受相同的单步列向量并统一返回 ``(p,)``。"""
    spec = ControllerSpec(
        A=np.zeros((1, 1)),
        B=np.array([[1.0, 0.0]]),
        C=np.array([[1.0], [-1.0]]),
        D=np.array([[0.0, 1.0], [1.0, 0.0]]),
        x0=np.array([0.0]),
    )
    contract = ControllerRangeContract(state_payload_bounds=(128,), input_payload_bounds=(64, 64))
    context = FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8)
    plain_flat = PlaintextStateSpaceRuntime(spec)
    plain_column = PlaintextStateSpaceRuntime(spec)
    secure_flat = SecureStateSpaceRuntime(
        spec, context, contract, security_parameter=8, test_seed=110
    )
    secure_column = SecureStateSpaceRuntime(
        spec, context, contract, security_parameter=8, test_seed=110
    )

    flat_input = np.array([0.25, -0.125])
    column_input = np.array([[0.25], [-0.125]])
    plain_flat_output = plain_flat.step(flat_input)
    plain_column_output = plain_column.step(column_input)
    secure_flat_output = secure_flat.step(flat_input)
    secure_column_output = secure_column.step(column_input)

    assert (
        plain_flat_output.shape
        == plain_column_output.shape
        == secure_flat_output.shape
        == secure_column_output.shape
        == (2,)
    )
    np.testing.assert_array_equal(plain_flat_output, plain_column_output)
    np.testing.assert_array_equal(secure_flat_output, secure_column_output)
    np.testing.assert_allclose(secure_flat_output, plain_flat_output, atol=1.0 / 256.0)


def test_zero_state_runtime_executes_static_d_path() -> None:
    """验证 runtime 不为静态 ``u=Dv`` 控制器虚构 state 或 Trunc 生命周期。"""
    spec = ControllerSpec(
        A=np.empty((0, 0)),
        B=np.empty((0, 2)),
        C=np.empty((1, 0)),
        D=np.array([[-1.5, -0.25]]),
        x0=np.empty(0),
    )
    runtime = SecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(state_payload_bounds=(), input_payload_bounds=(128, 64)),
        security_parameter=8,
        test_seed=111,
    )

    np.testing.assert_allclose(runtime.step([0.5, -0.25]), np.array([-0.6875]))


def test_finite_horizon_runtime_reset_restores_three_step_capability() -> None:
    """有限时间协议第 4 步必须失败且不推进资源；reset 用新 session 恢复可执行步数。"""
    spec = ControllerSpec(
        A=np.array([[1.0]]),
        B=np.array([[1.0]]),
        C=np.array([[1.0]]),
        D=np.array([[0.0]]),
        x0=np.array([0.0]),
        scale_metadata=ControllerScaleMetadata(state=8, input=8, output=8, A=0, B=0, C=0, D=0),
    )
    runtime = SecureStateSpaceRuntime(
        spec,
        FixedPointContext(2_147_483_647, integer_bits=20, fractional_bits=8),
        ControllerRangeContract(
            state_payload_bounds=(768,), input_payload_bounds=(256,), horizon_steps=3
        ),
        security_parameter=8,
        test_seed=180,
    )
    np.testing.assert_array_equal(
        [runtime.step(value) for value in (0.5, -0.25, 0.25)],
        np.array([[0.0], [0.5], [0.25]]),
    )
    created_before = runtime._client.multiplier.created_triples
    with pytest.raises(ValueError, match="horizon"):
        runtime.step(0.0)
    assert runtime._client.multiplier.created_triples == created_before

    runtime.reset()
    np.testing.assert_array_equal(runtime.step(0.5), np.array([0.0]))


@pytest.mark.parametrize(
    ("value", "exception", "message"),
    [
        (np.array([[0.25, 0.0]]), ValueError, "列向量"),
        (np.array([0.25, 0.0]), ValueError, "shape"),
        (np.array([np.nan]), FloatingPointError, "NaN"),
        ("not-a-number", TypeError, "实数"),
        (0.5, ValueError, "input_payload_bounds"),
    ],
)
def test_invalid_step_preserves_state_and_step_semantics(
    value: object, exception: type[Exception], message: str
) -> None:
    """验证非法输入或越界输入失败后，下一次合法 step 仍等同于全新 runtime。"""
    runtime = make_secure_runtime(integer_state_spec(), seed=120)
    fresh = make_secure_runtime(integer_state_spec(), seed=120)

    with pytest.raises(exception, match=message):
        runtime.step(value)  # type: ignore[arg-type]

    np.testing.assert_array_equal(runtime.step(0.25), fresh.step(0.25))


def test_reset_replaces_protocol_session_and_restores_initial_sequence() -> None:
    """验证 reset 创建新 session，并把 state、step 与测试材料序列原子恢复到构造状态。"""
    runtime = make_secure_runtime(general_spec(), seed=130, bound=256)
    fresh = make_secure_runtime(general_spec(), seed=130, bound=256)
    previous_session = runtime._distribution.session_id
    runtime.step(0.25)
    runtime.step(-0.125)

    runtime.reset()

    assert runtime._distribution.session_id != previous_session
    np.testing.assert_array_equal(runtime.step(0.25), fresh.step(0.25))


def test_runtime_reset_reuses_and_revalidates_immutable_modulus_evidence() -> None:
    """安全 runtime 首次构造与 reset 都使用同一公开证据并保留验证摘要。"""
    modulus = 18_446_744_073_709_554_719
    runtime = SecureStateSpaceRuntime(
        integer_state_spec(),
        FixedPointContext(modulus, integer_bits=60, fractional_bits=8),
        ControllerRangeContract(state_payload_bounds=(128,), input_payload_bounds=(64,)),
        security_parameter=8,
        modulus_evidence=_large_prime_evidence(),
        test_seed=131,
    )
    before = runtime.modulus_verification
    runtime.step(0.25)
    runtime.reset()

    assert before.method == "pocklington_v1"
    assert runtime.modulus_verification == before
    np.testing.assert_array_equal(runtime.step(0.25), np.array([0.25]))


def test_interleaved_instances_keep_state_and_rng_isolated() -> None:
    """验证两个安全 runtime 交错执行不会改变彼此的 state、资源或测试 RNG 序列。"""
    first = make_secure_runtime(general_spec(), seed=140, bound=256)
    second = make_secure_runtime(general_spec(), seed=141, bound=256)
    first_reference = make_secure_runtime(general_spec(), seed=140, bound=256)
    second_reference = make_secure_runtime(general_spec(), seed=141, bound=256)

    first_outputs = [first.step(0.25), first.step(-0.125)]
    second_outputs = [second.step(-0.125), second.step(0.25)]
    first_expected = [first_reference.step(0.25), first_reference.step(-0.125)]
    second_expected = [second_reference.step(-0.125), second_reference.step(0.25)]

    np.testing.assert_array_equal(first_outputs, first_expected)
    np.testing.assert_array_equal(second_outputs, second_expected)


def test_reconstruction_failure_rolls_back_state_and_revokes_round(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """验证 output 重构失败会回滚已提交 state，且同一 step 可用新资源安全重试。"""
    runtime = make_secure_runtime(general_spec(), seed=150, bound=256)
    fresh = make_secure_runtime(general_spec(), seed=150, bound=256)
    original = Client.reconstruct_control
    failed = False

    def fail_once(client: Client, *args: object) -> np.ndarray:
        """仅对目标 runtime 的首轮注入一次重构错误。"""
        nonlocal failed
        if client is runtime._client and not failed:
            failed = True
            raise ValueError("injected reconstruction failure")
        return original(client, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(Client, "reconstruct_control", fail_once)
    with pytest.raises(ValueError, match="injected reconstruction failure"):
        runtime.step(0.25)
    assert runtime._client._issued_rounds == {}

    # fresh 首轮与失败 runtime 的重试使用不同材料 epoch，但 controller 语义仍须一致。
    np.testing.assert_allclose(runtime.step(0.25), fresh.step(0.25), atol=1.0 / 256.0)


def test_reset_failure_keeps_previous_session_usable(monkeypatch: pytest.MonkeyPatch) -> None:
    """验证新 session 建立失败时，reset 不会破坏旧 session 的 state 或 step。"""
    runtime = make_secure_runtime(integer_state_spec(), seed=160)
    reference = make_secure_runtime(integer_state_spec(), seed=160)
    runtime.step(0.25)
    reference.step(0.25)
    original = Client.distribute_controller

    def fail_distribution(*args: object, **kwargs: object) -> object:
        """模拟 reset 期间离线分发失败。"""
        raise ValueError("injected reset failure")

    monkeypatch.setattr(Client, "distribute_controller", fail_distribution)
    with pytest.raises(ValueError, match="injected reset failure"):
        runtime.reset()
    monkeypatch.setattr(Client, "distribute_controller", original)

    np.testing.assert_array_equal(runtime.step(-0.125), reference.step(-0.125))


def test_protocol_execution_failure_is_propagated_without_half_step_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """验证 coordinator 在提交后抛错时，runtime 回滚两方 state 并保留原始异常。"""
    runtime = make_secure_runtime(integer_state_spec(), seed=170)
    fresh = make_secure_runtime(integer_state_spec(), seed=170)
    original = SingleProcessCoordinator.execute
    failed = False

    def fail_after_commit(
        coordinator: SingleProcessCoordinator, *args: object
    ) -> tuple[object, object]:
        """仅在目标 coordinator 首次提交 state 后注入失败。"""
        nonlocal failed
        result = original(coordinator, *args)  # type: ignore[arg-type]
        if coordinator is runtime._coordinator and not failed:
            failed = True
            raise RuntimeError("injected execution failure")
        return result

    monkeypatch.setattr(SingleProcessCoordinator, "execute", fail_after_commit)
    with pytest.raises(RuntimeError, match="injected execution failure"):
        runtime.step(0.25)
    assert runtime._client._issued_rounds == {}

    np.testing.assert_array_equal(runtime.step(0.25), fresh.step(0.25))
