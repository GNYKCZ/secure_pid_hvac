"""[38] 四级串联对象与 #69 paper-inspired 单支明文产物的验证。"""

from __future__ import annotations

import csv
import json
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest
import yaml
from scipy.linalg import expm

from secure_control.experiments.paper_pid_runner import run_paper_pid_experiment
from secure_control.scenarios.paper_pid.baseline import (
    BASELINE_COLUMNS,
    run_paper_pid_baseline,
)
from secure_control.scenarios.paper_pid.plant import (
    PaperPidCascadePlant,
    build_cascade_zoh_state_space,
)

CONFIG = Path(__file__).resolve().parents[1] / "configs" / "paper_pid_cascade_zoh.yaml"


def test_cascade_continuous_model_matches_benchmark_equation_two() -> None:
    """四级单位静态增益串联必须对应 [38] Eq. (2)，而非 HVAC 模型。"""
    m = build_cascade_zoh_state_space(0.2, 0.1)
    np.testing.assert_allclose(
        m.F,
        [[-1, 0, 0, 0], [5, -5, 0, 0], [0, 25, -25, 0], [0, 0, 125, -125]],
        rtol=1e-14,
        atol=1e-14,
    )
    np.testing.assert_array_equal(m.G, [[1], [0], [0], [0]])
    np.testing.assert_array_equal(m.H, [[0, 0, 0, 1]])
    np.testing.assert_array_equal(m.J, [[0]])
    for s in (0.0, 0.5, 3.0, 10.0):
        actual = float((m.H @ np.linalg.solve(s * np.eye(4) - m.F, m.G))[0, 0])
        expected = 1.0 / ((s + 1) * (1 + 0.2 * s) * (1 + 0.04 * s) * (1 + 0.008 * s))
        assert actual == pytest.approx(expected, rel=1e-13, abs=1e-13)


def test_zoh_matches_independent_augmented_exponential_and_poles() -> None:
    """用增广矩阵指数和解析极点交叉校核 SciPy ZOH 派生矩阵。"""
    m = build_cascade_zoh_state_space(0.2, 0.1)
    augmented = np.zeros((5, 5))
    augmented[:4, :4] = m.F
    augmented[:4, 4:] = m.G
    reference = expm(augmented * 0.1)
    np.testing.assert_allclose(m.A_p, reference[:4, :4], rtol=1e-13, atol=1e-14)
    np.testing.assert_allclose(m.B_p, reference[:4, 4:], rtol=1e-13, atol=1e-14)
    np.testing.assert_array_equal(m.C_p, m.H)
    np.testing.assert_array_equal(m.D_p, [[0]])
    np.testing.assert_allclose(
        np.sort(np.linalg.eigvals(m.A_p).real),
        np.sort(np.exp(-0.1 * np.array([1.0, 5.0, 25.0, 125.0]))),
        rtol=1e-11,
        atol=1e-13,
    )


def test_plant_initial_coordinates_and_transactional_step() -> None:
    """所选坐标下四级初值各为 100，输出为第四级且非法输入不漂移。"""
    plant = PaperPidCascadePlant(0.2, 0.1, [100.0] * 4)
    np.testing.assert_array_equal(plant.state, [100.0] * 4)
    np.testing.assert_array_equal(plant.output(), [100.0])
    assert not plant.state.flags.writeable
    with pytest.raises(ValueError, match="shape"):
        plant.step(np.array([1.0, 2.0]))
    with pytest.raises(FloatingPointError, match="NaN"):
        plant.step(np.array([np.nan]))
    np.testing.assert_array_equal(plant.state, [100.0] * 4)
    m = plant.state_space
    expected = m.A_p @ plant.state + m.B_p[:, 0] * -501.071167
    np.testing.assert_allclose(plant.step(np.array([-501.071167])), m.C_p @ expected)
    np.testing.assert_allclose(plant.state, expected)
    plant.reset()
    np.testing.assert_array_equal(plant.state, [100.0] * 4)


@pytest.mark.parametrize(
    ("alpha", "period", "state", "error"),
    [
        (0.0, 0.1, [100.0] * 4, ValueError),
        (True, 0.1, [100.0] * 4, ValueError),
        (0.2, np.inf, [100.0] * 4, ValueError),
        (1e-200, 0.1, [100.0] * 4, FloatingPointError),
        (0.2, 0.1, [100.0] * 3, ValueError),
        (0.2, 0.1, [100.0, 100.0, np.nan, 100.0], FloatingPointError),
    ],
)
def test_invalid_plant_parameters_fail_closed(alpha, period, state, error) -> None:
    """错误时间/状态不能通过 NumPy 广播或隐式转换进入模型。"""
    with pytest.raises(error):
        PaperPidCascadePlant(alpha, period, state)


def test_51_step_baseline_matches_independent_difference_and_plant_recurrence() -> None:
    """独立 I/d 差分式及矩阵指数对象逐步核对十列更新前日志。"""
    result = run_paper_pid_baseline(
        alpha=0.2, sample_period_seconds=0.1,
        plant_initial_state=[100.0] * 4, sample_count=51,
    )
    m = result.plant_matrices
    augmented = np.zeros((5, 5))
    augmented[:4, :4] = m.F
    augmented[:4, 4:] = m.G
    discrete = expm(augmented * 0.1)
    x_p = np.full(4, 100.0)
    x_c = np.zeros(2)
    integral = derivative = previous_y = 0.0
    expected_rows = []
    for k in range(51):
        y = x_p[3]
        # 参数仅由论文印刷矩阵反推作测试 oracle，不在运行代码中重算 controller。
        derivative = (-0.296540833 / 0.1) * (y - previous_y)
        raw_u = -2.04530334 * y + integral + derivative
        expected_rows.append((k, k * 0.1, *x_p, y, *x_c, raw_u))
        x_c = np.array([x_c[0] + y, x_c[0]])
        x_p = discrete[:4, :4] @ x_p + discrete[:4, 4] * raw_u
        integral += -2.2851563 * 0.1 * y
        previous_y = y
    assert result.rows.shape == (51, len(BASELINE_COLUMNS))
    np.testing.assert_allclose(result.rows, expected_rows, rtol=1e-12, atol=1e-10)
    assert result.rows[0, 6] == 100.0
    assert result.rows[0, 9] == pytest.approx(-501.071167)
    assert result.rows[-1, 0] == 50.0
    assert result.rows[-1, 1] == 5.0
    assert result.stability.status == "stable"
    phi = np.block(
        [
            [m.A_p + m.B_p @ np.array([[-5.01071167]]) @ m.C_p,
             m.B_p @ np.array([[2.7368927, -2.96540833]])],
            [np.array([[1.0], [0.0]]) @ m.C_p, np.array([[1.0, 0.0], [1.0, 0.0]])],
        ]
    )
    assert result.stability.spectral_radius == pytest.approx(
        max(abs(np.linalg.eigvals(phi))), rel=1e-12
    )


def test_runner_publishes_replayable_paper_inspired_artifacts(tmp_path: Path) -> None:
    """两次运行数值完全一致；元数据保留来源/矩阵/稳定诊断而不伪装原例。"""
    root = tmp_path / "artifacts"
    first = run_paper_pid_experiment(CONFIG, output_root=root)
    second = run_paper_pid_experiment(CONFIG, output_root=root)
    assert first != second
    assert sorted(path.name for path in root.iterdir()) == sorted([first.name, second.name])
    first_bytes = (first / "trajectory.csv").read_bytes()
    assert first_bytes == (second / "trajectory.csv").read_bytes()
    with (first / "trajectory.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    metadata = json.loads((first / "metadata.json").read_text(encoding="utf-8"))
    assert len(rows) == 51
    assert list(rows[0]) == list(BASELINE_COLUMNS)
    assert float(rows[0]["y"]) == 100.0
    assert float(rows[0]["raw_u"]) == pytest.approx(-501.071167)
    assert int(rows[-1]["k"]) == 50
    assert metadata["claim_level"] == "paper-inspired"
    assert metadata["sources"]["plant_equation"] == "Eq. (2)"
    assert metadata["model"]["realization"] == "four_stage_cascade_outputs"
    assert metadata["model"]["discretization"] == "zoh"
    assert metadata["model"]["controller_initial_state"] == [0.0, 0.0]
    assert metadata["closed_loop_stability"]["status"] == "stable"
    assert metadata["trajectory"]["sha256"] == sha256(first_bytes).hexdigest()
    assert metadata["config_sha256"] == sha256(CONFIG.read_bytes()).hexdigest()
    assert len(metadata["git"]["head_sha"]) == 40
    assert isinstance(metadata["git"]["dirty"], bool)
    assert "not the authors' original matrices" in metadata["limitation"]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("claim_level",), "paper-original"),
        (("sample_count",), 50),
        (("plant", "alpha"), 0.3),
        (("plant", "discretization"), "euler"),
        (("plant", "initial_state"), [100, 100, 100, 0]),
        (("sources", "plant_equation"), "unknown"),
    ],
)
def test_runner_rejects_drifted_config_without_publishing(
    tmp_path: Path, path: tuple[str, ...], value
) -> None:
    """改变来源、参数或声明等级不能沿用本原例名称发布成功目录。"""
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    target = config
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    changed = tmp_path / "changed.yaml"
    changed.write_text(yaml.safe_dump(config), encoding="utf-8")
    root = tmp_path / "artifacts"
    with pytest.raises(ValueError):
        run_paper_pid_experiment(changed, output_root=root)
    assert not root.exists()


def test_writer_failure_leaves_no_success_directory(tmp_path: Path, monkeypatch) -> None:
    """CSV 写入失败后临时 staging 自动清理，不出现 success sidecar。"""
    from secure_control.experiments import paper_pid_runner

    def fail_after_partial_write(path: Path, _result) -> None:
        path.write_text("partial", encoding="utf-8")
        raise OSError("simulated write failure")

    monkeypatch.setattr(paper_pid_runner, "_write_csv", fail_after_partial_write)
    root = tmp_path / "artifacts"
    with pytest.raises(OSError, match="simulated"):
        run_paper_pid_experiment(CONFIG, output_root=root)
    assert list(root.iterdir()) == []
