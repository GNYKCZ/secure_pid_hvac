"""领域无关的精确有理数鲁棒仿射不变集验证器。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
from itertools import product
from math import gcd, isqrt
from numbers import Integral
from typing import Literal

InvariantStatus = Literal["certified", "rejected", "indeterminate"]

_MAX_DIMENSION = 12
_MAX_DISTURBANCES = 16
_MAX_CONSTRAINTS = 128
_MAX_INTEGER_BITS = 8192
_MAX_INITIAL_VERTICES = 4096


@dataclass(frozen=True, slots=True)
class RationalValue:
    """保存约分后且分母恒正的精确有理数。"""

    numerator: int
    denominator: int = 1

    def __post_init__(self) -> None:
        """规范化符号和最大公因数，并拒绝布尔值与零分母。"""
        if isinstance(self.numerator, bool) or not isinstance(self.numerator, Integral):
            raise TypeError("numerator 必须是整数")
        if isinstance(self.denominator, bool) or not isinstance(self.denominator, Integral):
            raise TypeError("denominator 必须是整数")
        numerator = int(self.numerator)
        denominator = int(self.denominator)
        if denominator == 0:
            raise ValueError("denominator 不得为零")
        if denominator < 0:
            numerator, denominator = -numerator, -denominator
        common = gcd(abs(numerator), denominator)
        object.__setattr__(self, "numerator", numerator // common)
        object.__setattr__(self, "denominator", denominator // common)

    @property
    def fraction(self) -> Fraction:
        """返回标准库 ``Fraction``，供验证器执行精确运算。"""
        return Fraction(self.numerator, self.denominator)

    @classmethod
    def from_fraction(cls, value: Fraction) -> RationalValue:
        """由已约分的 ``Fraction`` 建立公开记录。"""
        return cls(value.numerator, value.denominator)


RationalVector = tuple[RationalValue, ...]
RationalMatrix = tuple[RationalVector, ...]


@dataclass(frozen=True, slots=True)
class RationalBox:
    """保存闭区间盒的逐坐标下界与上界。"""

    lower: RationalVector
    upper: RationalVector

    def __post_init__(self) -> None:
        """拒绝维数不一致和反向区间。"""
        if len(self.lower) != len(self.upper) or not self.lower:
            raise ValueError("RationalBox 必须具有相同且非零的上下界维数")
        if any(low.fraction > high.fraction for low, high in zip(self.lower, self.upper)):
            raise ValueError("RationalBox 下界不得大于上界")


@dataclass(frozen=True, slots=True)
class LinearSafetyConstraint:
    """描述 ``lower <= h*z + offset + d*w <= upper`` 的安全约束。"""

    name: str
    state_row: RationalVector
    offset: RationalValue
    disturbance_row: RationalVector
    lower: RationalValue
    upper: RationalValue
    strict: bool = False

    def __post_init__(self) -> None:
        """拒绝空名称、反向界和非布尔严格性标记。"""
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("constraint name 必须是非空字符串")
        if self.lower.fraction > self.upper.fraction:
            raise ValueError("constraint lower 不得大于 upper")
        if type(self.strict) is not bool:
            raise TypeError("constraint strict 必须是 bool")


@dataclass(frozen=True, slots=True)
class RobustAffineInvariantProblem:
    """保存 ``z+=Phi*z+a+G*w``、扰动盒、初始盒和线性约束。"""

    transition: RationalMatrix
    affine: RationalVector
    disturbance_matrix: RationalMatrix
    disturbance_abs_bounds: RationalVector
    initial_set: RationalBox
    constraints: tuple[LinearSafetyConstraint, ...]
    state_labels: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EllipsoidalInvariantWitness:
    """保存椭球不变集的中心、度量、收缩界和全部精确上界。"""

    equilibrium: RationalVector
    shape_matrix: RationalMatrix
    contraction_bound: RationalValue
    disturbance_norm_bounds: RationalVector
    radius: RationalValue
    constraint_dual_norm_bounds: RationalVector


@dataclass(frozen=True, slots=True)
class ExactInvariantCheck:
    """保存单项精确判定的稳定名称与结果。"""

    name: str
    passed: bool


@dataclass(frozen=True, slots=True)
class RationalInterval:
    """保存验证器推导出的精确闭区间。"""

    lower: RationalValue
    upper: RationalValue


@dataclass(frozen=True, slots=True)
class InvariantResourceUsage:
    """记录本次精确验证使用的有限维数与顶点数量。"""

    state_dimension: int
    disturbance_dimension: int
    constraint_count: int
    initial_vertex_count: int
    maximum_integer_bits: int


@dataclass(frozen=True, slots=True)
class InvariantVerificationReport:
    """返回可审计的三态结论、证书摘要、投影范围和精确检查。"""

    status: InvariantStatus
    reason_codes: tuple[str, ...]
    certificate_sha256: str
    coordinate_bounds: tuple[RationalInterval, ...]
    constraint_bounds: tuple[tuple[str, RationalInterval], ...]
    exact_checks: tuple[ExactInvariantCheck, ...]
    resource_usage: InvariantResourceUsage


class _ResourceLimitError(Exception):
    """标记输入规模超过冻结预算，而不是数学反例。"""


def verify_ellipsoidal_invariant(
    problem: RobustAffineInvariantProblem,
    witness: EllipsoidalInvariantWitness,
) -> InvariantVerificationReport:
    """用精确有理数验证鲁棒正不变椭球与全部安全约束。

    返回 ``certified`` 仅当平衡、正定、收缩、扰动闭包、初始包含和约束投影
    全部精确成立；数学反例返回 ``rejected``，资源预算不足返回 ``indeterminate``。
    """
    if not isinstance(problem, RobustAffineInvariantProblem):
        raise TypeError("problem 必须是 RobustAffineInvariantProblem")
    if not isinstance(witness, EllipsoidalInvariantWitness):
        raise TypeError("witness 必须是 EllipsoidalInvariantWitness")
    try:
        _preflight_resource_limits(problem, witness)
    except _ResourceLimitError:
        return InvariantVerificationReport(
            "indeterminate",
            ("resource_limit_exceeded",),
            "",
            (),
            (),
            (),
            InvariantResourceUsage(0, 0, 0, 0, 0),
        )
    digest = invariant_certificate_sha256(problem, witness)
    checks: list[ExactInvariantCheck] = []
    coordinate_bounds: tuple[RationalInterval, ...] = ()
    constraint_bounds: tuple[tuple[str, RationalInterval], ...] = ()
    usage = InvariantResourceUsage(0, 0, 0, 0, 0)
    try:
        values = _validated_values(problem, witness)
        (
            transition,
            affine,
            disturbance,
            disturbance_bounds,
            initial_lower,
            initial_upper,
            shape,
            equilibrium,
            gamma,
            eta,
            radius,
            xi,
        ) = values
        n = len(transition)
        m = len(disturbance_bounds)
        vertex_count = 1 << n
        usage = InvariantResourceUsage(
            n,
            m,
            len(problem.constraints),
            vertex_count,
            _maximum_integer_bits(problem, witness),
        )

        equilibrium_ok = _vector_equal(
            equilibrium,
            _vector_add(_matrix_vector(transition, equilibrium), affine),
        )
        checks.append(ExactInvariantCheck("equilibrium_fixed_point", equilibrium_ok))

        shape_ok = _is_symmetric(shape) and _positive_definite(shape)
        checks.append(ExactInvariantCheck("shape_symmetric_positive_definite", shape_ok))
        if not shape_ok:
            return InvariantVerificationReport(
                "rejected",
                ("shape_symmetric_positive_definite",),
                digest,
                (),
                (),
                tuple(checks),
                usage,
            )
        gamma_ok = Fraction(0) <= gamma < Fraction(1)
        checks.append(ExactInvariantCheck("contraction_bound_in_unit_interval", gamma_ok))
        contraction = _matrix_subtract(
            _scalar_matrix(gamma * gamma, shape),
            _matrix_multiply(_transpose(transition), _matrix_multiply(shape, transition)),
        )
        contraction_ok = _is_symmetric(contraction) and _positive_definite(contraction)
        checks.append(ExactInvariantCheck("strict_lyapunov_contraction", contraction_ok))

        disturbance_ok = all(
            bound >= 0 and eta_bound >= 0 and eta_bound * eta_bound >= _quadratic(shape, column)
            for bound, eta_bound, column in zip(disturbance_bounds, eta, _columns(disturbance))
        )
        checks.append(ExactInvariantCheck("disturbance_norm_bounds", disturbance_ok))
        beta = sum(
            (eta_bound * bound for eta_bound, bound in zip(eta, disturbance_bounds)),
            Fraction(0),
        )
        radius_ok = radius > 0 and radius * (1 - gamma) >= beta
        checks.append(ExactInvariantCheck("robust_radius_closure", radius_ok))

        initial_ok = all(
            _quadratic(shape, _vector_subtract(vertex, equilibrium)) <= radius * radius
            for vertex in product(*zip(initial_lower, initial_upper))
        )
        checks.append(ExactInvariantCheck("initial_box_inclusion", initial_ok))

        inverse_shape = _inverse(shape)
        coordinate_bounds = tuple(
            _projection_interval(
                equilibrium[index],
                radius,
                _unit_dual_bound(inverse_shape, index),
                Fraction(0),
            )
            for index in range(n)
        )
        constraint_results: list[tuple[str, RationalInterval]] = []
        constraints_ok = True
        for index, constraint in enumerate(problem.constraints):
            row = _fractions(constraint.state_row)
            direct = sum(
                (
                    abs(coefficient) * bound
                    for coefficient, bound in zip(
                        _fractions(constraint.disturbance_row), disturbance_bounds
                    )
                ),
                Fraction(0),
            )
            dual_square = _quadratic(inverse_shape, row)
            dual_ok = xi[index] >= 0 and xi[index] * xi[index] >= dual_square
            checks.append(ExactInvariantCheck(f"constraint_dual_norm:{constraint.name}", dual_ok))
            center = _dot(row, equilibrium) + constraint.offset.fraction
            interval = _projection_interval(center, radius, xi[index], direct)
            constraint_results.append((constraint.name, interval))
            if constraint.strict:
                safe = (
                    interval.lower.fraction > constraint.lower.fraction
                    and interval.upper.fraction < constraint.upper.fraction
                )
            else:
                safe = (
                    interval.lower.fraction >= constraint.lower.fraction
                    and interval.upper.fraction <= constraint.upper.fraction
                )
            checks.append(ExactInvariantCheck(f"constraint_range:{constraint.name}", safe))
            constraints_ok &= dual_ok and safe
        constraint_bounds = tuple(constraint_results)
        passed = (
            equilibrium_ok
            and shape_ok
            and gamma_ok
            and contraction_ok
            and disturbance_ok
            and radius_ok
            and initial_ok
            and constraints_ok
        )
        reasons = () if passed else tuple(check.name for check in checks if not check.passed)
        return InvariantVerificationReport(
            "certified" if passed else "rejected",
            reasons,
            digest,
            coordinate_bounds,
            constraint_bounds,
            tuple(checks),
            usage,
        )
    except _ResourceLimitError:
        return InvariantVerificationReport(
            "indeterminate",
            ("resource_limit_exceeded",),
            digest,
            coordinate_bounds,
            constraint_bounds,
            tuple(checks),
            usage,
        )


def invariant_certificate_sha256(
    problem: RobustAffineInvariantProblem,
    witness: EllipsoidalInvariantWitness,
) -> str:
    """按稳定 UTF-8/LF JSON 计算 problem 与 witness 的规范摘要。"""
    payload = {"problem": _canonical(problem), "witness": _canonical(witness)}
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _preflight_resource_limits(problem, witness) -> None:
    """在规范序列化前以常数级顶层检查阻止超大证书消耗资源。"""
    n = len(problem.transition)
    m = len(problem.disturbance_abs_bounds)
    constraint_count = len(problem.constraints)
    if (
        n == 0
        or n > _MAX_DIMENSION
        or m > _MAX_DISTURBANCES
        or constraint_count > _MAX_CONSTRAINTS
        or (1 << n) > _MAX_INITIAL_VERTICES
    ):
        raise _ResourceLimitError
    matrix_rows = (
        *problem.transition,
        *problem.disturbance_matrix,
        *witness.shape_matrix,
    )
    if any(len(row) > max(_MAX_DIMENSION, _MAX_DISTURBANCES) for row in matrix_rows):
        raise _ResourceLimitError
    if len(problem.affine) > _MAX_DIMENSION or len(problem.state_labels) > _MAX_DIMENSION:
        raise _ResourceLimitError
    if (
        len(witness.equilibrium) > _MAX_DIMENSION
        or len(witness.disturbance_norm_bounds) > _MAX_DISTURBANCES
        or len(witness.constraint_dual_norm_bounds) > _MAX_CONSTRAINTS
    ):
        raise _ResourceLimitError
    for constraint in problem.constraints:
        if (
            len(constraint.state_row) > _MAX_DIMENSION
            or len(constraint.disturbance_row) > _MAX_DISTURBANCES
        ):
            raise _ResourceLimitError
    if _maximum_integer_bits(problem, witness) > _MAX_INTEGER_BITS:
        raise _ResourceLimitError


def _validated_values(problem, witness):
    """校验维数与资源预算，并转换为 ``Fraction`` 容器。"""
    n = len(problem.transition)
    m = len(problem.disturbance_abs_bounds)
    if n == 0 or n > _MAX_DIMENSION or m > _MAX_DISTURBANCES:
        raise _ResourceLimitError
    if len(problem.constraints) > _MAX_CONSTRAINTS or (1 << n) > _MAX_INITIAL_VERTICES:
        raise _ResourceLimitError
    if len(problem.state_labels) != n or len(set(problem.state_labels)) != n:
        raise ValueError("state_labels 必须与状态维数一致且不得重复")
    if any(not isinstance(label, str) or not label for label in problem.state_labels):
        raise ValueError("state_labels 必须是非空字符串")
    transition = _matrix(problem.transition, n, n, "transition")
    affine = _vector(problem.affine, n, "affine")
    disturbance = _matrix(problem.disturbance_matrix, n, m, "disturbance_matrix")
    disturbance_bounds = _vector(problem.disturbance_abs_bounds, m, "disturbance_abs_bounds")
    initial_lower = _vector(problem.initial_set.lower, n, "initial_set.lower")
    initial_upper = _vector(problem.initial_set.upper, n, "initial_set.upper")
    shape = _matrix(witness.shape_matrix, n, n, "shape_matrix")
    equilibrium = _vector(witness.equilibrium, n, "equilibrium")
    eta = _vector(witness.disturbance_norm_bounds, m, "disturbance_norm_bounds")
    xi = _vector(
        witness.constraint_dual_norm_bounds,
        len(problem.constraints),
        "constraint_dual_norm_bounds",
    )
    for constraint in problem.constraints:
        _vector(constraint.state_row, n, f"{constraint.name}.state_row")
        _vector(constraint.disturbance_row, m, f"{constraint.name}.disturbance_row")
    bit_count = _maximum_integer_bits(problem, witness)
    if bit_count > _MAX_INTEGER_BITS:
        raise _ResourceLimitError
    return (
        transition,
        affine,
        disturbance,
        disturbance_bounds,
        initial_lower,
        initial_upper,
        shape,
        equilibrium,
        witness.contraction_bound.fraction,
        eta,
        witness.radius.fraction,
        xi,
    )


def _maximum_integer_bits(problem, witness) -> int:
    """返回证书内分子和分母的最大位数。"""
    values: list[RationalValue] = []

    def visit(value) -> None:
        if isinstance(value, RationalValue):
            values.append(value)
        elif isinstance(value, tuple):
            for item in value:
                visit(item)
        elif hasattr(value, "__dataclass_fields__"):
            for name in value.__dataclass_fields__:
                visit(getattr(value, name))

    visit(problem)
    visit(witness)
    return max(
        (
            max(abs(value.numerator).bit_length(), value.denominator.bit_length())
            for value in values
        ),
        default=0,
    )


def _canonical(value):
    """把证书对象转换为不含浮点数的规范 JSON 载荷。"""
    if isinstance(value, RationalValue):
        return [value.numerator, value.denominator]
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return {name: _canonical(getattr(value, name)) for name in value.__dataclass_fields__}
    if isinstance(value, (str, bool)):
        return value
    raise TypeError(f"证书包含不可规范序列化的类型：{type(value).__name__}")


def _fractions(values: RationalVector) -> tuple[Fraction, ...]:
    return tuple(value.fraction for value in values)


def _vector(values, expected, name):
    if len(values) != expected:
        raise ValueError(f"{name} 维数无效")
    return _fractions(values)


def _matrix(values, rows, columns, name):
    if len(values) != rows or any(len(row) != columns for row in values):
        raise ValueError(f"{name} shape 无效")
    return tuple(_fractions(row) for row in values)


def _transpose(matrix):
    return tuple(
        tuple(matrix[row][column] for row in range(len(matrix))) for column in range(len(matrix[0]))
    )


def _matrix_vector(matrix, vector):
    return tuple(_dot(row, vector) for row in matrix)


def _matrix_multiply(left, right):
    right_t = _transpose(right)
    return tuple(tuple(_dot(row, column) for column in right_t) for row in left)


def _matrix_subtract(left, right):
    return tuple(tuple(a - b for a, b in zip(x, y)) for x, y in zip(left, right))


def _scalar_matrix(value, matrix):
    return tuple(tuple(value * item for item in row) for row in matrix)


def _vector_add(left, right):
    return tuple(a + b for a, b in zip(left, right))


def _vector_subtract(left, right):
    return tuple(a - b for a, b in zip(left, right))


def _vector_equal(left, right):
    return len(left) == len(right) and all(a == b for a, b in zip(left, right))


def _dot(left, right):
    return sum((a * b for a, b in zip(left, right)), Fraction(0))


def _quadratic(matrix, vector):
    return _dot(vector, _matrix_vector(matrix, vector))


def _columns(matrix):
    if not matrix:
        return ()
    if not matrix[0]:
        return ()
    return _transpose(matrix)


def _is_symmetric(matrix):
    return matrix == _transpose(matrix)


def _determinant(matrix):
    """用 Bareiss 消元计算精确行列式。"""
    size = len(matrix)
    work = [list(row) for row in matrix]
    sign = 1
    previous = Fraction(1)
    for pivot_index in range(size - 1):
        if work[pivot_index][pivot_index] == 0:
            swap = next(
                (row for row in range(pivot_index + 1, size) if work[row][pivot_index] != 0),
                None,
            )
            if swap is None:
                return Fraction(0)
            work[pivot_index], work[swap] = work[swap], work[pivot_index]
            sign *= -1
        pivot = work[pivot_index][pivot_index]
        for row in range(pivot_index + 1, size):
            for column in range(pivot_index + 1, size):
                work[row][column] = (
                    work[row][column] * pivot - work[row][pivot_index] * work[pivot_index][column]
                ) / previous
        previous = pivot
    return Fraction(sign) * work[-1][-1]


def _positive_definite(matrix):
    return all(
        _determinant(tuple(row[:size] for row in matrix[:size])) > 0
        for size in range(1, len(matrix) + 1)
    )


def _inverse(matrix):
    size = len(matrix)
    work = [
        list(row) + [Fraction(int(i == j)) for j in range(size)] for i, row in enumerate(matrix)
    ]
    for column in range(size):
        pivot = next((row for row in range(column, size) if work[row][column] != 0), None)
        if pivot is None:
            raise ValueError("shape_matrix 不可逆")
        work[column], work[pivot] = work[pivot], work[column]
        divisor = work[column][column]
        work[column] = [value / divisor for value in work[column]]
        for row in range(size):
            if row == column:
                continue
            factor = work[row][column]
            work[row] = [a - factor * b for a, b in zip(work[row], work[column])]
    return tuple(tuple(row[size:]) for row in work)


def _unit_dual_bound(inverse_shape, index):
    """返回坐标投影范数的保守有理上界；整数上取整避免求平方根。"""
    value = inverse_shape[index][index]
    if value < 0:
        raise ValueError("正定矩阵逆的对角元不得为负")
    quotient = value.numerator // value.denominator
    integer = isqrt(quotient)
    if integer * integer * value.denominator < value.numerator:
        integer += 1
    return Fraction(integer)


def _projection_interval(center, radius, dual_bound, direct):
    half_width = radius * dual_bound + direct
    return RationalInterval(
        RationalValue.from_fraction(center - half_width),
        RationalValue.from_fraction(center + half_width),
    )
