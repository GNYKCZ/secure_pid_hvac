"""精确有理数鲁棒不变集验证器的正反例测试。"""

from dataclasses import replace

from secure_control.core import (
    EllipsoidalInvariantWitness,
    LinearSafetyConstraint,
    RationalBox,
    RationalValue,
    RobustAffineInvariantProblem,
    invariant_certificate_sha256,
    verify_ellipsoidal_invariant,
)


def q(numerator: int, denominator: int = 1) -> RationalValue:
    """缩短测试中的精确有理数构造。"""
    return RationalValue(numerator, denominator)


def toy_certificate():
    """返回标量稳定系统的最小正证书。"""
    problem = RobustAffineInvariantProblem(
        transition=((q(1, 2),),),
        affine=(q(0),),
        disturbance_matrix=((q(1),),),
        disturbance_abs_bounds=(q(1, 10),),
        initial_set=RationalBox((q(-1, 10),), (q(1, 10),)),
        constraints=(
            LinearSafetyConstraint(
                "state",
                (q(1),),
                q(0),
                (q(0),),
                q(-3, 10),
                q(3, 10),
            ),
        ),
        state_labels=("x",),
    )
    witness = EllipsoidalInvariantWitness(
        equilibrium=(q(0),),
        shape_matrix=((q(1),),),
        contraction_bound=q(3, 5),
        disturbance_norm_bounds=(q(1),),
        radius=q(1, 4),
        constraint_dual_norm_bounds=(q(1),),
    )
    return problem, witness


def test_toy_invariant_is_certified_with_stable_hash() -> None:
    problem, witness = toy_certificate()

    report = verify_ellipsoidal_invariant(problem, witness)

    assert report.status == "certified"
    assert report.reason_codes == ()
    assert report.certificate_sha256 == invariant_certificate_sha256(problem, witness)
    assert report.coordinate_bounds[0].lower == q(-1, 4)
    assert report.coordinate_bounds[0].upper == q(1, 4)


def test_unstable_or_invalid_witnesses_are_rejected() -> None:
    problem, witness = toy_certificate()
    unstable = replace(problem, transition=((q(2),),))
    small_radius = replace(witness, radius=q(1, 10))
    outside_initial = replace(
        problem,
        initial_set=RationalBox((q(-1),), (q(1),)),
    )
    singular_shape = replace(witness, shape_matrix=((q(0),),))

    assert verify_ellipsoidal_invariant(unstable, witness).status == "rejected"
    assert verify_ellipsoidal_invariant(problem, small_radius).status == "rejected"
    assert verify_ellipsoidal_invariant(outside_initial, witness).status == "rejected"
    assert verify_ellipsoidal_invariant(problem, singular_shape).reason_codes == (
        "shape_symmetric_positive_definite",
    )


def test_constraint_violation_and_resource_limit_fail_closed() -> None:
    problem, witness = toy_certificate()
    narrow = replace(
        problem,
        constraints=(replace(problem.constraints[0], lower=q(-1, 10), upper=q(1, 10)),),
    )
    assert verify_ellipsoidal_invariant(narrow, witness).status == "rejected"

    dimension = 13
    oversized = RobustAffineInvariantProblem(
        transition=tuple(
            tuple(q(int(row == column)) for column in range(dimension)) for row in range(dimension)
        ),
        affine=tuple(q(0) for _ in range(dimension)),
        disturbance_matrix=tuple(() for _ in range(dimension)),
        disturbance_abs_bounds=(),
        initial_set=RationalBox(
            tuple(q(0) for _ in range(dimension)),
            tuple(q(0) for _ in range(dimension)),
        ),
        constraints=(),
        state_labels=tuple(f"x{index}" for index in range(dimension)),
    )
    oversized_witness = EllipsoidalInvariantWitness(
        equilibrium=tuple(q(0) for _ in range(dimension)),
        shape_matrix=oversized.transition,
        contraction_bound=q(1, 2),
        disturbance_norm_bounds=(),
        radius=q(1),
        constraint_dual_norm_bounds=(),
    )
    report = verify_ellipsoidal_invariant(oversized, oversized_witness)
    assert report.status == "indeterminate"
    assert report.reason_codes == ("resource_limit_exceeded",)
    assert report.certificate_sha256 == ""
