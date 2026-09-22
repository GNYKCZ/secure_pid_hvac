"""Exact-grid control-error derivation from verified binary64 and integer evidence."""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

ExactGridClassification = Literal["exact_grid_zero", "float64_collision", "nonzero"]


@dataclass(frozen=True, slots=True)
class ExactGridControlRow:
    """One lossless exact-grid comparison for an applied-control sample."""

    ell: int
    seed: int
    step: int
    channel: int
    output_fractional_bits: int
    ideal_grid_integer: int
    secure_grid_integer: int
    signed_error_integer: int
    float64_applied_error: float
    classification: ExactGridClassification

    @property
    def exact_grid_error(self) -> Fraction:
        """Return the grid-quantized error ``(M-U)/2**s`` exactly."""
        return Fraction(self.signed_error_integer, 1 << self.output_fractional_bits)


def paper_round_fraction(value: Fraction) -> int:
    """Apply the paper's integer rule ``floor(value + 1/2)`` exactly."""
    if not isinstance(value, Fraction):
        raise TypeError("paper_round_fraction 只接受 Fraction。")
    shifted = value + Fraction(1, 2)
    return shifted.numerator // shifted.denominator


def derive_exact_grid_row(
    *,
    ell: int,
    seed: int,
    step: int,
    channel: int,
    output_fractional_bits: int,
    ideal_applied_control: float,
    secure_grid_integer: int,
    float64_applied_error: float,
) -> ExactGridControlRow:
    """Derive ``M``, ``U`` and ``M-U`` without converting the integer path to float."""
    integer_fields = {
        "ell": ell,
        "seed": seed,
        "step": step,
        "channel": channel,
        "output_fractional_bits": output_fractional_bits,
        "secure_grid_integer": secure_grid_integer,
    }
    if any(type(value) is not int for value in integer_fields.values()):
        raise TypeError("exact-grid 的 ell/seed/step/channel/s/U 必须是 int。")
    if ell <= 0 or step < 0 or channel < 0 or output_fractional_bits < 0:
        raise ValueError("exact-grid 的 ell/step/channel/s 范围无效。")
    if output_fractional_bits > 4096:
        raise ValueError("exact-grid scale 超出资源上限。")
    if not isinstance(ideal_applied_control, float) or not math.isfinite(ideal_applied_control):
        raise ValueError("ideal applied control 必须是有限 binary64。")
    if not isinstance(float64_applied_error, float) or not math.isfinite(float64_applied_error):
        raise ValueError("float64 applied error 必须是有限 binary64。")
    ideal_grid_integer = paper_round_fraction(
        Fraction.from_float(ideal_applied_control) * (1 << output_fractional_bits)
    )
    signed_error_integer = ideal_grid_integer - secure_grid_integer
    classification: ExactGridClassification
    if signed_error_integer == 0:
        classification = "exact_grid_zero"
    elif float64_applied_error == 0.0:
        classification = "float64_collision"
    else:
        classification = "nonzero"
    return ExactGridControlRow(
        ell=ell,
        seed=seed,
        step=step,
        channel=channel,
        output_fractional_bits=output_fractional_bits,
        ideal_grid_integer=ideal_grid_integer,
        secure_grid_integer=secure_grid_integer,
        signed_error_integer=signed_error_integer,
        float64_applied_error=float64_applied_error,
        classification=classification,
    )


def unquantized_binary64_error(
    *,
    ideal_applied_control: float,
    secure_grid_integer: int,
    output_fractional_bits: int,
) -> Fraction:
    """Return ``Fraction.from_float(x)-U/2**s``, distinct from grid error."""
    if not isinstance(ideal_applied_control, float) or not math.isfinite(ideal_applied_control):
        raise ValueError("ideal applied control 必须是有限 binary64。")
    if (
        type(secure_grid_integer) is not int
        or type(output_fractional_bits) is not int
        or not 0 <= output_fractional_bits <= 4096
    ):
        raise ValueError("secure integer 或 scale 无效。")
    return Fraction.from_float(ideal_applied_control) - Fraction(
        secure_grid_integer, 1 << output_fractional_bits
    )
