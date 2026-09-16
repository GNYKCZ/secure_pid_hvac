"""从完整已发布 run 选择通道并调用通用绘图，不装配或运行场景。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .artifacts import ExperimentRecord, load_artifacts
from .plotting import PlotDisplay, PlotSelection, render_saved_run


def _tracking_pair(value: str) -> tuple[int, int]:
    """CLI 的 output:reference 明确指定配对，禁止向量时自动猜测同号通道。"""
    parts = value.split(":")
    if len(parts) != 2 or any(not part.isdecimal() for part in parts):
        raise argparse.ArgumentTypeError("--tracking 必须是 output:reference 非负整数配对。")
    return int(parts[0]), int(parts[1])


def _channel_index(value: str) -> int:
    """CLI 只解析索引格式；实际越界由已发布 metadata 校验。"""
    if not value.isdecimal():
        raise argparse.ArgumentTypeError("--control-channel 必须是非负整数。")
    return int(value)


def _selection(
    record: ExperimentRecord, args: argparse.Namespace
) -> tuple[PlotSelection, PlotDisplay]:
    """只有已保存的单通道 HVAC 可省略选择；其余场景必须显式给出配对。"""
    is_single_hvac = (
        record.metadata.name == "hvac"
        and len(record.metadata.reference.names) == 1
        and len(record.metadata.output.names) == 1
        and len(record.metadata.control.names) == 1
    )
    tracking = args.tracking or ([(0, 0)] if is_single_hvac else None)
    controls = args.control_channel or ([0] if is_single_hvac else None)
    if tracking is None or controls is None:
        raise ValueError("非单通道 HVAC 必须显式指定 --tracking 与 --control-channel。")
    time_unit = args.time_unit or ("h" if is_single_hvac else "s")
    selection = PlotSelection(
        tuple(tracking),
        tuple(controls),
        args.control_error_scale,
        time_unit,
        args.format,
    )
    display = PlotDisplay(
        time_unit, "HVAC" if record.metadata.name == "hvac" else record.metadata.name
    )
    return selection, display


def main() -> None:
    """使用 `--run-dir` 调用 #13 reader，输出 source/render 与正式图路径摘要。"""
    parser = argparse.ArgumentParser(description="Render saved scenario comparison figures")
    parser.add_argument("--run-dir", required=True, help="published schema v1 run directory")
    parser.add_argument(
        "--tracking",
        action="append",
        type=_tracking_pair,
        help="output:reference channel pair; repeatable",
    )
    parser.add_argument(
        "--control-channel",
        action="append",
        type=_channel_index,
        help="applied control channel index; repeatable",
    )
    parser.add_argument("--control-error-scale", choices=("linear", "log"), default="linear")
    parser.add_argument("--time-unit", choices=("s", "h"), default=None)
    parser.add_argument("--format", choices=("png", "pdf"), default="png")
    parser.add_argument("--output-root", default="results/figures")
    args = parser.parse_args()
    record = load_artifacts(Path(args.run_dir))
    selection, display = _selection(record, args)
    published = render_saved_run(
        args.run_dir, selection, output_root=args.output_root, display=display
    )
    print(
        json.dumps(
            {
                "source_run_id": published.source_run_id,
                "render_id": published.render_id,
                "figures": [str(path) for path in published.figure_paths],
                "manifest": str(published.manifest_path),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
