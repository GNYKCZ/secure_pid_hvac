"""只读取正式 sweep 工件并生成中文报告，不运行实验或场景。"""

from __future__ import annotations

import argparse
import json

from .reporting import render_chinese_report


def main() -> None:
    """解析 artifact-only CLI 并输出报告身份和路径。"""
    parser = argparse.ArgumentParser(description="Render a verified sweep as a localized report")
    parser.add_argument("--sweep-dir", required=True)
    parser.add_argument("--display-config", required=True)
    parser.add_argument("--output-root", default="results/figures/reports")
    args = parser.parse_args()
    report = render_chinese_report(args.sweep_dir, args.display_config, args.output_root)
    print(
        json.dumps(
            {
                "report_id": report.report_id,
                "output_dir": str(report.output_dir),
                "figures": [str(path) for path in report.figure_paths],
                "manifest": str(report.manifest_path),
                "catalog": str(report.catalog_path),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
