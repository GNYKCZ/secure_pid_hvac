"""从已验证 sweep 与诊断 evidence 生成 Issue #51 中文增强报告。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evidence_reporting import render_verified_evidence_report


def main() -> None:
    """解析显式来源目录并输出原子发布的报告身份与入口文件。"""
    parser = argparse.ArgumentParser(description="Render the verified secure evidence report")
    parser.add_argument("--source-sweep-id", required=True)
    parser.add_argument("--trace-id", required=True)
    parser.add_argument("--sweep-root", default="results/sweeps")
    parser.add_argument("--diagnostics-root", default="results/diagnostics")
    parser.add_argument("--output-root", default="results/figures/evidence_reports")
    parser.add_argument(
        "--display-config",
        default="configs/hvac_2r2c_evidence_report_zh.yaml",
    )
    args = parser.parse_args()
    artifacts = render_verified_evidence_report(
        sweep_dir=Path(args.sweep_root) / args.source_sweep_id,
        evidence_dir=Path(args.diagnostics_root) / args.source_sweep_id / args.trace_id,
        profile_path=Path(args.display_config),
        output_root=Path(args.output_root),
    )
    print(
        json.dumps(
            {
                "report_id": artifacts.report_id,
                "directory": str(artifacts.output_dir),
                "manifest": str(artifacts.manifest_path),
                "main_catalog": str(artifacts.main_catalog_path),
                "appendix_catalog": str(artifacts.appendix_catalog_path),
                "table_csv": str(artifacts.table_csv_path),
                "table_markdown": str(artifacts.table_markdown_path),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
