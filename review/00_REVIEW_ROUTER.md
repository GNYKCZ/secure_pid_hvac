# Review Router v3 — Pure Review Only

## 0. 先确认任务边界
本目录只做 Review。若请求同时包含“审查并修复/实现”，本流程只完成审查部分；不要在 Review 流程中编辑代码。

始终加载：
- `core/BOUNDARY.md`
- `core/EVIDENCE_AND_FINDINGS.md`
- `core/VERIFICATION_AND_COVERAGE.md`
- `reference/REVIEW_TARGET.md`
- `reference/PAPER_MAPPING.md`
- `output/REPORT_FORMAT.md`

随后根据目标加载相关 checks。对本项目做完整 Target Review 时，五个 checks 全部加载。

## 1. Review 模式
- **Target Mode**：用户要求审查当前 `.py`、当前仿真或完整小项目。报告任何会影响当前实验正确性/可信度的问题，不要求证明是最近 diff 新引入。
- **Diff Mode**：用户明确指定 diff/commit/branch/PR。聚焦本次改动引入、暴露或明显恶化的问题；必要时读取相关未修改代码来验证影响。

## 2. Context ladder
不要一上来扫完整仓库。按证据需要逐层扩大：
1. 被审 diff / 目标文件；
2. 直接 caller / callee / 数据消费者；
3. 对应配置、测试、运行入口；
4. 与候选问题直接相关的其他文件；
5. 只有语义仍不明确时才查 git history/blame。

完整 Target Review 至少覆盖：主仿真入口、plant/controller、fixed-point/protocol arithmetic、实验循环、metric/plot、相关 tests/config。

## 3. 两阶段审查
### Pass A — Candidate discovery
使用五个专项 checks 找候选问题：
- `checks/AI_CODING_FAILURES.md`
- `checks/PYTHON_NUMERICS.md`
- `checks/CONTROL_SIMULATION.md`
- `checks/SECURE_PROTOCOL.md`
- `checks/EXPERIMENT_AND_TESTS.md`

### Pass B — Adversarial verification
对每个候选 Finding，主动尝试**证伪**：
- 是否在别处初始化/校正？
- 是否由 caller 保证前置条件？
- 是否是有意适配而非 Bug？
- 是否只在不可达路径？
- 是否已有测试/运行证据反驳？

只有证伪失败且证据达到门槛，才进入最终 Findings。

## 4. 优先审查顺序
1. 同一数学对象/控制器是否公平可比；
2. 时间、单位、状态更新顺序和独立闭环；
3. fixed-point / modulo / Mult / Trunc / decode；
4. Python dtype、shape、状态、异常与 API 事实；
5. sweep/reset/RNG/data provenance/plots/metrics；
6. tests 是否真的验证行为；
7. claim 是否超过代码和证据。

风格、命名、格式化、纯审美重构不属于本包默认 Findings。

## 5. “无问题”门槛
只有在 `core/VERIFICATION_AND_COVERAGE.md` 定义的 scope coverage 为 COMPLETE 时，才能给出“未发现符合门槛的问题”。
若关键文件/论文/运行路径不可访问，必须标记 PARTIAL，不能给整体 PASS。
