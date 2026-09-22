# Review Report Format v4

## Review scope & completeness
- Mode: Target / Diff
- Target: Issue / PR / branch / commit；Diff Mode 记录被审 head SHA 和比较基线
- Completeness: COMPLETE / PARTIAL
- Reviewed: 按 `core/VERIFICATION_AND_COVERAGE.md` 给 coverage ledger
- Not verified: 关键不可访问/不可执行项

## Findings
按 P0 -> P3，只列 confidence >= 0.80 且通过 adversarial verification 的问题。

每个 Finding 使用稳定 ID；若发到 Issue / PR，遵循 `review-output-issue_handoff.md`：
### RV-001 — [P?] 标题
- Location: `path:line`
- Confidence: `0.00-1.00`
- Trigger: 具体输入/时间/状态/参数/路径
- Evidence: 代码、测试、论文或本轮真实运行证据
- Impact: 对 u/y/protocol/metric/claim 的具体影响
- Violated invariant: 当前实现违反了什么已声明/已验证的约束
- Verification: Reviewer 如何排除了最可能的反例
- Suggested direction: 根据现有架构说明修复方向和责任层，不把方案当成唯一正确 patch
- Constraints / Non-goals: 修复时必须保留的接口、invariant、范围和测试强度
- Acceptance check: 可观察的完成条件
- Suggested validation: 能验证修复的最小相关测试或运行检查

不要给 patch、实现代码、未经验证的新架构或逐步开发计划。

若 COMPLETE 且没有合格 Finding：`未发现符合门槛的问题。`
若 PARTIAL：不得用无保留的“未发现问题”代替未覆盖内容。

## Paper correspondence
对实际存在/声称存在的项列 `Exact / Equivalent / Adapted / Simplified / Missing` + 证据：
- controller equation
- encoded state update
- Mult
- Trunc
- Protocol 3 dataflow
- Sec. VII special PID（若相关）

## AI-coding failure-mode audit
对 `checks/AI_CODING_FAILURES.md` 的类别简要给：`Checked / Issue found / Not applicable / Not verifiable`。

## Numerical / control / protocol audit
简要给：
- time & units
- update ordering
- independent state
- dtype / shape / rounding
- scale ledger
- signed mod-q
- Mult / Trunc
- q range / wraparound

## Experiment / tests / provenance audit
简要给：
- reset/isolation
- RNG/randomness reuse
- metric alignment
- figure/data provenance
- behavioral test quality
- claim consistency

## Validation executed
只列本轮真正执行并观察到结果的命令/测试，以及结果。

## Residual risks / unverified gaps
只列证据不足但会限制结论的事项，不把猜测伪装成 Finding。

## Overall assessment
只能选：
- `PASS`：COMPLETE 且没有 P0-P2；
- `PASS WITH LIMITATIONS`：没有 P0-P2，但存在 P3、已说明的限制或未验证项；若 PARTIAL，必须明确仍需哪些验证，不视为可合并结论；
- `FAIL`：存在 P0-P2，或发现足以让主要实验结论不可信的问题。

## Merge recommendation
- `APPROVE`：当前 PR head 的审查 COMPLETE，没有 P0-P2，且 Issue 验收和必要验证已有证据；
- `REQUEST CHANGES`：存在应在当前 PR 修复的确认问题或未满足的 Issue 验收项；
- `INCONCLUSIVE`：关键路径或验证无法覆盖，现有证据不足以判断可否合并。列出缺少的证据。

Merge recommendation 只针对报告记录的 head SHA；PR 出现新提交后需 re-review。

最后明确：当前证据最多支持到哪种 claim（例如 float simulation / fixed-point numerical comparison / local two-party protocol emulation），不要自动升级到真实部署安全性。
