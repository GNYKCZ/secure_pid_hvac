# Review Report Format v3

## Review scope & completeness
- Mode: Target / Diff
- Completeness: COMPLETE / PARTIAL
- Reviewed: 按 `core/VERIFICATION_AND_COVERAGE.md` 给 coverage ledger
- Not verified: 关键不可访问/不可执行项

## Findings
按 P0 -> P3，只列 confidence >= 0.80 且通过 adversarial verification 的问题。

每个 Finding：
### [P?] 标题
- Location: `path:line`
- Confidence: `0.00-1.00`
- Trigger: 具体输入/时间/状态/参数/路径
- Evidence: 代码、测试、论文或本轮真实运行证据
- Impact: 对 u/y/protocol/metric/claim 的具体影响
- Violated invariant: 当前实现违反了什么已声明/已验证的约束
- Verification: Reviewer 如何排除了最可能的反例

不要给 patch、实现代码、重构方案或开发计划。

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
- `PASS WITH LIMITATIONS`：没有阻断性 Finding，但存在已说明的限制/未验证项；
- `FAIL`：存在足以让主要实验结论不可信的 Finding。

最后明确：当前证据最多支持到哪种 claim（例如 float simulation / fixed-point numerical comparison / local two-party protocol emulation），不要自动升级到真实部署安全性。
