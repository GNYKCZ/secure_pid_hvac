# Verification and Coverage

## 只读验证原则
可以运行：
- 已有 unit/integration tests；
- 已有主仿真入口；
- 解释器/type checker/linter/static analyzer（若项目已配置）；
- 不落盘的 `python -c` / REPL 诊断；
- git diff/status/log/blame/search。

不要为了审查而把新脚本或新测试写进仓库。

运行可能产生日志/cache/figure 的命令前后检查 `git status --short`。尽量避免修改 tracked files；若工具不可避免地产生 untracked cache，报告它，不把它当项目改动。

没有真正执行并观察结果的命令，不能写“通过”。

## Coverage ledger
最终报告列出本轮实际覆盖：
- entrypoint / simulation loop
- plant
- ideal controller
- fixed-point arithmetic
- secret sharing / Mult / Trunc（若存在）
- experiment sweep / reset / RNG
- metrics / plots / saved data
- tests
- config / dependencies
- paper correspondence

每项标：`Reviewed / Not present / Not accessible / Out of scope`。

## Completeness
- **COMPLETE**：当前声明的 review scope 中所有关键路径已读到足够上下文，关键候选已验证；
- **PARTIAL**：存在关键文件、依赖、论文段落、运行环境或输出不可访问/不可执行。

PARTIAL 时可以报告已确认 Findings，但不能给“整体无问题”或无保留 PASS。

## 验证矩阵
优先选择能直接证伪/证实候选的窄验证，不为了“看起来彻底”跑无关全仓库扫描。

每条必要验收记录：契约来源、独立判断依据（oracle）、输入/工况、命令或证据链接、实际结果、未覆盖限制。状态使用 `PASS / FAIL / NOT RUN / NOT APPLICABLE`；未运行必须说明原因，不适用必须说明与本次改动无关。不得把计划执行的命令写为执行证据。

审查开始与发布前分别核对 base/head SHA、工作区差异和验证环境。日志绑定被测版本；有本地未提交代码或配置参与运行时须明确记录，不能冒充干净 PR head 的验证。head 变化后旧报告仅作为历史证据；base 变化后复核合并差异和相关验证。合并建议不能自动授权合并，执行合并时还需核对获授权的 PR 与当前 head。


## 测试证据复用
按 AGENTS.md Phase E 选择验证范围。独立审查不等于机械重跑测试：核对Work的相关代码/测试/配置及环境和真实日志，无具体疑点直接复用。文档免pytest，局部改动仅补测相关边界；新head仅文档变化不使其他证据失效。
