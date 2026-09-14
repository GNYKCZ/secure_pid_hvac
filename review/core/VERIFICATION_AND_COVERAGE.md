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
