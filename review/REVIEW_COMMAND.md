# Review 调用文本

## 完整目标审查（Target Mode）

进入纯 Review Mode。

读取 `review/00_REVIEW_ROUTER.md`（若本目录本身就是 `review/`，读取 `00_REVIEW_ROUTER.md`），对当前 HVAC PID + two-party simulation 执行 Target Mode review。

这是只读审查任务：
- 不修改、新增、删除或重构文件；
- 不编写修复代码或实现计划；
- 可以读取源码/测试/论文/已有输出；
- 可以运行已有测试、已有仿真以及不落盘的诊断命令；
- 最后严格按 `output/REPORT_FORMAT.md` 报告。

重点判断“当前实验结论是否可信”，而不是代码风格是否漂亮。

## Git diff 审查（Diff Mode）

进入纯 Review Mode。

按照 `review/00_REVIEW_ROUTER.md` 对当前 git diff 执行 Diff Mode review。只报告本次改动引入、暴露或明显恶化的问题；不要修改文件。

最后严格按 `output/REPORT_FORMAT.md` 报告。
