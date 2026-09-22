# Review 调用文本

## 完整目标审查（Target Mode）

进入纯 Review Mode。

读取 `review/00_REVIEW_ROUTER.md`（若本目录本身就是 `review/`，读取 `00_REVIEW_ROUTER.md`），对指定目标执行 Target Mode review。先写明目标和适用的 Issue / 配置 / 声明。

这是只读审查任务：
- 不修改、新增、删除或重构文件；
- 不编写修复代码或逐步实施计划；确认的 Finding 按报告格式提供修复方向和验收检查；
- 可以读取源码/测试/论文/已有输出；
- 可以运行已有测试、已有仿真以及不落盘的诊断命令；
- 最后严格按 `output/REPORT_FORMAT.md` 报告。

重点判断“当前实验结论是否可信”，而不是代码风格是否漂亮。

## Git diff 审查（Diff Mode）

进入纯 Review Mode。

按照 `review/00_REVIEW_ROUTER.md` 对指定 PR / commit / branch 的 diff 执行 Diff Mode review。记录 base 和 head SHA；只报告本次改动引入、暴露或明显恶化的问题；不要修改文件。每个确认的 Finding 给出有证据支持的修复方向、约束和验收检查。

最后严格按 `output/REPORT_FORMAT.md` 报告。
