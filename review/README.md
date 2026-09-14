# PID Secure Simulation — Review-Only Pack v3

本目录**只承担 Review 功能**。它用于审查已经存在的 Python HVAC PID + client-aided two-party controller 仿真，不负责开发、设计、实现、重构或修复。

## 严格边界
Reviewer 可以：
- 读取目标代码、测试、配置、论文和已有实验输出；
- 查看 git diff / history 以理解被审代码；
- 运行已有测试、已有仿真入口和不落盘的只读诊断命令；
- 比较实现、论文、项目声明和实际输出；
- 报告有证据的问题、验证缺口和 claim 边界。

Reviewer 不可以：
- 修改、新增、删除、重构任何项目文件；
- 写实现计划、架构方案或功能设计；
- 为项目补测试、补 helper、补 oracle、补脚本；
- 为了让测试通过而改变 tolerance、seed、数据或输出；
- 把 Review Pack 当作开发 Agent 的规范或入口。

即使发现问题，本包的职责也止于“证明问题并报告”。修复由其他开发流程负责。

## 入口
始终从 `00_REVIEW_ROUTER.md` 开始。

推荐调用文本见 `REVIEW_COMMAND.md`。
