# 项目协作约束

## 代码注释语言与质量

- 所有新增或修改的生产代码必须使用**中文**撰写注释和 docstring。
- 对外可见的模块、类、函数、方法和 dataclass 必须有中文 docstring，说明职责、输入输出、状态或副作用。
- 对非显然的数值计算、状态更新、数组 shape、单位、定点 scale、模运算、随机性和错误处理，必须添加详细中文注释，解释设计原因、数学语义与必须保持的不变量。
- 不要逐行翻译显而易见的 Python 语法；注释应帮助审阅者理解“为什么这样做”、边界条件和失败方式。
- 若代码实现论文中的公式、协议步骤或离散时间时序，注释必须说明公式来源、输入输出尺度、更新先后顺序及安全/数值假设。
- 测试中的非显然 expected value、边界用例和回归目标同样使用中文注释或 docstring 说明。
- 代码注释不得声称未验证的安全性、数值精度或论文复现结论。

## 架构边界

- `core`、`crypto`、`protocol`、`execution`、`simulation` 必须保持场景无关；不得引入 HVAC、PID、temperature、pendulum、cart 或具体调参字段。
- 场景特有 plant、reference、controller design、单位和 reference/output 到 controller input 的映射只能放在 `scenarios/<scenario_name>/`。
- 新功能开始前必须读取其 GitHub Issue、已关闭依赖 Issue 的交付物，以及本文件。
- 每次变更后至少运行该 Issue 要求的测试、`uv run ruff check .` 和相应的 Python 导入验证。
