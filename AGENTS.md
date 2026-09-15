# AGENTS.md

本文件是本仓库中 AI 编程代理（包括 Codex、Copilot Agent 等）必须遵守的项目级约束。
目标是保证代码正确、可复现、可审查，并防止 AI 在实现任务时扩大范围、破坏架构或绕过验证。

## 1. 项目目标与当前边界

本项目用于研究和复现基于秘密分享的安全两方动态控制，并以 HVAC + PID 作为第一个实验场景。

长期架构目标：

- `secure_control` 核心必须保持场景无关。
- HVAC 只是第一个 scenario，不是核心领域模型。
- 后续应能够加入 inverted pendulum 等其他 plant，而无需重写安全计算核心。
- 安全控制运行时应面向通用离散状态空间控制器：
  - `x_c(k+1) = A x_c(k) + B v(k)`
  - `u(k) = C x_c(k) + D v(k)`
- PID 只是产生 `A, B, C, D, x0` 的一种控制器设计方法。
- fixed-point、secret sharing、Beaver、Trunc、Client/P1/P2 不得依赖 HVAC 或 PID 特定概念。

除非当前 Issue 明确要求，不得提前实现未来阶段功能。

## 2. 开始任务前必须执行

在修改任何代码前：

1. 阅读当前 Issue / 用户任务，明确 Objective、In Scope、Out of Scope、Acceptance Criteria。
2. 阅读本文件以及当前目录向上适用的其他 `AGENTS.md`。
3. 检查：
   - `git status`
   - 当前 branch
   - 相关源码、测试、配置和文档
4. 先理解现有实现，再修改；不得仅凭文件名猜测行为。
5. 若任务依赖前置 Issue 或必要接口尚不存在，停止扩大实现范围，并报告阻塞原因。
6. 如果发现超出当前 Issue 的问题，记录为 follow-up；不要顺手修复无关代码。


## 2A. 强制工作流（Issue → 实现 → 验证 → PR）

除非用户明确要求其他流程，每个功能任务必须按以下状态机执行，禁止跳步：

### Phase A — Intake / Scope Lock

在写代码前，先确认：

- 当前 Issue 编号和标题
- Objective
- In Scope
- Out of Scope
- Acceptance Criteria
- Dependencies
- 当前分支是否正确
- 工作区是否存在用户尚未提交的修改

必须先形成一个最小实施计划，至少回答：

1. 预计修改哪些文件？
2. 为什么需要修改这些文件？
3. 需要新增/修改哪些测试？
4. 是否涉及公共接口、配置 schema 或依赖？
5. 是否存在超出当前 Issue 的需求？

如果实现过程中发现实际工作明显超出原计划，应暂停继续扩张，重新评估 scope。

### Phase B — Inspect Before Edit

必须先读取：

- 即将修改的源码
- 对应测试
- 直接调用者/被调用者
- 相关配置
- 相关文档
- 与当前模块相邻的架构边界

禁止在没有阅读现有实现的情况下直接“按经验重写”。

不得因为文件内容较短就假设它是占位实现。

### Phase C — Smallest Correct Change

实现时遵循：

- 优先最小正确修改
- 优先复用现有接口
- 优先 composition 而不是增加继承层级
- 不顺手清理与任务无关的代码
- 不顺手统一全仓库风格
- 不顺手升级依赖
- 不顺手重命名公共 API

如果必须修改公共接口，应在最终报告和 PR 中明确列出影响。

### Phase D — Focused Tests First

先运行与当前修改直接相关的测试。

若是 bug fix：

1. 先新增能稳定复现 bug 的测试；
2. 确认测试在旧行为下会失败；
3. 再实现修复；
4. 确认 regression test 通过。

不得先修改测试让现有实现“看起来正确”。

### Phase E — Full Validation

完成实现后至少执行：

```powershell
uv run pytest
uv run ruff check .
```

并根据修改内容增加必要验证。

任何失败都必须处理或明确报告。
不得在验证失败的情况下宣称任务完成。

### Phase F — Self Review

提交前必须查看：

```powershell
git diff
git status
```

逐项检查：

- 是否出现未计划文件
- 是否出现 debug 临时代码
- 是否留下 TODO/XXX/FIXME
- 是否有硬编码实验结果
- 是否有无关格式化
- 是否有配置被偷偷改变
- 是否有测试被弱化
- 是否违反架构依赖
- 是否泄露 secret/token/本地路径

AI 必须把自己的 diff 当成别人的 PR 重新审查一次。

### Phase G — Commit / Push / PR

只有任务明确要求 Git 提交、push 或 PR 时才执行这些动作。

若要求提交：

- commit 必须聚焦当前 Issue；
- 不混入无关修改；
- commit message 应描述实际变化；
- 不修改/重写用户已有 commit，除非明确授权。

若要求 PR：

- PR 必须引用真实 Issue；
- PR body 必须记录实际验证结果；
- 不得自动 merge，除非用户明确要求。

### Phase H — Stop

完成当前 Issue 后停止。

禁止自动继续：

- 下一个 Issue
- 下一阶段 milestone
- “顺便”做 future work
- “顺便”做性能优化
- “顺便”做 Docker / socket / multiprocessing

下一项工作必须由用户或明确任务再次授权。

## 2B. 工作区保护

AI 必须把用户已有修改视为不可丢失数据。

未经明确授权，禁止：

- `git reset --hard`
- `git clean -fd`
- `git checkout -- .`
- `git restore .`
- 强制覆盖本地未提交修改
- 删除不理解用途的文件
- 使用全局 `ours` / `theirs` 策略粗暴解决 merge conflict
- rebase / force-push 用户公共分支
- amend 用户已有 commit

如果工作区不是 clean：

1. 先检查差异；
2. 判断是否与当前 Issue 有关；
3. 保留用户修改；
4. 若会发生冲突，报告并停止危险操作。

## 2C. 文件、目录与临时产物创建边界

AI 不得把“新建文件/文件夹”当作默认解决方案。任何新增路径都属于架构变更的一部分，必须受当前 Issue scope 约束。

### 2C.1 新建文件前的判断

创建新文件前必须能回答：

1. 这个文件属于哪个架构层？
2. 它的单一职责是什么？
3. 为什么不能合理地修改已有文件完成？
4. 谁会 import / 调用 /读取它？
5. 它是否属于当前 Issue 的必要 deliverable？
6. 是否需要长期维护和提交 Git？

如果无法用一句话说明新文件的职责和归属层级，默认不要创建。

优先级：

1. 修改已有、职责匹配的文件；
2. 在已有目录中新增必要模块；
3. 只有现有架构无法清晰承载时，才新增目录；
4. 新增仓库顶层目录属于较大结构变化，必须由当前 Issue、架构文档或用户明确授权。

### 2C.2 禁止“预建未来结构”

不得为了“以后可能会用”提前创建：

- 空目录
- 空模块
- 空 `__init__.py` 树
- placeholder class
- `pass`
- 无调用者的 interface
- 未来场景目录
- 未来 transport/backend 目录
- 大量配置模板

例如，在倒立摆 Issue 尚未开始前，不要提前创建：

`scenarios/inverted_pendulum/`

在 multiprocessing/socket Issue 尚未开始前，不要提前创建相应实现目录。

当前 Issue 不使用的未来结构不应进入当前 PR。

### 2C.3 禁止重复、备份式和逃避设计的文件名

不得创建这类文件来规避修改现有实现：

- `xxx_old.py`
- `xxx_new.py`
- `xxx_v2.py`
- `xxx_final.py`
- `xxx_copy.py`
- `xxx_backup.py`
- `test_temp.py`
- `debug2.py`
- `utils2.py`

如果旧实现需要替换，应在当前 Issue 范围内正常修改，并由 Git 保留历史。

不得在仓库中创建手工备份文件；Git 就是版本历史。

### 2C.4 顶层目录边界

仓库顶层目录应保持稳定、少而清晰。

未经明确必要性，不得新增新的顶层目录。

新增顶层目录前必须检查：

- 是否能放入现有 `src/`、`tests/`、`configs/`、`docs/`、`scripts/`、`results/`
- 是否会制造与已有目录职责重复的概念
- 是否需要同步 `README` / `ARCHITECTURE.md`

禁止为了单个脚本创建新的顶层分类。

### 2C.5 `scripts/` 的边界

`scripts/` 只允许放：

- 用户会重复执行的正式入口
- 可复现实验入口
- 项目维护中有长期价值的工具

一次性检查、调试、数据观察脚本默认不进入 `scripts/`。

如果一段逻辑只用于一次验证，优先：

- 直接使用现有测试；
- 使用 `uv run python -c "..."`；
- 使用系统临时目录；
- 或在本地临时文件中执行并在任务结束前删除。

### 2C.6 `tests/` 的边界

`tests/` 只存放长期维护的正式测试。

临时探索性测试不得直接提交。

如果临时测试发现：

- bug
- 协议边界问题
- 数值边界问题
- 未来必须持续保护的行为

则应将其整理为正式的：

- unit test
- regression test
- parameterized/property-style test

要求：

- 文件名和测试名语义明确
- 具有稳定断言
- 不依赖本地绝对路径
- 不依赖人工观察输出
- 能在干净环境重复执行

如果临时测试没有长期价值，任务完成前删除。

### 2C.7 临时文件统一规则

默认不提交任何临时产物。

包括但不限于：

- scratch code
- debug script
- 临时 JSON/CSV/NPY/NPZ
- 临时图片
- 临时 benchmark 输出
- 本地日志
- profiler 输出
- 手工记录
- 中间转换文件
- 下载缓存
- notebook checkpoint
- 本地备份

如果确实需要 repo-local 临时空间，优先使用已被 `.gitignore` 精确忽略的 `.tmp/`；如果 `.tmp/` 当前不存在，不应仅为了习惯而创建，除非任务实际需要。

任务结束前必须：

1. 删除不再需要的临时文件；或
2. 确认它们处于精确的 ignore 规则下；并
3. 确认它们不会进入 staged changes。

### 2C.8 实验数据与结果文件

可由源码 + 配置 + seed 确定性重新生成的中间实验数据，默认不提交 Git。

默认不提交：

- `results/raw/`
- 普通中间 CSV
- 普通中间 figure
- sweep 中间文件
- benchmark 临时数据

只有以下情况可以提交结果类文件：

- 当前 Issue 明确要求发布/保存该 artifact；
- 它是论文、报告或 README 的正式代表性结果；
- 它是无法轻易重建且确有必要的小型 reference/golden fixture；
- 它是长期回归测试所必需的数据。

提交这类文件时必须说明：

- 为什么需要版本管理；
- 如何生成；
- 对应配置/seed；
- 是否可以重新生成。

大文件和二进制 artifact 默认不提交，也不要擅自启用 Git LFS；如确有需要，应建立独立 Issue 或获得用户明确授权。

### 2C.9 `.gitignore` 规则必须精确

AI 可以在当前任务需要时更新 `.gitignore`，但禁止通过过宽规则“隐藏问题”。

不推荐：

- `*.json`
- `*.csv`
- `*.yaml`
- `tests/*`
- `results/*`

这类可能误伤正式配置、fixture 或发布结果的全局规则。

应优先使用路径级规则，例如：

- `.tmp/`
- `results/raw/`
- `results/figures/`
- `*.log`（若确认日志均不需版本管理）

修改 `.gitignore` 后，应检查是否意外把本应跟踪的文件隐藏。

### 2C.10 文件移动与删除

移动、重命名或删除文件前必须：

1. 确认属于当前 Issue 范围；
2. 搜索 import / 引用 / 文档链接；
3. 判断是否影响公共 API；
4. 更新相应测试和文档；
5. 确认不是用户尚未提交的重要文件。

不得因为“看起来没用”就删除文件。

### 2C.11 Staging 纪律

默认优先按路径精确 staging：

```powershell
git add <明确的文件路径>
```

不要把：

```powershell
git add .
```

当成无检查的默认动作。

如果任务确实使用 `git add .`，执行前后都必须检查：

```powershell
git status --short
git diff --stat
git diff
git diff --cached
```

还应关注未跟踪文件：

```powershell
git ls-files --others --exclude-standard
```

确保没有把：

- 临时测试
- debug 文件
- 原始实验数据
- IDE 文件
- secrets
- 用户无关修改

带入提交。

### 2C.12 新增文件的最小化原则

一个 Issue 的新增文件数应由实际职责决定，而不是为了“看起来工程化”。

如果出现以下信号，应重新检查是否过度拆分：

- 多个只有几行、且只有一个调用者的模块
- 大量 wrapper 只转发一次调用
- 为单一实现创建抽象基类
- 同一概念分散在多个目录
- 为一个 Issue 新建大量目录但几乎没有实际代码

“文件多”不等于架构好；边界清晰、职责稳定、可测试才是目标。

### 2C.13 Existing File Editing Discipline

修改已有文件时，默认必须进行最小范围的原位修改（minimal in-place patch）。

禁止仅为了编辑方便而：

- 删除已有文件后重新创建同名文件；
- 整文件重写一个只需要局部修改的模块；
- 通过 recreate 文件的方式完成普通 refactor；
- 因格式化、换行符或编码变化制造与当前 Issue 无关的大面积 diff；
- 为了“代码更整洁”而重排与当前任务无关的代码、注释或 import。

只有以下情况允许完整替换已有文件：

1. 当前 Issue 明确要求重写该模块；
2. 现有文件结构已经无法合理承载所需修改；
3. 完整替换比局部修改更安全且理由明确；
4. 文件属于自动生成文件，并且生成流程本身属于当前任务。

如果确实需要完整替换已有文件，必须：

- 保持原有编码和换行约定；
- 保留仍然有效的注释和文档；
- 不改变与当前 Issue 无关的行为；
- 在最终报告中说明为什么不能使用局部 patch。

AI 应以“最小可审查 diff”为目标，而不是“最少编辑操作”为目标。

完成修改后必须检查：

```powershell
git diff -- <modified-file>
```

## 3. Python 与环境

本项目统一使用：

- Windows 兼容
- Python 3.11
- `uv`
- 项目本地 `.venv`
- `pyproject.toml`
- `uv.lock`

必须：

- 运行 Python：`uv run python ...`
- 运行测试：`uv run pytest`
- 运行静态检查：`uv run ruff check .`
- 添加运行依赖：`uv add <package>`
- 添加开发依赖：`uv add --dev <package>`

禁止：

- 使用全局项目依赖
- 使用 `pip install` 管理本项目依赖
- 使用 Conda
- 手工编辑 `uv.lock`
- 无明确必要性新增依赖

若新增依赖，必须说明原因，并同时提交 `pyproject.toml` 与 `uv.lock`。

## 4. 架构依赖规则

推荐依赖方向：

`scenarios -> core/execution/simulation -> protocol/crypto`

更准确地说：

- `crypto/` 不得 import `scenarios/`
- `crypto/` 不得出现 HVAC、PID、temperature、pendulum 等领域概念
- `protocol/` 不得依赖 HVAC-specific type 或 PID gain object
- `execution/` 应向上层提供稳定、通用的 controller runtime 接口
- `simulation/` 不得硬编码 HVAC 字段或 PID 误差公式
- `scenarios/hvac/` 负责 HVAC plant、reference、signal mapping、PID 设计和场景特定语义

严禁形成以下依赖：

- `crypto -> hvac`
- `protocol -> hvac`
- `simulation -> PID-specific implementation`

新增场景时，目标是主要新增：

- `scenarios/<scenario_name>/`
- `configs/<scenario_name>_*.yaml`
- 场景测试

而不是修改 secure arithmetic / protocol 核心。

## 5. Signal / Controller Input 边界

不得在通用 simulation engine 中写死：

`error = reference - measurement`

原因：HVAC PID 可以使用误差，但倒立摆、LQR、observer-based controller 可能使用完整状态或其他 controller input。

`reference + plant output -> controller input`

必须由 scenario 层负责。

## 6. 代码注释与文档

### 6.1 中文注释要求

代码必须有充分、清晰的中文注释。

必须使用中文注释的内容包括：

- public class / public function 的 docstring
- 非显然的数学公式与推导
- fixed-point 缩放规则
- 模运算和有符号恢复逻辑
- Secret Sharing / Beaver / Trunc 的协议步骤
- 关键 shape、单位、符号约定
- 重要边界条件
- 容易误解的控制理论逻辑
- 为何采用某种实现而不是仅描述“做了什么”

注释应解释“为什么”和数学含义，而不是机械复述代码。

推荐：

```python
# 将实数按 2^ell 缩放并取整，使其能够在 Z_q 上进行秘密分享。
encoded = round(value * scale)
```

不推荐：

```python
# 计算 scale
scale = 1 << ell
```

不得为了满足“详细注释”而给每一行写无信息量注释。

变量名、函数名、类名保持规范英文；解释性注释和 docstring 使用中文。

### 6.2 文档同步

修改以下内容时同步相关文档：

- 公共接口
- 配置 schema
- 实验运行方式
- 架构边界
- 输出数据格式

不要让 README / docs 描述已经失效的命令或目录。

## 7. 数值计算规则

本项目同时涉及控制、定点数和模运算，数值错误通常不会直接抛异常，因此必须特别谨慎。

必须：

- 明确输入输出 shape
- 明确单位
- 明确采样周期
- 明确控制输入正负号定义
- 明确 `ell`、`q`、`lambda` 等参数含义
- 对 signed modular representation 做显式测试
- 定点编码/解码测试量化误差
- 对边界值、零、正数、负数进行测试
- 避免隐式 dtype 转换
- 涉及大整数和模运算时，确认不会因 NumPy 固定位宽整数发生静默溢出
- 浮点结果使用合理 tolerance，不使用脆弱的直接相等比较

严禁为了“让结果接近论文”而硬编码输出或人为修改误差数据。


## 7A. 控制系统与仿真的高风险规则

### 7A.1 明确时间索引，防止 off-by-one

离散闭环必须明确采用一致顺序，例如：

1. 读取 `y(k)`
2. 构造 controller input `v(k)`
3. 计算 `u(k)`
4. 用 `u(k)` 更新 plant 得到 `x_p(k+1)`
5. 记录与该时间索引对应的数据

不得在 ideal 和 secure 分支使用不同的 update order。

保存 CSV / plotting 时必须保证：

- `u(k)` 与产生它的 measurement/reference 对齐
- `x(k)` / `x(k+1)` 不错位
- reference step 的边界时刻定义一致

### 7A.2 Ideal 与 Secure 必须是两套独立闭环

必须使用：

- 相同 plant 参数
- 相同初始条件
- 相同 reference
- 相同采样周期
- 相同外部 disturbance（若有）

但必须使用：

- 独立 plant instance
- 独立 controller state

禁止共享可变 state。

### 7A.3 不得静默改变控制器语义

未经当前 Issue 明确要求，不得擅自加入或删除：

- actuator saturation
- anti-windup
- derivative filter
- derivative-on-measurement
- deadband
- noise filter
- rate limit
- clipping
- disturbance model

这些都会改变控制结果。

如果需要加入，必须：

- 配置化
- 文档化
- 在 ideal / secure 两分支保持语义一致

### 7A.4 Saturation 的位置必须一致

如果 actuator saturation 属于 plant/actuator，而不是安全协议本身：

- ideal `u` 和 secure `u_hat` 应在相同位置应用 saturation
- 不得在一个 controller 内 clipping、另一个在 plant 外 clipping
- 不得把 plaintext saturation 误称为“securely computed saturation”

### 7A.5 PID 表示不得混用后直接声称等价

如果项目同时存在：

- textbook/discrete PID
- state-space PID

必须通过专门测试验证其输入约定、初始化、滤波、饱和等条件下是否等价。

不得仅因为都叫 PID 就假设：

`Kp, Ki, Kd` 实现 == `(A,B,C,D)` 实现。

### 7A.6 HVAC 特定符号必须配置并固定

HVAC scenario 必须明确：

- `u > 0` 表示 heating 还是 cooling
- 温度单位
- `dt` 单位
- plant 参数单位
- actuator bound

禁止在不同模块中使用相反符号约定。

### 7A.7 不允许为“让控制稳定”偷偷改参数

如果仿真不稳定或 tracking 不达标：

禁止偷偷修改：

- plant 参数
- PID 参数
- initial condition
- actuator limits
- simulation dt
- reference
- fixed-point precision

必须先诊断原因。

任何参数修改都应通过配置和当前 Issue 的明确范围完成。


## 8. 安全协议正确性规则

安全实现不得为了方便绕过协议语义。

特别禁止：

- P1 或 P2 获得完整 plaintext secret
- 在 Server 内部偷偷 Reconst 后再计算
- secure branch 读取 ideal branch 的内部状态
- 为了通过测试而直接调用 plaintext implementation 得到 secure result
- Beaver multiplication 用普通明文乘法替代后仍声称完成安全协议
- Trunc 测试忽略论文允许的误差语义

每个密码学 primitive 必须先独立验证，再组合到完整控制器。


## 8A. 论文语义保真（Paper Fidelity Gate）

本项目不是“看起来类似”的安全控制 demo，而是论文方法的工程化复现。
涉及论文算法时，论文定义优先于编程习惯。

实现 Share / Mult / Trunc / fixed-point / Protocol 3 时必须：

- 在 docstring 或附近注释标明对应的论文 Protocol / Equation / Lemma（适用时）
- 保留论文变量的数学含义，即使代码变量名更工程化
- 若实现为了工程需要与论文公式不同，必须明确记录 deviation，不得静默改变
- 不得为了简化实现而改变安全假设后仍声称“复现论文协议”
- 不得用经验公式替代论文给定公式而不说明

特别注意以下高风险点。

### 8A.1 论文的 rounding 不等于 Python `round`

论文定义的 rounding 为：

`floor(x + 1/2)`

Python 内置 `round()` 使用 banker’s rounding（ties-to-even），语义不同。

因此：

- 不得直接假定 `round(x)` 等价于论文 rounding
- 必须实现并测试论文规定的 rounding semantics
- 必须特别测试 `n + 0.5`、负数和边界值

这是本项目的高风险 correctness point。

### 8A.2 中心化模表示必须一致

论文使用中心化的：

`Z_q = [-q/2, q/2) ∩ Z`

代码内部即使使用 `[0, q)` 做模存储，也必须：

- 明确定义 canonical modular representation
- 明确定义 signed reconstruction
- 编码、运算、重构、decode 之间保持一致
- 对 `q/2` 附近正负边界做测试

禁止不同模块各自实现一套不一致的 signed modulo 规则。

### 8A.3 Beaver triple 不得复用

每次安全乘法必须消费独立 Beaver triple。

禁止：

- 不同乘法复用同一 triple
- 不同时间步复用同一 triple
- 矩阵不同元素共享同一 triple（除非论文明确允许且有证明）

测试可以通过固定 seed 生成可重复的不同 triples，
但“可重复测试”不等于“协议运行时复用 triple”。

### 8A.4 Trunc randomness 不得复用

每次 Trunc 调用需要符合协议要求的新鲜随机辅助量。

不得为了减少代码或提高速度而跨元素、跨时间步复用随机掩码，除非当前 Issue 明确实现论文中具有对应安全论证的优化。

### 8A.5 不得错误假设所有 PID 都不需要 Trunc

论文数值例子中的特定 PID 因其 `A`、`B` 结构可进行简化，
这不代表通用 PID、HVAC PID 或后续控制器都能省略 Trunc。

只有在当前控制器数学形式确实满足相同条件，并有测试/推导支撑时，才允许使用该简化。

### 8A.6 fixed-point scale 必须逐变量明确

不得笼统写成“全部除以 `2^ell`”。

必须明确：

- controller parameter 的 scale
- controller state 的 scale
- measurement/controller input 的 scale
- 乘法后 intermediate 的 scale
- Trunc 后的 scale
- control output reconstruction/decode 的 scale

任何 scale 改变都必须由公式和测试支撑。

## 8B. 安全边界与调试输出

即使当前全部在本机运行，也必须保持协议角色边界。

禁止为了调试在 Server 日志中输出：

- 完整 plaintext controller 参数
- 完整 plaintext controller state
- 完整 plaintext measurement/controller input
- 同一 secret 的两份 share
- 可以直接组合恢复 secret 的调试信息

测试代码如确需重构验证，必须在 test/client 边界显式完成，不能把 Server 生产接口改成可获取 plaintext。

不得在真实 runtime 中保留“debug_reconstruct()”之类后门接口。


## 9. 配置与可复现性

实验参数优先写入配置，不得散落硬编码在源码中。

必须配置化的典型内容：

- simulation duration / dt
- plant parameters
- controller parameters
- fixed-point precision
- modulus / security parameters
- random seed

随机实验必须支持固定 seed，以便测试和 CI 可复现。

实验结果应能够追踪到：

- 使用的配置
- seed
- 代码版本/commit（在合理范围内）
- 关键数值参数

plotting 应优先读取已保存的实验结果，不要为了画图重新执行隐藏的控制计算。


## 9A. 实验数据完整性

实验 runner、metrics、plotting 必须职责分离。

要求：

- runner 负责产生原始结果
- metrics 负责从结果计算指标
- plotting 负责从保存结果画图
- plotting 不得偷偷重新运行 controller
- plotting 不得重新计算一套不同定义的 `u_error`
- CSV/结果文件不得手工后处理以“变好看”

建议原始结果至少保留：

- time
- reference
- ideal output
- secure output
- ideal control
- secure control
- controller/plant metadata 或 config snapshot

误差必须由原始结果可重新计算。

如果图中使用对数轴：

- 必须明确零误差如何处理
- 不得通过人为加大 epsilon 改变结论
- 用于显示的数值处理不得覆盖原始误差数据

性能数据（runtime、通信量、内存等）只有实际测量后才能报告。
不得把理论复杂度写成实测性能。


## 10. 测试纪律

每个功能 Issue 必须同时提交相应测试，除非 Issue 明确只涉及文档。

测试应验证行为和数学 invariant，而不是仅覆盖代码行。

典型 invariant：

- `Reconst(Share(m)) == m mod q`
- secure multiplication reconstruction 等于 plaintext modular product
- fixed-point decode/encode 误差在设计范围内
- ideal 与 secure 双闭环使用独立 plant state
- actuator limits 被遵守
- 仿真中不存在 NaN / inf

禁止：

- 删除或弱化已有测试来让新代码通过
- 将失败断言改成宽松到失去意义
- 使用无断言的“测试”
- 只测试 happy path
- 捕获异常后不验证异常类型/含义

修复 bug 时优先先增加能复现 bug 的 regression test。


## 10A. 项目关键测试矩阵

涉及相关模块时，至少考虑以下测试集合；不要求无关 Issue 提前全部实现。

### Fixed-point

- 0
- 正数 / 负数
- `.5` rounding tie
- 可表示范围边界
- encode → decode
- scale consistency
- 溢出/越界拒绝

### Secret Sharing

- 多个随机 secret
- 负数的中心化表示
- 0
- q 边界附近
- 单 share 不应通过 API 直接得到 secret
- Reconst invariant

### Beaver Mult

- 0
- 正 × 正
- 正 × 负
- 负 × 负
- q 边界
- randomized trials
- triple consumption / no reuse（若实现资源对象）

### Trunc

- 正数
- 负数
- 边界值
- 允许的 `w ∈ {-1,0,1}` 语义
- 参数前提检查
- 多次随机运行

### Closed Loop

- time-index alignment
- ideal/secure plant state independence
- deterministic seeded run
- no NaN / inf
- actuator bound
- reference boundary times
- result shape / length 一致

测试名应描述实际行为，不要使用 `test_basic`、`test_stuff` 等无语义名称。


## 11. 错误处理

不得：

- 使用裸 `except:`
- 静默吞掉异常
- 在关键数值错误时自动使用“看起来能跑”的 fallback
- 对不满足 shape/range/config 的输入继续计算

对于程序员错误和不满足协议前提的情况，应尽早失败并给出明确错误信息。

## 12. 防止 AI 常见过度实现

始终选择满足当前需求的最简单实现。

未经当前 Issue 授权，不要：

- drive-by refactor
- 大范围 rename
- 提取并不存在第二个真实用例的抽象
- 创建 Factory / Registry / PluginManager / BackendManager
- 创建复杂 inheritance hierarchy
- 提前实现 multiprocessing / socket / Docker
- 为“未来可能需要”增加依赖
- 重写工作正常的模块只为了统一个人风格

如果一个小改动可以解决问题，不要重构整个模块。


## 12A. Correctness First，禁止过早优化

在协议正确性和数值一致性通过之前，不得优先做：

- vectorization 复杂化
- multiprocessing
- async
- socket batching
- cache
- PRF/PCF 优化
- memory pooling
- 自定义 serialization
- “减少通信量”的协议改写

优化前必须先有：

1. 正确性 baseline；
2. 可重复 benchmark；
3. 明确瓶颈；
4. 独立 Issue。

不得以“更快”为理由改变数学语义。

## 12B. TODO / 临时代码规则

禁止提交无归属的：

- TODO
- FIXME
- XXX
- `pass`
- `NotImplementedError`
- debug print
- 临时常量
- 注释掉的大段旧代码
- 临时测试文件
- 一次性调试脚本
- 手工备份文件

如果当前 Issue 有意保留未实现接口，必须：

- 明确说明原因
- 有对应 follow-up Issue
- 不得让未实现路径在正常运行中被误用

临时测试若揭示长期需要保护的行为，必须按第 2C.6 节整理为正式测试；否则在任务结束前删除。


## 13. 不得猜测

AI 容易根据名称补全不存在的事实。

因此：

- 不确定接口时先读代码
- 不确定库行为时查本地版本文档/实际运行验证
- 不确定 Issue 意图时说明假设或请求澄清
- 不得声称未实际执行的命令“已通过”
- 不得声称未实际检查的 GitHub 状态“已完成”
- 不得编造 benchmark、性能结果或协议正确性

最终报告必须区分：
- 实际验证的事实
- 推断
- 未验证事项

## 14. Git 与 GitHub 工作流

除非当前任务另有明确说明：

- 一个 Issue 对应一个可独立 review 的工程目标
- 推荐 branch：`issue/<number>-<short-slug>`
- 不直接在 `main` 上开发功能
- 不把多个无关 Issue 混入一个 PR
- 不自动 merge PR，除非用户明确要求
- 不自动关闭未满足 Acceptance Criteria 的 Issue
- 不修改已完成 Issue 的历史语义来适配当前实现

提交前必须检查：

- `git diff`
- `git status`
- 是否包含无关文件
- 是否意外包含生成数据、IDE 文件、`.venv`、secret

禁止：

- 对 `main` 使用 `git push --force`
- 未经明确授权重写公共历史
- 使用 `git reset --hard`、大范围删除等破坏性命令清理问题
- 提交 API key、token、密码、私钥或 `.env`

推荐 commit message：

- `feat: ...`
- `fix: ...`
- `test: ...`
- `refactor: ...`
- `docs: ...`
- `chore: ...`

必要时关联 Issue，例如：

`feat: implement HVAC plant (#3)`


## 14A. Issue / PR 边界不得被实现反向篡改

实现发现 Acceptance Criteria 难以满足时：

禁止：

- 修改 Issue 文字来迁就当前实现
- 删除困难的 Acceptance Criteria
- 把原本必须实现的内容改成 future work
- 先关闭 Issue 再补实现

正确做法：

1. 说明阻塞；
2. 判断是 implementation defect、Issue 设计错误还是新增 dependency；
3. 若确需修改 Issue，必须作为显式 planning decision 处理，并保留变更理由；
4. 实现 Agent 不得自行把“未完成”改写成“已完成”。

### PR review feedback

收到 review comment 后：

- 逐条理解，不机械照改
- 如果 review 建议会破坏论文语义或架构边界，应说明原因而不是盲从
- 修复后重新执行相关测试和完整验证
- 不得只 resolve thread 而不真正修改/解释

### GitHub 状态真实性

不得声称：

- PR 已创建
- Issue 已关闭
- CI 已通过
- branch 已 push
- review 已解决

除非实际通过 Git/GitHub 工具确认。

## 14B. Review Finding 修复工作流

当独立 Review Agent 将 Finding 写入当前 Issue、PR 或其他持久化评论区后，后续实现 Agent 必须把这些 Finding 视为“需要重新验证的缺陷报告”，而不是无需验证的修改指令。

### 14B.1 修复前必须重新验证 Finding

处理每个 Finding 前必须：

1. 阅读 Finding 的 Trigger、Evidence、Impact、Suggested direction、Constraints 和 Acceptance check；
2. 检查当前 branch / HEAD 是否仍然包含该问题；
3. 阅读 Finding 涉及的实际实现、调用方、测试和相关配置；
4. 确认 Finding 的触发路径真实存在；
5. 确认问题仍属于当前 Issue 范围。

禁止因为 Review Agent 给出了修改建议就直接机械修改代码。

如果重新验证后发现 Finding 不成立、已经被其他修改解决，或建立在错误假设上，应记录证据并将其标记为：

* Rejected；
* Already resolved；
* Superseded；

而不是为了迎合 Review 结果强行修改代码。

### 14B.2 Suggested direction 不是强制实现方案

Review Finding 中的 Suggested direction 用于说明推荐的修复方向和架构约束，但默认不是精确 patch specification。

修复 Agent仍必须：

* 优先寻找现有 canonical implementation；
* 保持现有 ownership 和架构边界；
* 选择满足 Finding Acceptance check 的最小正确修改；
* 不因为 Review 建议创建额外 abstraction、文件或依赖；
* 不扩大原 Issue scope。

如果 Review 建议本身与项目架构、论文语义、本文件规则或当前代码证据冲突，应说明原因，不得盲从。

### 14B.3 Finding 状态

每个 Finding 最终只能进入以下状态之一：

* `Fixed`：问题已修复，并有验证证据；
* `Rejected`：重新验证证明 Finding 不成立；
* `Already resolved`：当前代码已经不存在该问题；
* `Superseded`：后续设计或修改使原 Finding 不再适用；
* `Follow-up required`：问题真实，但修复超出当前 Issue 范围，需要独立 Issue / planning decision；
* `Blocked`：问题真实，但受外部依赖或前置条件阻塞。

不得仅因为修改了相关代码就标记为 `Fixed`。

### 14B.4 修复后的验证

每个 Fixed Finding 至少需要：

1. 执行与该 Finding 直接相关的 targeted validation；
2. 若属于 bug fix，优先增加或保留能够防止该问题再次出现的 regression test；
3. 执行本文件要求的完整验证；
4. 检查修复没有产生新的无关 diff；
5. 保留 Finding ID 与验证结果的对应关系。

例如：

`RV-002 — Fixed — uv run pytest tests/test_x.py::test_y passed`

### 14B.5 Issue / PR 评论回复

修复完成后，应在 Finding 所在 Issue / PR 评论中记录：

* Finding ID；
* 最终状态；
* 实际修复内容的简要说明；
* 实际运行的验证命令及结果；
* 对应 commit（若已创建）；
* 尚未解决的限制或 follow-up（若存在）。

不得只回复：

`fixed`

或仅 resolve review thread 而不提供可验证结果。

### 14B.6 Re-review

修复完成并通过验证后，应由独立 Review 会话重新检查相关改动。

Re-review 应重点确认：

* 原 Finding 是否真正消失；
* 修复是否引入新的回归；
* 是否出现新的重复实现、架构旁路或范围扩张；
* 测试是否真实验证修复而没有被弱化。

Re-review 通过后，Finding 才可视为完成闭环。

## 15. PR 要求

PR 应保持小而聚焦。

PR body 至少包含：

- Summary
- Scope
- Validation
- Results / Metrics（适用时）
- Known limitations
- `Closes #<issue>`（仅在确实满足该 Issue 时）

不得把“测试通过”作为文字声明而没有实际执行证据。

如果当前任务只要求创建 PR，不要自行 merge。

## 16. 修改后的强制验证

代码修改完成后，至少执行：

```powershell
uv run pytest
uv run ruff check .
```

涉及 Python/runtime 环境时额外执行：

```powershell
uv run python --version
```

涉及具体模块时，运行最小相关测试之外，还要运行完整测试套件，除非测试成本已经高到不合理并在报告中说明。

任何验证失败：

- 不得隐藏
- 不得声称任务完成
- 应修复，或明确报告阻塞

## 17. 任务完成前自检

提交/PR 前逐项确认：

- [ ] 只完成了当前 Issue 的范围
- [ ] 没有修改无关文件
- [ ] 没有破坏架构依赖方向
- [ ] 没有把 HVAC/PID 概念泄漏到通用安全核心
- [ ] 新增代码有必要的中文解释性注释和中文 docstring
- [ ] 测试覆盖主要正常路径和关键边界
- [ ] `uv run pytest` 通过
- [ ] `uv run ruff check .` 通过
- [ ] 没有提交 `.venv`、实验临时文件或 secrets
- [ ] README/docs 在需要时已同步
- [ ] `git diff` 已人工式自审
- [ ] 最终报告只陈述实际验证过的结果
- [ ] 没有直接使用 Python `round()` 冒充论文 rounding
- [ ] signed modulo / fixed-point scale 在修改涉及处保持一致
- [ ] Beaver triple / Trunc randomness 没有被不当复用
- [ ] ideal 与 secure 时间索引和 actuator 语义一致
- [ ] 没有为了让实验稳定/好看而静默修改配置参数
- [ ] 没有遗留 debug reconstruct、debug print 或协议后门
- [ ] 没有无必要新增顶层目录、空目录或未来占位模块
- [ ] 新增文件均能说明职责、归属层和当前 Issue 必要性
- [ ] 没有提交 `*_old`、`*_new`、`*_v2`、backup/copy/final 等备份式文件
- [ ] 临时测试已转为正式回归测试或已删除
- [ ] 中间 CSV/图片/日志/benchmark 等临时产物未进入 staged changes
- [ ] `.gitignore` 没有使用会误伤正式源码、配置或测试数据的过宽规则
- [ ] staging 前后已检查未跟踪文件和 cached diff
- [ ] 已有文件均采用必要的最小修改；没有通过删除并重建同名文件制造无关大面积 diff

## 18. 最终报告格式

完成任务后简洁报告：

### Changes
说明实际修改了什么。

### Validation
列出实际运行的命令及结果。

### Architecture impact
说明是否改变公共接口、依赖方向或配置。

### Git/GitHub
说明 branch、commit、PR/Issue 状态（仅陈述实际确认的事实）。

### Remaining issues
列出已知限制、未验证项或 follow-up；没有则写“无已知阻塞”。

不要用大量过程叙述代替可验证结果。


## 19. 指令冲突与优先级

当要求发生冲突时，按以下原则处理：

1. 用户当前明确指令
2. 当前 Issue 的明确 Acceptance Criteria / Scope
3. 适用于当前目录的更具体 `AGENTS.md`
4. 本根目录 `AGENTS.md`
5. README / docs 中的一般性建议

但任何低层级说明都不能自动授权：

- 破坏数据
- 泄露 secrets
- 绕过测试
- 伪造验证结果
- 违反论文核心协议语义

若冲突会改变算法正确性、安全边界或公共接口，应停止并报告，而不是自行猜测。

## 20. 本项目 AI 最常见失败模式清单

每次实现结束前，主动检查自己是否犯了以下错误：

1. 把 HVAC 当成 core，而不是 scenario。
2. 把 PID gains 直接塞进 secure protocol。
3. 在 simulation engine 中写死 `reference - temperature`。
4. ideal / secure 两个闭环共享同一个 plant 或 controller state。
5. secure server 为方便直接看到 plaintext。
6. Beaver triple 被复用。
7. Trunc randomness 被复用。
8. Python `round()` 被误当成论文 rounding。
9. `[0,q)` 与中心化 `Z_q` 的 signed interpretation 混乱。
10. fixed-point scale 在乘法 / Trunc / decode 后少乘或多除一个 `2^ell`。
11. NumPy `int64` 在大模数下静默溢出。
12. PID 的普通实现和 state-space 实现未验证等价。
13. ideal 与 secure 分支 saturation / anti-windup 位置不一致。
14. reference step 的时间边界 off-by-one。
15. 为让图“像论文”而改参数、改数据或放宽 tolerance。
16. plotting 重新运行了一套隐藏仿真。
17. 为未来倒立摆提前造复杂 Factory/Registry。
18. 当前 Issue 之外顺手实现下一阶段。
19. 为让测试通过而修改测试目标。
20. 声称已测试/已 push/已创建 PR，但实际没有验证。
21. 为单个任务随意新增顶层目录或大量空模块。
22. 用 `*_new` / `*_v2` / backup 文件逃避正常修改。
23. 把临时测试、debug 脚本、中间 CSV/图片通过 `git add .` 带进 PR。
24. 为隐藏生成文件添加过宽 `.gitignore`，导致正式 fixture/config 也被忽略。
25. 把可重复生成的大量实验 artifact 当作源码长期提交。
26. 为了编辑方便删除并重新创建已有文件，导致局部需求变成整文件 rewrite 或出现无关 diff。

发现任一项，应在提交前修复或明确报告为阻塞。
