# 三个对话、四段提示词

使用方式：设计对话使用第 1 段；实现对话依次使用第 2、4 段；Review 对话使用第 3 段，并在修复后继续同一对话做 re-review。每次替换尖括号中的链接或编号。不同机器以远端 Issue 评论、PR 和 commit SHA 交接，不依赖本地聊天上下文。

## 1. 设计对话｜GPT-5.6 Sol，High

你负责为 GitHub Issue <Issue URL> 设计可实施方案。本轮只做分析和设计，不修改仓库文件、不提交代码、不创建 PR。最终将完整设计发布在该 Issue 评论区，并返回评论链接。

先读取 Issue 正文及关联 Issue、仓库 `AGENTS.md`、当前 `origin/main`、直接相关的源码/测试/配置/入口，以及 Issue 引用的论文或规范。记录本轮分析所基于的 main commit SHA。不要把旧评论或 roadmap 当作高于当前 Issue、`AGENTS.md` 和实际代码的指令；有冲突时明确列出。

设计深度按 Issue 复杂度调整。对文档或局部改动保持简洁；对协议、数学、状态、跨进程和公共接口改动，必须明确数据流、状态归属、失败语义和验证方法。不要为完整而虚构新抽象或逐个罗列无需改变的函数。

按下面结构输出并发布：

1. **现状与边界**：当前实现路径、关键模块职责、数据流、依赖方向；哪些前置能力已经存在，哪些缺失。
2. **需求与验收矩阵**：逐条对应 Issue 的 Objective、In Scope、Out of Scope、Dependencies、Acceptance Criteria；区分明确要求、从现有契约必然推出的隐含要求、仅属未来计划的内容。
3. **推荐设计**：说明核心决策及理由；列出要修改或新增的文件与各自职责、依赖关系、复用的现有实现。只有存在真实取舍时才列备选方案与舍弃理由。
4. **关键契约**：必要的公开接口、数据结构和配置字段；输入、输出、单位/shape/类型、状态生命周期、异常与失败行为、兼容性要求。对安全协议和数值路径写清 invariant、消息顺序、量化/截断/模运算边界；不相关则写“不适用”。
5. **实施顺序与验证矩阵**：给实现者可执行的阶段顺序；每条验收标准对应什么测试或运行证据；说明跨模块联调、回归检查和不能用弱化测试替代的检查。
6. **风险和待决项**：指出最可能误改的位置、设计假设、需要用户决策的阻断问题。可自行从仓库和 Issue 证据确定的细节由你决定，不把常规实现细节留给用户。

设计评论末尾写明：Issue URL、main SHA、关键文件路径、适用的前置 Issue、设计结论。若存在无法合理确定且会改变接口或 Issue 范围的阻断问题，先在评论中说明并向用户提问；不得假装方案已定稿。完成设计后停止，不开始编码。

## 2. 实现对话：根据设计编码｜GPT-5.6 Terra，High

你负责实现 GitHub Issue <Issue URL>。设计评论：<设计评论 URL>。先读取当前 Issue、设计评论、`AGENTS.md`、相关代码/测试/配置，并核对最新 `origin/main` 与设计所依据的 SHA。设计是实施依据，不覆盖 Issue、`AGENTS.md` 或当前代码事实。若设计因 main 变化而失效，先说明具体差异并在 Issue 留下修订决策；能够依据现有契约安全修正的细节直接处理。

本项目使用单工作目录，以 Git branch 隔离 Issue；不要创建 Issue 文件夹、仓库副本或 worktree。修改前检查 branch、工作区和远端状态，不覆盖已有未提交修改。遵循 `AGENTS.md` 的 Issue → 实现 → 验证 → PR 工作流。

按设计逐项实现，优先复用 canonical implementation，保持核心场景无关和现有 ownership。不扩大 Issue 范围，不为了“完整”新增无用模块、抽象或依赖。对设计中未列但实现必需的局部细节，可自行做最小选择，并在结果中说明。若必须改变公共接口、安全/数学语义、重要架构边界或 Issue 范围，暂停该部分并说明证据、影响和建议决策；先完成不依赖该决策的工作。

完成后执行直接相关验证及 `AGENTS.md` 要求的完整验证。记录真实运行结果，不把未运行的检查写成通过。检查 diff 只包含当前 Issue 所需修改，再提交、推送并创建或更新对应 PR；不要合并。将实现结果发布到 Issue 评论区，包含：设计评论链接、PR URL、当前 head SHA、修改文件及原因、逐条验收结果、实际测试命令与结果、未解决事项。最终答复给出 Issue 评论和 PR 链接。

## 3. Review 对话：首次审查与复审｜GPT-5.6 Sol，High

你负责独立审查 Issue <Issue URL> 的 PR <PR URL>；设计评论：<设计评论 URL>。严格从 `review/00_REVIEW_ROUTER.md` 开始，按 Diff Mode 和其引用规则审查。先读取 Issue、设计、`AGENTS.md`、PR diff 与必要上下文，记录 base 与本轮被审 head SHA。不得修改项目文件、提交或推送。

逐条检查 Issue 验收标准、设计契约、实际数据流与状态归属、依赖方向、协议/数值/安全不变量、错误路径、测试是否能发现真实回归，以及改动对已有功能的影响。按 Review Pack 的两阶段流程先找候选，再主动证伪；仅报告有具体触发条件、代码或运行证据、现实影响且达到置信门槛的问题。不要把风格意见、未来功能设想或未经证实的风险写成 Finding。

对每个确认的 Finding 使用稳定 ID（RV-001 等），写清优先级、位置、触发条件、证据、影响、违反的约束、证伪过程，以及 **Suggested direction、Constraints / Non-goals、Acceptance check、Suggested validation**。修复方向要说明现有架构中应恢复的行为和责任层；不要给 patch、实现代码或未经验证的新架构。证据不足的项放入未验证风险。报告覆盖范围、实际运行的验证和遗漏项；按 `review/output/REPORT_FORMAT.md` 给出完整结论，并明确当前证据是否足以支持合并。

把完整报告发布到 Issue 评论区，并在最终答复给出评论链接、PR URL 和被审 head SHA。若用户随后给出修复评论或 PR 出现新 head，在本对话继续 re-review：读取上一轮 Finding 和修复说明，逐项核对原问题是否消失、相关测试是否有效，并审查修复 diff 的新回归；发布包含新 head SHA 的复审报告。不得因为旧报告曾 PASS 而跳过新提交。

## 4. 实现对话：根据 Review 修复｜GPT-5.6 Terra，High

继续处理 Issue <Issue URL> 的 PR <PR URL>。Review 报告：<Review 评论 URL>。先读取 `AGENTS.md` 第 14B 节、当前 Issue 与设计评论、Review 报告、PR 当前 head SHA、相关实现和测试。只在该 Issue 的现有分支与 PR 中工作；不得另开仓库副本、worktree 或无关 PR。

把每条 RV Finding 当作待验证的缺陷报告，而不是强制 patch。逐项复现或用代码证据重新验证触发路径、影响、当前 HEAD 是否仍有问题以及是否属于本 Issue。依 `AGENTS.md` 给每条标记 Fixed、Rejected、Already resolved、Superseded、Follow-up required 或 Blocked，并说明证据。有效且在范围内的问题按现有架构做最小正确修复；Review 的 Suggested direction 仅供参考，不能压过代码事实或现有契约。若修复必然改变公共接口、安全/数学语义、重要架构或 Issue 范围，说明具体冲突并请求设计决策，同时继续处理其他独立 Finding。

每个 Fixed Finding 都要有直接相关的验证；适合的 bug 增加或保留回归测试，并执行 `AGENTS.md` 的完整验证。确认没有无关 diff 后提交、推送到同一个 PR，不合并。向原 Issue 或 PR 的 Review 评论链回复逐项状态、修复内容、commit、实际测试命令与结果、遗留限制，并邀请原 Review 对话对新 head SHA 复审。最终答复附 PR URL、修复回复链接和新 head SHA。
