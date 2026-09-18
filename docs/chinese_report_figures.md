# 2R2C HVAC 中文汇报图

## 只读数据链

中文报告只消费已冻结的正式工件。单次运行入口先调用 `load_artifacts()`；完整报告入口先调用
`load_verified_sweep_data()`，验证 final/data manifest、摘要、逐点记录和每个成功 run 后才绘图。
报告入口不导入或调用实验 runner、scenario、controller、protocol、runtime 或 simulation。

正式完整报告命令为：

```powershell
uv run python -m secure_control.experiments.sweep_figure_runner --sweep-dir results/sweeps/<sweep_id> --display-config configs/hvac_2r2c_report_zh.yaml --output-root results/figures/reports
```

只重绘一个 canonical run 的 01–06 单点图时可以使用：

```powershell
uv run python -m secure_control.experiments.figure_runner --run-dir <run_dir> --display-config configs/hvac_2r2c_report_zh.yaml --output-root results/figures/reports
```

不传 `--display-config` 时，既有英文技术图的参数、文件名和行为保持不变。

## 展示配置与字体

`configs/hvac_2r2c_report_zh.yaml` 是场景拥有的纯展示配置，冻结 `zh-CN` 文案、机器通道和单位
到中文名称的映射、显式通道索引、所有图面文字模板、主 seed、代表精度、阶段配置路径、16:9 画布、DPI、颜色、线型、marker、
01–12 中文文件名以及 P1/P2/P3。配置 SHA-256 会写入报告清单；它不改变 metadata、通道选择、
实验数组或指标。

绘图前按配置顺序解析本机 `Microsoft YaHei`、`SimHei`。实际 family、文件路径和可读取时的
字体文件 SHA-256 写入 `report_manifest.json`。本批所有中文字符先通过 FT2Font charmap 预检，
保存图时仍捕获 missing-glyph warning；任一检查失败都拒绝发布，不静默回退到乱码图。数学符号
使用 Matplotlib mathtext，不启用外部 LaTeX。

## 图、布局和数值语义

完整报告严格生成 `01_温度跟踪.png` 至 `12_时间与协议资源.png`。P1/P2/P3 只写入清单和目录，
不用于过滤。所有时间序列共享来源样本的时间范围、小时单位和从 effective config 读取的 reference
阶段边界；不会补造 10800 s 终点。跨精度图统一按 `ell=32,40,48,56` 排列并使用冻结样式。

`control_ideal/control_secure` 是实际施加给 plant 的 applied control，不是 raw PID output。
有符号误差始终为 ideal minus secure；绝对误差只在绘图副本中取绝对值。log 轴对精确零值做 mask
并保留零样本语义，不注入 epsilon。线性科学计数法使用 mathtext `times 10` 形式，log tick 使用
`10` 的幂；formatter 不改写数组。跨精度主图只画冻结的 `primary_seed=42`，避免三个数值相同
seed 的重复曲线；全部 seed、成功/失败/不可行状态仍记录在报告 manifest。

## 发布与追溯

报告写入 `results/figures/reports/<source_sweep_id>/<render_id>/`，不写回 frozen sweep。正式 sweep
入口固定验证最终 `manifest.json` 及其绑定的 `data_manifest.json`，不提供降级为 data manifest 的选项。
全部图、`report_manifest.json` 和 `汇报图目录.md` 先写入私有 staging，源与 display profile 在读取前、绘图后
和原子发布前保持相同才发布；已有 render ID 拒绝覆盖，失败清理本次 staging。

JSON 与 Markdown 使用同一个内存 catalog，逐图记录 sequence、priority、中文文件名、用途、讲解
建议、来源字段、限制和图 SHA-256。manifest 还记录 source sweep/run、final/data manifest hash、
全部点状态、代表 run 三文件 hash、来源 Git provenance、display profile、字体、Matplotlib 版本、
统一时间轴/阶段线/精度样式。SHA-256 只用于完整性和来源关联，不是数字签名或对抗性安全证明。

## 声明边界

这些图是冻结工件的 Equivalent 重渲染，未重新运行实验也未改变任何 metric。2R2C 模型仍是
Adapted HVAC plant model；报告不把它表述为论文原数值例，不新增闭环性能、安全性或真实建筑
标定结论。数值继续受 binary64 与已记录定点误差边界限制。
