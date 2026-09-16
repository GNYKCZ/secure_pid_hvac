# Issue #14 已保存结果绘图契约

## 数据入口和职责

绘图只接受 #13 已发布的完整 `run_dir`，先由 `load_artifacts(run_dir)` 复验成功状态、
schema v1、CSV/配置摘要、通道 metadata、shape、有限值和有符号误差。不接受孤立 CSV
与 metadata 的组合，因为它不能复用配置摘要及发布状态校验。绘图不构造 plant、PID、
安全 session，也不调用 simulation runner 或修改原始 CSV/metrics。

```powershell
uv run python -m secure_control.experiments.figure_runner --run-dir results/csv/<run_id> --control-error-scale log
```

默认单通道 HVAC 使用 `output 0 → reference 0`、control 0、小时轴，生成四张 PNG。
非单通道 HVAC 和其他场景必须显式指定至少一组 tracking 配对及 control 通道；
两个选项都可重复；若输出通道没有可共轴的 reference，`--output-error-channel`
可独立、重复指定仅画该通道的有符号 error：

```powershell
uv run python -m secure_control.experiments.figure_runner --run-dir results/csv/<run_id> --tracking 0:1 --control-channel 0 --control-channel 1 --output-error-channel 2 --time-unit s --format pdf
```

tracking 配对顺序为 `output_index:reference_index`，不能自动把向量同号通道配对。
共轴前要求 reference/output 单位完全相同；通道 index 越界、重复选择、单位错配
都会失败。图例的通道名及 y 轴单位来自保存的 `ScenarioMetadata`，通用绘图层不定义
`temperature_*`、PID 或 HVAC schema。
省略 `--output-error-channel` 时，output-error 图仍按既有规则取 tracking 中出现的
输出通道；显式指定时只按给出的输出索引绘制，不要求它与 reference 单位相同，
也不放宽 tracking 图本身的共轴校验。

## 四类曲线和时间语义

| 类别 | 已保存字段 | 画法 |
| --- | --- | --- |
| tracking | `reference[:,r]`、`output_ideal[:,y]`、`output_secure[:,y]` | 同一 y 轴的 reference/更新前 ideal/secure output |
| control | `control_ideal[:,u]`、`control_secure[:,u]` | 两支实际施加给 plant 的 applied control，不是 raw PID |
| control_error | `control_error[:,u]` | linear 为有符号 `ideal-secure`；log 为仅供渲染的 `abs(ideal-secure)` |
| output_error | `output_error[:,y]` | 有符号 `ideal-secure`，不偷偷取绝对值 |

所有曲线使用同一 `result.time`。schema v1 保存秒数；`--time-unit h` 只按
`time / 3600` 显示，不添加虚构终点。当前 HVAC 180 个样本为 0…10740 s，
并不包含 10800 s。若以后画 reference 切换标记，只能读取有效配置中的区段边界；
本 Issue 的图没有额外硬编码标记。

普通 log y 轴不能显示负数或零。control error 的 log 图明确标注绝对值，
将恰为零的样本仅在渲染副本中 mask，并标注 mask 数量。全零时不画任何正值点，
而注记“全部为零、没有正值可显示”；绝不制造 epsilon 或写回 CSV。

## 路径、发布和追溯

默认图目录为 `results/figures/<source_run_id>/<render_id>/`。一次 render 生成独立
时间+随机 nonce 身份，不覆盖同 ID 已有目录。所有图与 `figures_manifest.json`
先写入同父目录私有 `.incomplete-<render_id>` staging，全部保存成功后同盘发布。
失败仅清理本调用拥有的 staging；已有成功图、未知用户目录和源 run 始终保留。
清单源文件摘要在正式 reader 调用前取得，并在其返回后及发布前再次比对；
读取或绘图期间若源 CSV/metadata/config 改变，拒绝发布与旧记录不一致的清单。

文件名含通道/配对与 error 尺度，例如：

```text
tracking_output-0_reference-0.png
control-0.png
control_error-0_log.png
output_error-0.png
figures_manifest.json
```

图使用无 GUI 的 Agg canvas、统一字体/线型/图例/网格和 300 dpi；`--format pdf`
使用同一 Figure 保存 PDF，不重新仿真。manifest 记录 source run ID、schema/scenario
version、源 `trajectory.csv`/`metadata.json`/`config.json` SHA-256、render ID、
Matplotlib 版本、每张图的类别/相对文件名/选择的通道 index/name/unit/时间单位/
error 尺度/零样本数量及图文件 SHA-256。它不存用户绝对路径或安全随机材料。
这些 hash 是损坏和来源关联信息，不是数字签名、恶意篡改保证或控制安全证明。

普通生成图及 CSV 被路径级 `.gitignore` 规则精确忽略；论文正式代表结果若需
版本管理，必须另有明确交付要求，而非把本 Issue 的临时验证图提交 Git。
