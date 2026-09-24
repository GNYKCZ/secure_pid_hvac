"use strict";

const $ = (id) => document.getElementById(id);
const ns = "http://www.w3.org/2000/svg";
const colors = { reference: "#899d18", output_ideal: "#2183b3", output_secure: "#c65535",
  control_ideal: "#2183b3", control_secure: "#c65535", control_error: "#7445a2", output_error: "#7445a2" };
const view = { source: null, generation: 0, sessionId: null, lastSeq: -1, seen: new Map(), ended: false, gaps: 0, late: 0,
  samples: [], channels: null, roles: null, latency: null, currentRun: null, mode: "live" };

function labelUnit(unit) {
  return unit === "paper_unit_unspecified" ? "物理单位未指定" : unit;
}

function setText(id, value) { $(id).textContent = String(value); }

function selectChannels(id, channels) {
  const select = $(id);
  select.replaceChildren();
  if (!channels) return;
  if (channels.names.length > 1) select.add(new Option("显式选择通道", ""));
  channels.names.forEach((name, index) => select.add(new Option(
    `${index}: ${name} (${labelUnit(channels.units[index])})`, String(index))));
  select.value = channels.names.length === 1 ? "0" : "";
}

function reset(mode, run) {
  if (view.source) view.source.close();
  view.generation += 1;
  Object.assign(view, { source: null, sessionId: null, lastSeq: -1, ended: false,
    seen: new Map(), gaps: 0, late: 0, samples: [], channels: null, roles: null, latency: null,
    currentRun: run || null, mode });
  setText("source", mode === "live" ? "直播" : `正式回放 ${run.run_id}`);
  setText("status", "等待公开事件");
  setText("session-id", "未提供");
  setText("backend", run ? run.backend : "未提供");
  setText("scenario-note", "");
  ["reference", "output", "control"].forEach((key) => selectChannels(`${key}-channel`, null));
  render();
}

function startStream(mode, run) {
  reset(mode, run);
  const generation = view.generation;
  const url = mode === "live" ? "/api/events" : `/api/runs/${encodeURIComponent(run.run_id)}/events`;
  const source = new EventSource(url);
  view.source = source;
  source.onmessage = (message) => {
    if (generation !== view.generation) return;
    let event;
    try { event = JSON.parse(message.data); } catch { setText("status", "事件格式无效"); return; }
    if (event.event_schema_version !== 1 || !Number.isInteger(event.event_seq)) {
      setText("status", "事件版本不支持"); source.close(); return;
    }
    accept(event);
  };
  source.onerror = () => {
    if (generation !== view.generation) return;
    if (!view.ended) setText("status", mode === "live" ?
      "连接中断，运行状态未知" : "回放连接中断，结果未完整展示");
    if (mode === "replay") source.close();
  };
}

function accept(event) {
  if (event.kind === "session_started") {
    if (view.sessionId === event.session_id) {
      if (view.seen.get(0) !== JSON.stringify(event)) {
        setText("status", "事件序号冲突"); view.source.close();
      }
      return; // SSE 重连的同一 header 不清空旧样本。
    }
    view.sessionId = event.session_id;
    view.lastSeq = 0;
    view.seen = new Map([[0, JSON.stringify(event)]]);
    view.ended = false;
    view.samples = [];
    view.gaps = 0;
    view.channels = event.channels;
    ["reference", "output", "control"].forEach((key) => selectChannels(
      `${key}-channel`, event.channels[key]));
    setText("session-id", event.session_id);
    setText("status", "会话已开始");
  } else {
    if (event.session_id !== view.sessionId) {
      view.late += 1; render(); return;
    }
    if (view.seen.has(event.event_seq)) {
      if (view.seen.get(event.event_seq) !== JSON.stringify(event)) {
        setText("status", "事件序号冲突"); view.source.close();
      }
      return;
    }
    if (event.event_seq <= view.lastSeq || view.ended) {
      view.late += 1; render(); return;
    }
    view.seen.set(event.event_seq, JSON.stringify(event));
    if (event.event_seq > view.lastSeq + 1) view.gaps += event.event_seq - view.lastSeq - 1;
    view.lastSeq = event.event_seq;
    if (event.kind === "sample") {
      view.samples.push(event);
      view.latency = event.latency_ms;
      setText("status", view.gaps ? (view.mode === "live" ?
        "直播缺帧；正式回放可恢复完整轨迹" : "回放缺口，结果未完整展示") : "运行中");
    } else if (event.kind === "session_fault") {
      setText("status", `会话故障：${event.category}`);
    } else if (event.kind === "session_ended") {
      view.ended = true;
      setText("status", event.status === "completed" ? "控制已完成；正式发布状态见上方" :
        `会话结束：${event.status}`);
      if (view.mode === "replay") view.source.close();
    }
  }
  view.roles = event.roles;
  render();
}

function semanticReference(referenceName, outputName) {
  if (referenceName === "unused_zero") return false;
  if (referenceName === outputName) return true;
  const tokens = (name) => name.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const generic = new Set(["target", "reference", "setpoint", "output", "air", "room"]);
  return tokens(referenceName).some((token) => !generic.has(token) && tokens(outputName).includes(token));
}

function signal(field, index) {
  if (index === null) return [];
  return view.samples.filter((row) => Array.isArray(row[field])).map((row) => ({
    step: row.step, time: row.time_s, value: row[field][index]
  }));
}

function element(name, attributes = {}) {
  const item = document.createElementNS(ns, name);
  Object.entries(attributes).forEach(([key, value]) => item.setAttribute(key, String(value)));
  return item;
}

function draw(id, series, unit, legendId) {
  const svg = $(id);
  svg.replaceChildren();
  svg.setAttribute("viewBox", "0 0 680 240");
  const visible = series.filter((item) => item.points.length);
  setText(legendId, visible.length ?
    `${visible.map((item) => item.name).join(" · ")} · ${labelUnit(unit)} · 横轴为仿真秒（按 step 采样）` :
    "暂无可展示样本或尚未选择通道");
  if (!visible.length) return;
  const all = visible.flatMap((item) => item.points);
  let x0 = Math.min(...all.map((point) => point.time));
  let x1 = Math.max(...all.map((point) => point.time));
  let y0 = Math.min(...all.map((point) => point.value));
  let y1 = Math.max(...all.map((point) => point.value));
  if (x0 === x1) x1 = x0 + 1;
  if (y0 === y1) { y0 -= 1; y1 += 1; }
  const x = (value) => 64 + 590 * (value - x0) / (x1 - x0);
  const y = (value) => 195 - 155 * (value - y0) / (y1 - y0);
  svg.append(element("path", { d: "M64 30 V195 H655", fill: "none", stroke: "#879aa5" }));
  [[String(y1), 32], [String(y0), 198]].forEach(([text, ypos]) => {
    const node = element("text", { x: 4, y: ypos, "font-size": 11 }); node.textContent = Number(text).toPrecision(4); svg.append(node);
  });
  const axis = element("text", { x: 64, y: 222, "font-size": 11 });
  axis.textContent = `k=${Math.min(...all.map((p) => p.step))}…${Math.max(...all.map((p) => p.step))} · t=${x0}…${Math.max(...all.map((p) => p.time))} s`;
  svg.append(axis);
  visible.forEach((item) => {
    let segment = [];
    const flush = () => {
      if (!segment.length) return;
      svg.append(element("path", { d: segment.map((point, i) => `${i ? "L" : "M"}${x(point.time)} ${y(point.value)}`).join(" "),
        fill: "none", stroke: colors[item.field], "stroke-width": 2,
        "stroke-dasharray": item.field.endsWith("ideal") ? "5 3" : "none" }));
      segment = [];
    };
    item.points.forEach((point, i) => {
      if (i && point.step !== item.points[i - 1].step + 1) flush();
      segment.push(point);
      const marker = item.field.endsWith("ideal") ? element("circle", { cx: x(point.time), cy: y(point.value), r: 2.4 }) :
        element("rect", { x: x(point.time) - 2, y: y(point.value) - 2, width: 4, height: 4 });
      marker.setAttribute("fill", colors[item.field]);
      marker.setAttribute("data-step", point.step);
      marker.setAttribute("data-time-s", point.time);
      marker.setAttribute("data-value", point.value);
      const tip = element("title"); tip.textContent = `${item.name}: k=${point.step}, t=${point.time} s, ${point.value} ${labelUnit(unit)}`;
      marker.append(tip); svg.append(marker);
    });
    flush();
  });
}

function render() {
  setText("gaps", view.gaps);
  setText("late-count", view.late);
  setText("sample-count", view.samples.length);
  const last = view.samples.at(-1);
  setText("step", last ? last.step : "未提供");
  setText("time-range", last ? `${view.samples[0].time_s}…${last.time_s} s` : "未提供");
  const roles = $("roles"); roles.replaceChildren();
  ["Client", "P1", "P2"].forEach((role) => {
    const item = document.createElement("span"); item.className = "role";
    const value = view.roles && view.roles[role];
    item.textContent = `${role}: ${value ? value.state : "unknown"} (${value ? value.source : "unavailable"})`;
    roles.append(item);
  });
  setText("latency-round", view.latency && view.latency.controller_round !== null ?
    `${view.latency.controller_round.toFixed(3)} ms` : "未采集");
  setText("latency-plant", view.latency && view.latency.actuator_plant !== null ?
    `${view.latency.actuator_plant.toFixed(3)} ms` : "未采集");
  const channels = view.channels;
  const notes = [];
  if (channels && channels.reference.names.includes("unused_zero"))
    notes.push("unused_zero 是未使用的 schema 占位；本实验没有设定值阶跃。");
  if (last && last.control_ideal === null) notes.push("本会话无理想分支，只展示安全侧曲线。");
  if (view.currentRun && view.currentRun.raw_equals_applied)
    notes.push("该 verified run 声明 raw_equals_applied=true；原始控制量等于实际施加量。");
  setText("scenario-note", notes.join(" "));
  const index = (id) => $(id).value === "" ? null : Number($(id).value);
  const oi = index("output-channel"), ci = index("control-channel"), ri = index("reference-channel");
  const outputUnit = channels && oi !== null ? channels.output.units[oi] : "";
  const controlUnit = channels && ci !== null ? channels.control.units[ci] : "";
  const refAllowed = channels && oi !== null && ri !== null &&
    channels.reference.units[ri] === outputUnit &&
    semanticReference(channels.reference.names[ri], channels.output.names[oi]);
  setText("channel-note", channels && !refAllowed ?
    "Reference 未与输出共轴：占位、单位不同或名称语义无法对应。向量信号须逐通道选择。" :
    "名称与单位允许共轴；向量信号须逐通道选择。");
  const item = (field, name, points) => ({ field, name, points });
  draw("output-chart", [
    item("reference", "Reference", refAllowed ? signal("reference", ri) : []),
    item("output_ideal", "理想输出", signal("output_ideal", oi)),
    item("output_secure", "安全输出", signal("output_secure", oi)),
  ], outputUnit, "output-legend");
  draw("control-chart", [
    item("control_ideal", "理想实际施加 u(t)", signal("control_ideal", ci)),
    item("control_secure", "安全实际施加 û(t)", signal("control_secure", ci)),
  ], controlUnit, "control-legend");
  draw("control-error-chart", [item("control_error", "有符号 u−û", signal("control_error", ci))],
    controlUnit, "control-error-legend");
  draw("output-error-chart", [item("output_error", "有符号输出差", signal("output_error", oi))],
    outputUnit, "output-error-legend");
}

async function updateStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) return;
    const status = await response.json();
    const publicationLabels = { not_started: "未开始", running: "控制运行中", saving: "正式结果待验证",
      verified: "正式回放可用", unavailable: "正式回放不可用", saved_only: "仅保存回放" };
    setText("publication", publicationLabels[status.publication] || "未知");
    setText("delivery-note", `A07 丢帧 ${status.publisher_dropped_samples}；页面桥丢帧 ${status.bridge_dropped_samples}；派发失败 ${status.publisher_delivery_failed ? "是" : "否"}。`);
    if (status.publisher_delivery_failed && view.mode === "live" && !view.ended)
      setText("status", "公开遥测派发失败，控制运行状态未知");
    const picker = $("run-select");
    const newRuns = JSON.stringify(status.runs);
    if (picker.dataset.runs !== newRuns) {
      const selected = picker.value;
      picker.replaceChildren(new Option("选择 run", ""));
      status.runs.forEach((run) => {
        const label = `${run.run_id} · ${run.scenario} · ${run.backend}${run.fractional_bits ? ` · ell=${run.fractional_bits}` : ""}`;
        picker.add(new Option(label, run.run_id));
      });
      picker.value = status.runs.some((run) => run.run_id === selected) ? selected : "";
      picker.dataset.runs = newRuns;
    }
    if (view.mode === "live" && view.sessionId)
      view.currentRun = status.runs.find((run) => run.live_session_id === view.sessionId) || null;
    if (view.currentRun) setText("backend", view.currentRun.backend);
    render();
  } catch { /* 本机服务不可达时，SSE 的连接状态仍显示在会话卡片。 */ }
}

$("live-button").addEventListener("click", () => startStream("live", null));
$("replay-button").addEventListener("click", () => {
  const runs = JSON.parse($("run-select").dataset.runs || "[]");
  const run = runs.find((item) => item.run_id === $("run-select").value);
  if (run) startStream("replay", run);
});
["reference", "output", "control"].forEach((key) => $(key + "-channel").addEventListener("change", render));
startStream("live", null);
updateStatus();
setInterval(updateStatus, 2000);
