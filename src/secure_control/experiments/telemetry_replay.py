"""从正式 verified artifact 映射公开遥测 v1；不重跑控制器。"""

from __future__ import annotations

from pathlib import Path

from secure_control.experiments.artifacts import load_artifacts
from secure_control.simulation.telemetry import PublicEvent, Sample, SessionEnded, SessionStarted


def replay_events(run_dir: str | Path) -> tuple[PublicEvent, ...]:
    """逐行严格依赖 v1 reader 复验；旧产物不推造历史角色和时延。"""
    record = load_artifacts(run_dir)
    result = record.result
    events: list[PublicEvent] = [SessionStarted(record.run_id, 0, record.metadata)]
    for step, time in enumerate(result.time):
        events.append(
            Sample(
                session_id=record.run_id,
                event_seq=step + 1,
                step=step,
                time_s=float(time),
                reference=tuple(map(float, result.reference[step])),
                output_secure=tuple(map(float, result.output_secure[step])),
                control_secure=tuple(map(float, result.control_secure[step])),
                metadata=record.metadata,
                output_ideal=tuple(map(float, result.output_ideal[step])),
                control_ideal=tuple(map(float, result.control_ideal[step])),
                control_error=tuple(map(float, result.control_error[step])),
                output_error=tuple(map(float, result.output_error[step])),
            )
        )
    events.append(SessionEnded(record.run_id, len(events), "completed", len(result.time) - 1))
    return tuple(events)
