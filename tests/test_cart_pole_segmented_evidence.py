"""#101：真实持续计算的聚合发布、跨块 replay 与语义篡改回归。"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from itertools import pairwise
from pathlib import Path

import numpy as np
import pytest
import yaml
from scipy.integrate import solve_ivp
from test_cart_pole_balance import ORACLE_K, _oracle_rhs
from test_cart_pole_lan import ROOT, _profile_for
from test_lan_continuous import _plain_deployment
from test_lan_segmented import _PARTY
from test_lan_single_step import _finish, deployment

from secure_control.experiments import cart_pole_segmented_evidence as evidence

_CLIENT = r'''
import json, sys
from pathlib import Path
from secure_control.execution.lan_config import load_lan_config
from secure_control.execution.lan_runtime import RunControl
from secure_control.experiments import cart_pole_segmented_evidence as e
from secure_control.scenarios.cart_pole.interactive import InteractiveSession
config = load_lan_config(Path(sys.argv[1]), 'Client')
mode, count, capacity = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
control, session = RunControl(), InteractiveSession(scheduled={399:1.,400:-1.,799:1.,800:-1.})
frames, phases = [], {}
if count == 0:
    control.request_stop()
if mode in ('spool', 'disk_full'):
    original = e._write
    def write(path, *args):
        if path.name.startswith('spool-'):
            raise OSError(28, 'injected disk full')
        return original(path, *args)
    e._write = write
if mode == 'plot':
    def plot(*args, **kwargs):
        raise RuntimeError('injected mandatory plot failure')
    e.write_segmented_overview = plot
if mode == 'reader':
    e._verify = lambda *args, **kwargs: (_ for _ in ()).throw(ValueError('reader failed'))
if mode == 'replay':
    e._Replay.convert = lambda *args, **kwargs: (_ for _ in ()).throw(ValueError('replay failed'))
def phase(value):
    phases[value] = phases.get(value, 0) + 1
    if mode == 'zero_tail' and value == 'RECORDING_SEGMENT' and len(frames) == count:
        control.request_stop()
    if mode.startswith('cancel_') and value == mode.removeprefix('cancel_'):
        session.close()
    if mode == 'source' and value == 'REPLAYING':
        with config.experiment_config.open('ab') as output:
            output.write(b'\n# changed during replay\n')
    if mode == 'cancel_before_rename' and value == 'PUBLISHING':
        session.close()
    if mode == 'cancel_after_rename' and value == 'COMPLETE':
        session.close()
def step(record):
    frames.append({'g':record.protocol.global_step, 'state':record.snapshot.observation_after})
    if len(frames) == count and mode != 'zero_tail':
        control.request_stop()
try:
    result = e.run_cart_pole_segmented(config, control=control, session=session,
                                      segment_steps=capacity, on_step=step, phase=phase)
except Exception as error:
    import traceback
    result = {'status':'failed','category':type(error).__name__, 'traceback':traceback.format_exc()}
print(json.dumps({'result':result,'frames':frames,'phases':phases}))
'''


def _run(tmp_path, *, count=7, capacity=3, mode="normal", tls=False, client_code=_CLIENT,
         party_fault="none"):
    paths = deployment.__wrapped__(tmp_path) if tls else _plain_deployment(tmp_path)
    profile = _profile_for(paths)
    if tls:
        value = yaml.safe_load(paths["Client"].read_text())
        value.pop("controller")
        value["experiment"] = str(profile)
        paths["Client"].write_text(yaml.safe_dump(value, sort_keys=False))
    processes = []
    try:
        for role in ("P1", "P2"):
            processes.append(subprocess.Popen(
                [sys.executable, "-c", _PARTY, role, str(paths[role]), party_fault], cwd=ROOT,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ))
        client = subprocess.Popen(
            [sys.executable, "-c", client_code, str(paths["Client"]), mode, str(count), str(capacity)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        processes.append(client)
        try:
            code, report, errors = _finish(client, 600)
        except subprocess.TimeoutExpired:
            client.kill()
            output, errors = client.communicate()
            pytest.fail(f"Client timeout: {output} / {errors}")
        if code != 0:
            pytest.fail(json.dumps(report, ensure_ascii=False, indent=2) + "\n" + errors)
        if report["result"]["status"] == "complete":
            outcomes = [_finish(p, 20) for p in processes[:2]]
            assert all(row[0] == 0 for row in outcomes), outcomes
            assert len({report["result"]["backend"]["pid"], *(row[1]["pid"] for row in outcomes)}) == 3
            assert all(row[1]["steps_committed"] == count for row in outcomes)
        return report
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate()


@pytest.fixture(scope="module")
def published(tmp_path_factory):
    root = tmp_path_factory.mktemp("segmented-result")
    report = _run(root)
    assert report["result"]["status"] == "complete", report
    return Path(report["result"]["run_dir"]), report


def test_real_segments_publish_and_observation_seek_matches_confirmed_frames(published):
    path, report = published
    run = evidence.open_verified_cart_pole_segmented_run(path)
    assert run.metadata["N"] == 7 and run.metadata["segment_count"] == 3
    assert run.metadata["termination"]["stop_reason"] == "user_requested"
    assert run.metadata["termination"]["observed_status"] == "recovering"
    for frame in report["frames"]:
        point = run.observation_at(frame["g"]+1)
        np.testing.assert_allclose(point["state"], frame["state"], rtol=0, atol=1e-12)
        assert point["time_s"] == (frame["g"]+1)*.02
    assert run.observation_at(0)["applied_force_n"] is None
    assert len(run._cache) <= 2
    with pytest.raises(TypeError):
        run.metadata["N"] = 1
    for value in (-1, 8, True):
        with pytest.raises(ValueError):
            run.observation_at(value)


@pytest.mark.parametrize("count", [0, 1, 3])
def test_empty_partial_and_full_stop_results_have_no_dummy_rows(tmp_path, count):
    report = _run(tmp_path, count=count)
    assert report["result"]["status"] == "complete", report
    run = evidence.open_verified_cart_pole_segmented_run(report["result"]["run_dir"])
    assert run.metadata["N"] == count
    entries = list(run.iter_segments())
    if count == 0:
        assert entries[0][1] is None and run.observation_at(0)["applied_force_n"] is None
    else:
        assert sum(record.result.time.size for _, record, _, _ in entries) == count


def test_1001_steps_cross_boundaries_and_independent_physical_oracle(tmp_path):
    report = _run(tmp_path, count=1001, capacity=400)
    assert report["result"]["status"] == "complete", report
    run = evidence.open_verified_cart_pole_segmented_run(report["result"]["run_dir"])
    assert run.metadata["N"] == 1001
    assert [entry[0]["global_start"] for entry in run.iter_segments()] == [0,400,800]
    state = np.array([0.,0.,np.pi/36,0.])
    for g, frame in enumerate(report["frames"]):
        force = float(np.clip(-ORACLE_K @ state, -10,10))
        d = 1. if g in (399,799) else -1. if g in (400,800) else 0.
        state = solve_ivp(_oracle_rhs, (0,.02), state, args=(force+d,),
                          method="DOP853", rtol=1e-13, atol=1e-15).y[:,-1]
        np.testing.assert_allclose(frame["state"], state, rtol=0, atol=4e-8)
    for k in (0,399,400,401,799,800,801,1001):
        assert run.observation_at(k)["step"] == k


@pytest.mark.parametrize("mode", ["spool", "disk_full", "replay", "reader", "plot", "source",
                                  "cancel_before_rename", "cancel_CONNECTING", "cancel_REPLAYING",
                                  "cancel_VERIFYING", "cancel_PLOTTING"])
def test_failed_publication_has_no_formal_or_owned_staging_root(tmp_path, mode):
    report = _run(tmp_path, mode=mode)
    assert report["result"]["status"] != "complete"
    assert not list(tmp_path.rglob("run.json"))
    assert not list(tmp_path.rglob(".incomplete-*"))


def test_cancel_after_rename_keeps_verified_result(tmp_path):
    report = _run(tmp_path, mode="cancel_after_rename")
    assert report["result"]["status"] == "complete"
    assert evidence.open_verified_cart_pole_segmented_run(report["result"]["run_dir"]).metadata["N"] == 7


def test_confirmed_continue_then_zero_step_stop_is_retained(tmp_path):
    report = _run(tmp_path, count=3, capacity=3, mode="zero_tail")
    assert report["result"]["status"] == "complete", report
    path = Path(report["result"]["run_dir"])
    run = evidence.open_verified_cart_pole_segmented_run(path)
    entries = list(run.iter_segments())
    assert run.metadata["N"] == 3 and run.metadata["segment_count"] == 2
    assert entries[-1][0]["global_start"] == entries[-1][0]["global_end"] == 3
    assert entries[-1][1] is None
    assert entries[-1][3]["protocol"]["receipts"][0]["end"]["last_round_id"] is None
    assert run.observation_at(3)["applied_force_n"] is not None
    shutil.rmtree(path / "segments/1")
    with pytest.raises(ValueError):
        evidence.open_verified_cart_pole_segmented_run(path)


def test_mutual_tls_result_verifies_across_segments(tmp_path):
    report = _run(tmp_path, tls=True)
    assert report["result"]["status"] == "complete", report
    run = evidence.open_verified_cart_pole_segmented_run(report["result"]["run_dir"])
    assert run._config["transport"] == "mutual_tls" and run.metadata["segment_count"] == 3


@pytest.mark.parametrize("fault", ["commit_lost", "end_lost", "peer_disconnect"])
def test_real_network_fault_cannot_publish_complete_result(tmp_path, fault):
    report = _run(tmp_path, party_fault=fault)
    assert report["result"]["status"] in ("failed", "uncertain")
    assert not list(tmp_path.rglob("run.json")) and not list(tmp_path.rglob(".incomplete-*"))


def _copy(published, tmp_path):
    source = published[0]
    path = tmp_path / source.name
    shutil.copytree(source, path)
    return path


def _rehash(path):
    """负控只更新局部摘要链，语义检查仍须拒绝伪造，不弱化来源验证。"""
    entries = [json.loads(line) for line in (path / "segments.jsonl").read_text().splitlines()]
    for entry in entries:
        folder = path / "segments" / str(entry["index"])
        entry["protocol_sha256"] = evidence._hash(folder / "protocol.json")
        if entry["chunk"]:
            block = folder / entry["chunk"]["name"]
            metadata = json.loads((block / "metadata.json").read_text())
            metadata["derived_files_sha256"][evidence.EVIDENCE] = evidence._hash(block / evidence.EVIDENCE)
            metadata["files_sha256"] = {name:evidence._hash(block / name)
                                         for name in ("trajectory.csv","config.json")}
            (block / "metadata.json").write_bytes(evidence._bytes(metadata))
            entry["chunk"]["files"] = {name:evidence._hash(block / name)
                                         for name in entry["chunk"]["files"]}
    _rewrite_index(path, entries)


def _rewrite_index(path, entries):
    tail = None
    for entry in entries:
        entry["prev_sha256"] = tail
        entry.pop("sha256")
        tail = evidence.sha256(evidence._bytes(entry)).hexdigest()
        entry["sha256"] = tail
    (path / "segments.jsonl").write_bytes(b"".join(evidence._bytes(e) for e in entries))
    root = json.loads((path / "run.json").read_text())
    root["index_sha256"], root["tail"] = evidence._hash(path / "segments.jsonl"), tail
    # 同步图的源索引字段；不以旧 plot hash 恰好拒绝来冒充语义负控。
    plots = json.loads((path / "plots.json").read_text())
    plots["index_sha256"] = root["index_sha256"]
    (path / "plots.json").write_bytes(evidence._bytes(plots))
    root["plots_sha256"] = evidence._hash(path / "plots.json")
    (path / "run.json").write_bytes(evidence._bytes(root))


@pytest.mark.parametrize("mutation", ["time", "event", "boundary", "monitor", "receipt",
                                      "resource", "setup", "session_duplicate", "round_duplicate",
                                      "raw_force", "applied_force", "side_initial", "csv_force"])
def test_rehashed_local_semantic_tampering_is_rejected(published, tmp_path, mutation):
    path = _copy(published, tmp_path)
    entry = json.loads((path / "segments.jsonl").read_text().splitlines()[1])
    folder = path / "segments" / "1"
    file = folder / "protocol.json"
    data = json.loads(file.read_text())
    if mutation == "time":
        data["steps"][0]["snapshot"]["t_before_s"] += .02
    elif mutation == "boundary":
        data["steps"][0]["snapshot"]["observation_before"][0] += .01
    elif mutation == "monitor":
        data["steps"][0]["snapshot"]["stable_count"] += 1
    elif mutation == "receipt":
        data["protocol"]["receipts"][1]["party"] = "P1"
    elif mutation == "resource":
        for item in (data["steps"][0]["protocol"], data["protocol"]["steps"][0]):
            item["resource_ids"][0] = item["resource_ids"][1]
    elif mutation == "setup":
        data["protocol"]["setup"]["fractional_bits"] += 1
    elif mutation == "session_duplicate":
        previous = json.loads((path / "segments/0/protocol.json").read_text())
        data["protocol"]["session_id"] = previous["protocol"]["session_id"]
    elif mutation == "round_duplicate":
        previous = json.loads((path / "segments/0/protocol.json").read_text())
        round_id = previous["protocol"]["steps"][0]["round_id"]
        for step in (data["steps"][0]["protocol"], data["protocol"]["steps"][0]):
            step["round_id"] = round_id
            step["resource_ids"] = [f"{round_id}:D[0,{j}]" for j in range(4)]
    elif mutation == "raw_force":
        data["steps"][0]["snapshot"]["raw_force_n"] += .01
        for step in (data["steps"][0]["protocol"], data["protocol"]["steps"][0]):
            step["raw_control"][0] = data["steps"][0]["snapshot"]["raw_force_n"]
    elif mutation == "applied_force":
        data["steps"][0]["snapshot"]["applied_force_n"] += .01
    elif mutation == "side_initial":
        side = folder / entry["chunk"]["name"] / evidence.EVIDENCE
        payload = json.loads(side.read_text())
        payload["branches"]["secure"]["observations"][0][0] += .01
        side.write_bytes(evidence._bytes(payload))
    elif mutation == "csv_force":
        import csv
        trajectory = folder / entry["chunk"]["name"] / "trajectory.csv"
        with trajectory.open(newline="") as source:
            rows = list(csv.reader(source))
        for name in ("control_ideal[0]", "control_secure[0]"):
            column = rows[0].index(name)
            rows[1][column] = str(float(rows[1][column])+.01)
        with trajectory.open("w", newline="") as output:
            csv.writer(output).writerows(rows)
    elif mutation == "event":
        side = folder / entry["chunk"]["name"] / evidence.EVIDENCE
        payload = json.loads(side.read_text())
        payload["events"] = [{"step":3,"force_n":1.,"duration_steps":1,"phase":"invalid"}]
        side.write_bytes(evidence._bytes(payload))
    file.write_bytes(evidence._bytes(data))
    _rehash(path)
    with pytest.raises((ValueError, TypeError, AssertionError)):
        evidence.open_verified_cart_pole_segmented_run(path)


@pytest.mark.parametrize("mutation", ["delete", "index", "extra", "version", "escape", "duplicate_key"])
def test_missing_extra_or_malformed_artifacts_rejected(published, tmp_path, mutation):
    path = _copy(published, tmp_path)
    if mutation == "delete":
        (path / "segments/1/protocol.json").unlink()
    elif mutation == "extra":
        (path / "segments/3").mkdir()
    elif mutation == "index":
        with (path / "segments.jsonl").open("ab") as output:
            output.write((path / "segments.jsonl").read_bytes().splitlines()[0] + b"\n")
    else:
        manifest = json.loads((path / "run.json").read_text())
        if mutation == "version":
            manifest["format_version"] = 2
        elif mutation == "escape":
            lines = (path / "segments.jsonl").read_bytes().splitlines()
            item = json.loads(lines[0])
            item["chunk"]["name"] = "../other"
            (path / "segments.jsonl").write_bytes(evidence._bytes(item) + b"\n".join(lines[1:])+b"\n")
        elif mutation == "duplicate_key":
            (path / "run.json").write_text('{"N":1,' + (path / "run.json").read_text()[1:])
            with pytest.raises(ValueError):
                evidence.open_verified_cart_pole_segmented_run(path)
            return
        (path / "run.json").write_bytes(evidence._bytes(manifest))
    with pytest.raises((ValueError, TypeError, OSError)):
        evidence.open_verified_cart_pole_segmented_run(path)


def test_seek_rechecks_files_after_open_and_reader_does_not_generate_shares(published, tmp_path, monkeypatch):
    path = _copy(published, tmp_path)
    monkeypatch.setattr(evidence.Client, "distribute_controller", lambda *_a, **_kw: pytest.fail("shares"))
    run = evidence.open_verified_cart_pole_segmented_run(path)
    run.observation_at(4)
    (path / "segments/1/protocol.json").write_text("{}")
    with pytest.raises(ValueError):
        run.observation_at(4)


@pytest.mark.parametrize("mutation", ["reorder", "overlap", "missing", "duplicate", "escape", "bool"])
def test_rehashed_index_semantics_reject_incomplete_or_invalid_ranges(published, tmp_path, mutation):
    path = _copy(published, tmp_path)
    entries = [json.loads(line) for line in (path / "segments.jsonl").read_text().splitlines()]
    if mutation == "reorder":
        entries[0], entries[1] = entries[1], entries[0]
    elif mutation == "overlap":
        entries[1]["global_start"] -= 1
    elif mutation == "missing":
        entries.pop()
    elif mutation == "duplicate":
        entries.append(entries[-1].copy())
    elif mutation == "escape":
        entries[0]["chunk"]["name"] = "../other"
    else:
        entries[0]["index"] = False
    _rewrite_index(path, entries)
    with pytest.raises((ValueError, TypeError)):
        evidence.open_verified_cart_pole_segmented_run(path)


def test_disk_identity_index_and_reducer_have_fixed_capacity():
    from secure_control.experiments.plotting import BoundedOverview
    with evidence._identities() as database:
        assert database.execute("PRAGMA cache_size").fetchone()[0] == -4096
        assert database.execute("PRAGMA temp_store").fetchone()[0] == 1
        evidence._identity(database, "round", "first")
        with pytest.raises(ValueError):
            evidence._identity(database, "round", "first")
    reducer = BoundedOverview(100_000, buckets=8)
    for k in range(100_001):
        reducer.add(k, k*.02, np.sin(k))
    points = reducer.points()
    assert len(reducer._items) <= 8 and len(points) <= 34
    assert points[0][0] == 0 and points[-1][0] == 100_000
    assert all(a[0] < b[0] for a,b in pairwise(points))


def test_redraw_dispatches_verified_segmented_source_without_protocol(published, tmp_path):
    output = tmp_path / "overview.png"
    result = subprocess.run([sys.executable,"-m","secure_control.experiments.lan_runner",
                             "redraw","--run-dir",str(published[0]),"--output",str(output)],
                            cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "complete" and output.stat().st_size > 1000
