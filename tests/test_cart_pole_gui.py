"""#101：实际 Tk 三进程停止/异步回放，以及有界显示邮箱回归。"""

from __future__ import annotations

import gc
import json
import runpy
import threading
import time
import tkinter as tk
from collections import deque
from pathlib import Path

import pytest
from test_cart_pole_segmented_evidence import _run

from secure_control.scenarios.cart_pole.gui import CartPoleWindow

_GUI = r'''
import json, os, sys, threading, time, tkinter as tk, tracemalloc, ctypes
from pathlib import Path
from PIL import ImageGrab
from secure_control.scenarios.cart_pole.gui import CartPoleWindow
tracemalloc.start()
root = tk.Tk()
count, capacity = int(sys.argv[3]), int(sys.argv[4])
window = CartPoleWindow(root, Path(sys.argv[1]), segment_steps=capacity)
disk_stop = threading.Event()
disk_peak = 0
phase_memory = {}
original_notify = window._notify
def memory_notify(kind,value):
    original_notify(kind,value)
    if kind == 'phase' and value in ('BACKEND_STOPPED','REPLAYING','VERIFYING','PLOTTING','COMPLETE'):
        phase_memory[value] = tracemalloc.get_traced_memory()
window._notify = memory_notify
def disk_size():
    # 测量仪器也按固定目录深度流式走访，避免 rglob 的已遍历路径 set 污染峰值。
    def walk(folder):
        total = 0
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    try:
                        total += walk(entry.path) if entry.is_dir(follow_symlinks=False) else entry.stat().st_size
                    except FileNotFoundError:
                        pass
        except FileNotFoundError:
            pass
        return total
    return walk(window.prepared.output_root)
def disk_sample():
    global disk_peak
    while not disk_stop.wait(1.):
        disk_peak = max(disk_peak, disk_size())
disk_thread = threading.Thread(target=disk_sample)
disk_thread.start()
def peak_rss():
    # Windows 原生 peak working set 包含 NumPy/Matplotlib/Tk 分配。
    class Counters(ctypes.Structure):
        _fields_ = [('cb',ctypes.c_ulong),('faults',ctypes.c_ulong)] + [
            (name,ctypes.c_size_t) for name in ('peak','working','peak_paged','paged',
                                              'peak_nonpaged','nonpaged','pagefile','peak_pagefile')]
    info = Counters()
    info.cb = ctypes.sizeof(info)
    kernel = ctypes.windll.kernel32
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    psapi = ctypes.windll.psapi
    psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p,ctypes.c_void_p,ctypes.c_ulong]
    assert psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(info),info.cb)
    return info.peak
window.session._scheduled.update({399:1.,400:-1.,799:1.,800:-1.})
gate = threading.Event()
committed = 0
terminal_frame = None
original_frame = window._confirmed_frame
def frame(record):
    global committed, terminal_frame
    original_frame(record)
    committed = record.protocol.global_step + 1
    if committed == count:
        terminal_frame = record.snapshot
        assert gate.wait(30), 'Tk did not handle stop'
window._confirmed_frame = frame
shown, opened = [], []
original_show = window._show_seek
def show(value):
    original_show(value)
    shown.append({'step':value['step'], 'state':list(value['state']), 'time':value['time_s']})
window._show_seek = show
import secure_control.scenarios.cart_pole.gui as gui
gui.webbrowser.open = lambda uri: opened.append(uri)
targets = [0,count] if sys.argv[2] == 'benchmark' else [0,399,400,401,799,800,801,count]
window._wanted = None
deadline = time.monotonic()+580
stopped = False
screenshot = Path(sys.argv[1]).parent / 'actual-tk.png'
def callback_error(kind, value, trace):
    import traceback
    print(json.dumps({'result':{'status':'failed'},'error':''.join(traceback.format_exception(kind,value,trace)),
                      'phase':window.phase.get()}), flush=True)
    gate.set()
    window._on_close()
root.report_callback_exception = callback_error
def drive():
    global stopped
    assert time.monotonic() < deadline, window.phase.get()
    assert not window.phase.get().startswith('失败'), window.phase.get()
    if committed == count and not stopped:
        # 真 Tk Button 回调；停止门禁立即拒绝新外力，重复点击幂等。
        window.stop.invoke()
        window._request_stop()
        assert window.control.stop_requested and not window.session.cancelled.is_set()
        assert not window.session.request(1.)
        stopped = True
        gate.set()
    if window._verified is not None:
        assert window._final_count == count
        assert int(window.replay.cget('to')) == count
        assert window._verified.metadata['termination']['terminal_time_s'] == terminal_frame.t_after_s
        if targets and (window._wanted is None or (shown and shown[-1]['step'] == window._wanted)):
            k = targets.pop(0)
            window._wanted = k
            window.seek_value.set(str(k))
            window._seek_exact()
        elif not targets and shown and shown[-1]['step'] == count:
            assert shown[-1]['state'] == list(terminal_frame.observation_after)
            assert len(window._verified._cache) <= 2 and len(window.messages) <= 64
            window._open_charts()
            root.update_idletasks()
            ImageGrab.grab(bbox=(root.winfo_rootx(), root.winfo_rooty(),
                                root.winfo_rootx()+root.winfo_width(),
                                root.winfo_rooty()+root.winfo_height())).save(screenshot)
            result = {'status':'complete','run_dir':str(window._verified.path),
                      'backend':{'pid':os.getpid()}}
            disk_stop.set()
            disk_thread.join()
            final_bytes = disk_size()
            stats = {'peak_rss_bytes':peak_rss(), 'python_peak_bytes':tracemalloc.get_traced_memory()[1],
                     'final_disk_bytes':final_bytes, 'sampled_peak_disk_bytes':max(disk_peak,final_bytes),
                     'segment_count':window._verified.metadata['segment_count'],
                     'cache_blocks':len(window._verified._cache),'mailbox':len(window.messages),
                     'phase_memory':phase_memory,'python_current_bytes':tracemalloc.get_traced_memory()[0]}
            (Path(sys.argv[1]).parent/'storage-stats.json').write_text(json.dumps(stats))
            print(json.dumps({'result':result,'shown':shown,'opened':opened,
                              'screenshot':str(screenshot),'phase':window.phase.get(),
                              'stats':stats}), flush=True)
            window._on_close()
            return
    root.after(20, drive)
window.start()
root.after(20, drive)
root.mainloop()
disk_stop.set()
disk_thread.join()
assert not window._worker.is_alive() and not window._seek_worker.is_alive()
'''


def test_actual_tk_window_crosses_400_800_stops_and_seeks_1001(tmp_path):
    report = _run(tmp_path, count=1001, capacity=400, client_code=_GUI)
    assert report["result"]["status"] == "complete", report
    assert [point["step"] for point in report["shown"]][-8:] == [0,399,400,401,799,800,801,1001]
    assert len(report["opened"]) == 2
    assert "N=1001" in report["phase"]
    assert Path(report["screenshot"]).is_file()


def test_mailbox_bounds_notifications_and_preserves_terminal_latest_frame():
    window = object.__new__(CartPoleWindow)
    window.messages = deque(maxlen=64)
    window._frame_lock = threading.Lock()
    for k in range(10_000):
        window._notify("frame", {"step": k})
        window._notify("phase", k)
        window._notify("queued", 1.)
    window._notify("complete", "verified")
    window._notify("phase", "older phase")
    assert window._latest_frame == {"step":9999}
    assert len(window.messages) == 64
    assert window._terminal == ("complete", "verified")


def test_async_seek_coalesces_requests_and_old_generation_cannot_override(tmp_path):
    """可控后台屏障，不依赖拖动时序；Tk 线程不执行 reader。"""
    from test_cart_pole_lan import _profile_for
    from test_lan_continuous import _plain_deployment
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    root = tk.Tk()
    window = CartPoleWindow(root, paths["Client"])
    started, release = threading.Event(), threading.Event()
    reader_threads = []

    class Reader:
        def observation_at(self, k, *, check):
            reader_threads.append(threading.current_thread().name)
            if k == 1:
                started.set()
                assert release.wait(5)
            check()
            return {"step": k,"time_s":k*.02,"state":(0.,0.,0.,0.),
                    "ideal_state":(0.,0.,0.,0.),"status":"stable",
                    "applied_force_n":None}

    window._verified, window._final_count = Reader(), 3
    window._seek_worker = threading.Thread(target=window._read_seek, name="test-background-seek")
    window._seek_worker.start()
    try:
        window._queue_seek(1)
        assert started.wait(5)
        window._queue_seek(2)
        window._queue_seek(3)
        release.set()
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            with window._frame_lock:
                ready = window._seek_result
            if ready and ready[0] == 3:
                break
            time.sleep(.01)
        window._poll()
        assert "step=3" in window.values.get()
        assert reader_threads == ["test-background-seek", "test-background-seek"]
        window._notify("seek", (1, None, "obsolete failure"))
        window._poll()
        assert "step=3" in window.values.get() and "obsolete" not in window.detail.get()
    finally:
        window.session.close()
        window._seek_wake.set()
        window._seek_worker.join(5)
        root.destroy()
    # session 回调会保留窗口环；在 Tk 主线程、下一次建解释器前释放旧解释器。
    del window, root
    gc.collect()


def test_script_default_segment_capacity_and_explicit_finite_dispatch(monkeypatch):
    import sys

    from test_cart_pole_lan import ROOT

    from secure_control.scenarios.cart_pole import gui
    calls = []
    monkeypatch.setattr(gui, "run_window", lambda path, **kwargs: calls.append((path,kwargs)))
    for arguments in (["--segment-steps","17"], ["--finite"], ["--finite","--headless-continuous"]):
        monkeypatch.setattr(sys, "argv", ["run_cart_pole_client.py", *arguments])
        if len(arguments) == 2 and arguments[0] == "--finite":
            with pytest.raises(SystemExit) as exit_info:
                runpy.run_path(str(ROOT / "scripts/run_cart_pole_client.py"), run_name="__main__")
            assert exit_info.value.code == 2
        else:
            runpy.run_path(str(ROOT / "scripts/run_cart_pole_client.py"), run_name="__main__")
    assert [kwargs for _,kwargs in calls] == [
        {"segment_steps":17,"mode":"segmented"}, {"segment_steps":400,"mode":"finite"}]


def test_finite_window_initial_replay_remains_finite_and_stop_disabled(tmp_path):
    from test_cart_pole_lan import _profile_for
    from test_lan_continuous import _plain_deployment
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    root = tk.Tk()
    try:
        window = CartPoleWindow(root, paths["Client"], mode="finite")
        assert window.prepared.sample_count == 400
        assert str(window.stop.cget("state")) == "disabled"
        assert window._verified is None and not window.control.stop_requested
    finally:
        root.destroy()
    del window, root
    gc.collect()


_FINITE = r'''
import json, os, sys, time, tkinter as tk
from pathlib import Path
from secure_control.scenarios.cart_pole.gui import CartPoleWindow
root = tk.Tk()
window = CartPoleWindow(root, Path(sys.argv[1]), mode='finite')
deadline = time.monotonic()+100
def drive():
    assert time.monotonic() < deadline, window.phase.get()
    assert not window.phase.get().startswith('失败'), window.phase.get()
    if window._result is not None:
        assert window._final_count == 400 and int(window.replay.cget('to')) == 400
        window._replay_step('0')
        assert '初态尚无控制区间' == window.detail.get()
        window._replay_step('400')
        assert 't=8.00' in window.values.get()
        print(json.dumps({'result':{'status':'complete','run_dir':str(window._result[2]),
                                   'backend':{'pid':os.getpid()}}}),flush=True)
        window._on_close()
        return
    root.after(20,drive)
def callback_error(kind,value,trace):
    print(json.dumps({'result':{'status':'failed'},'error':str(value)}),flush=True)
    window._on_close()
root.report_callback_exception = callback_error
window.start()
root.after(20,drive)
root.mainloop()
assert not window._worker.is_alive()
'''


def test_actual_finite_window_preserves_400_step_verified_replay(tmp_path):
    report = _run(tmp_path, count=400, capacity=400, client_code=_FINITE)
    assert report["result"]["status"] == "complete"


_CLOSE = r'''
import json, sys, threading, tkinter as tk
from pathlib import Path
from secure_control.scenarios.cart_pole.gui import CartPoleWindow
root = tk.Tk()
window = CartPoleWindow(root, Path(sys.argv[1]), segment_steps=3)
replaying, release = threading.Event(), threading.Event()
original_notify = window._notify
def notify(kind,value):
    original_notify(kind,value)
    if kind == 'phase' and value == 'REPLAYING':
        replaying.set()
        assert release.wait(5)
window._notify = notify
window._confirmed_frame_original = window._confirmed_frame
def frame(record):
    window._confirmed_frame_original(record)
    if record.protocol.global_step == 2:
        window.control.request_stop()
import secure_control.scenarios.cart_pole.gui as gui
original_run = gui.run_cart_pole_segmented
def run(*args,**kwargs):
    kwargs['on_step'] = frame
    return original_run(*args,**kwargs)
gui.run_cart_pole_segmented = run
def drive():
    if replaying.is_set():
        window._on_close()
        assert window.session.cancelled.is_set() and window._closing
        release.set()
        return
    root.after(10,drive)
window.start()
root.after(10,drive)
root.mainloop()
assert not window._worker.is_alive()
print(json.dumps({'result':{'status':'cancelled'}}))
'''


def test_actual_close_during_replay_cancels_without_publishing(tmp_path):
    report = _run(tmp_path, count=3, capacity=3, client_code=_CLOSE)
    assert report["result"]["status"] == "cancelled"
    assert not list(tmp_path.rglob("run.json")) and not list(tmp_path.rglob(".incomplete-*"))


def test_many_small_segments_memory_and_disk_include_gui_reader_and_plots(tmp_path):
    """固定 L=1、10/100/1000 段实测；结构上界与原生 RSS 共同防止全 N 保留。"""
    stats = []
    for count in (10,100,1000):
        folder = tmp_path / str(count)
        folder.mkdir()
        report = _run(folder, count=count, capacity=1, mode="benchmark", client_code=_GUI)
        row = report["stats"]
        assert row["segment_count"] == count
        assert row["cache_blocks"] <= 2 and row["mailbox"] <= 64
        stats.append({"N":count, **row})
    assert stats[-1]["peak_rss_bytes"]-stats[0]["peak_rss_bytes"] < 60*1024**2
    assert stats[-1]["python_peak_bytes"]-stats[0]["python_peak_bytes"] < 12*1024**2
    assert stats[-1]["final_disk_bytes"] > stats[1]["final_disk_bytes"] > stats[0]["final_disk_bytes"]
    (tmp_path / "storage-matrix.json").write_text(json.dumps(stats, indent=2))
