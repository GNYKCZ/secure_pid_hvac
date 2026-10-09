"""#101：实际 Tk 三进程停止/异步回放，以及有界显示邮箱回归。"""

from __future__ import annotations

import gc
import threading
import time
import tkinter as tk
from collections import deque

import pytest
from test_cart_pole_segmented_evidence import _run

from secure_control.scenarios.cart_pole.gui import CartPoleWindow


def _test_tk_root():
    """在 Tk 主线程释放旧窗口环；单次初始化失败仍直接报告。"""
    gc.collect()
    return tk.Tk()


@pytest.fixture
def tk_root():
    """每个测试拥有自己的 Tcl 解释器，构造窗口失败也能释放 root。"""
    root = _test_tk_root()
    try:
        yield root
    finally:
        try:
            root.destroy()
        except tk.TclError as error:
            if "application has been destroyed" not in str(error):
                raise
        del root
        gc.collect()


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


@pytest.mark.integration
@pytest.mark.gui
def test_async_seek_coalesces_requests_and_old_generation_cannot_override(tmp_path, tk_root):
    """可控后台屏障，不依赖拖动时序；Tk 线程不执行 reader。"""
    from test_cart_pole_lan import _profile_for
    from test_lan_continuous import _plain_deployment
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    root = tk_root
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


@pytest.mark.integration
@pytest.mark.gui
def test_finite_window_initial_replay_remains_finite_and_stop_disabled(tmp_path, tk_root):
    from test_cart_pole_lan import _profile_for
    from test_lan_continuous import _plain_deployment
    paths = _plain_deployment(tmp_path)
    _profile_for(paths)
    root = tk_root
    try:
        window = CartPoleWindow(root, paths["Client"], mode="finite")
        assert window.prepared.sample_count == 400
        assert str(window.stop.cget("state")) == "disabled"
        assert window._verified is None and not window.control.stop_requested
    finally:
        root.destroy()
    del window, root
    gc.collect()


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


@pytest.mark.integration
@pytest.mark.gui
def test_actual_close_during_replay_cancels_without_publishing(tmp_path):
    report = _run(tmp_path, count=3, capacity=3, client_code=_CLOSE)
    assert report["result"]["status"] == "cancelled"
    assert not list(tmp_path.rglob("run.json")) and not list(tmp_path.rglob(".incomplete-*"))
