"""有界诊断窗口的唯一容量/版本事实；不改变业务段或材料库存。"""
from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class DiagnosticLimits:
    """固定窗口声明，分配前检查所有业务进程诊断数值缓冲硬上限。"""

    window: int
    events: int
    gc_events: int
    identities: int
    identity_bytes: int
    stream_bytes: int
    memory_limit: int
    activity_s: int
    wall_s: int
    native_s: int
    trace_schema: str
    stream_schema: str

    @property
    def segment_steps(self):
        """控制段始终400，不随诊断观察窗口变化。"""
        return 400

    @property
    def frame_rows(self):
        """两条Client连接各一份控制帧区间。"""
        return 2*self.window

    def payload(self):
        """公开限额用于新v2文件契约；旧v1不新增窗口字段。"""
        return asdict(self)


_V1 = DiagnosticLimits(400,12288,2048,416,65536,65536,1024*1024,
                       30,180,40,'control-tail-diagnostic-v1','client-stream-map-v1')
_V2 = DiagnosticLimits(2000,61440,10240,2016,2016*130,320*1024,6*1024*1024,
                       90,240,100,'control-tail-diagnostic-v2','client-stream-map-v2')


def limits_for(window=400):
    """只允许两个明确窗口，拒绝bool/未知版本和无界调用方输入。"""
    if type(window) is not int or window not in (400,2000):
        raise ValueError('诊断window必须显式400或2000')
    value = _V1 if window==400 else _V2
    if ((value.events+value.gc_events)*64+value.identity_bytes+value.stream_bytes
            > value.memory_limit):
        raise ValueError('诊断数值缓冲超出硬限额')
    return value


def artifact_limits(data, *, stream=False):
    """旧v1精确保留原边界；新v2必须带完整且一致的公开声明。"""
    schema = data.get('schema')
    for value in (_V1,_V2):
        if schema == (value.stream_schema if stream else value.trace_schema):
            if value.window!=400 and data.get('limits') != value.payload():
                raise ValueError('v2诊断limits声明不一致')
            if value.window==400 and 'limits' in data:
                raise ValueError('v1不能静默扩展limits')
            return value
    raise ValueError('不支持的诊断schema')
