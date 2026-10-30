"""显式Client诊断的公开流计数；不保存业务内容或拥有控制/协议状态。"""
from __future__ import annotations

import os
import struct
import threading
import time

from .diagnostic_limits import limits_for

SCHEMA = 'client-stream-map-v1'
_ROW = struct.Struct('!8q')
_MAX = 2**63-1


class ClientStreamMap:
    """固定64KiB：800份两方控制帧槽，余量不作逐syscall历史。"""

    def __init__(self, *, window=400):
        self.limits = limits_for(window)
        self.buffer = bytearray(self.limits.stream_bytes)
        self.connections = []
        self.count = 0
        self.error = None

    def fail(self, kind):
        """观察故障不进入业务异常路径；第一次故障使整份映射不完整。"""
        self.error = self.error or kind

    def register(self, sock):
        """连接owner在任何应用握手前调用；每条socket只在这里查一次地址。"""
        if len(self.connections) >= 2:
            self.fail('connection_capacity')
            return sock
        try:
            local, remote = sock.getsockname(), sock.getpeername()
            if len(local) != 2 or len(remote) != 2:
                raise ValueError('仅IPv4')
            wrapped = _CountedSocket(sock,self,len(self.connections),local,remote)
            self.connections.append(wrapped)
            return wrapped
        except Exception as error:  # noqa: BLE001 - 原socket仍交给业务，不能改变业务结果。
            self.fail(type(error).__name__)
            return sock

    def begin(self, sockets, lengths, step):
        """仅原双路交换标记控制请求；所有setup/停止IO仍通过同一计数器。"""
        try:
            if type(step) is not int or not 0 <= step < self.limits.window or self.count+2 > self.limits.frame_rows:
                raise ValueError('frame_capacity')
            for sock,length in zip(sockets,lengths,strict=True):
                if (not isinstance(sock,_CountedSocket) or sock.owner is not self or sock.active is not None
                        or sock.remaining is not None or sock.header_bytes):
                    raise ValueError('anchor_unknown')
                index = self.count
                self.count += 1
                # id=2*step+connection；-1代表没有到达的完成端点/未知body长度。
                _ROW.pack_into(self.buffer,index*_ROW.size,2*step+sock.index,
                    sock.sent,length+4,-1,sock.received,-1,-1,0)
                sock.active = index
        except Exception as error:  # noqa: BLE001 - 固定槽异常不改变发送/接收。
            self.fail(type(error).__name__)

    def setup_checkpoint(self,sock):
        """仅原owner在已校验同步setup后调用；无新增IO，每连接固定一条。"""
        try:
            if (not isinstance(sock,_CountedSocket) or sock.owner is not self or sock.checkpoint is not None
                    or sock.active is not None or sock.remaining is not None or sock.header_bytes
                    or sock.received<=0 or sock.sent<=0 or threading.get_native_id()!=sock.thread):
                raise ValueError('setup_checkpoint_unproven')
            sock.checkpoint={'epoch':sock.index,'operation':'lan_setup','sequence':2,
                'contract':'validated-setup-reply-then-offline-request-v1',
                'received_bytes':sock.received,'sent_bytes':sock.sent,
                'checkpoint_ns':time.perf_counter_ns(),'next_send_enter_ns':None}
        except Exception as error:  # noqa: BLE001 - 观察失败不能改变协议结果。
            self.fail(type(error).__name__)

    def report(self):
        """退出才展开公开数字；round引用由原Client.json同step的身份表解释。"""
        rows = [list(_ROW.unpack_from(self.buffer,i*_ROW.size)) for i in range(self.count)]
        complete = (self.error is None and len(self.connections)==2
                    and all(r[3] == r[1]+r[2] and r[5] > 0 and r[6] == r[4]+4+r[5] for r in rows))
        return {'schema':self.limits.stream_schema,
            **({'limits':self.limits.payload()} if self.limits.window!=400 else {}),
            'buffer_bytes':len(self.buffer),'complete':complete,
            'error_type':self.error,'rows':rows,'row_fields':[
                'step_times_two_plus_connection','send_start','send_length','send_complete',
                'receive_start','receive_body_length','receive_complete','reserved'],
            'connections':[{'epoch':s.index,'pid':os.getpid(),'thread_id':s.thread,
                'registered_ns':s.registered_ns,'setup_checkpoint':s.checkpoint,
                'local':s.local,'remote':s.remote,'sent_bytes':s.sent,'received_bytes':s.received,
                'anchor':'application stream from connect; TCP sequence anchor still required'} for s in self.connections],
            'scope':'counts include every successful send/recv after registration; no TCP headers/body contents; frame bytes do not prove protocol validation'}


class _CountedSocket:
    """仅明文socket透明转交；计数在成功IO返回后推进，不修改socket模式。"""

    def __init__(self,sock,owner,index,local,remote):
        self.sock,self.owner,self.index = sock,owner,index
        self.local,self.remote = local,remote
        self.thread = threading.get_native_id()
        self.registered_ns = time.perf_counter_ns()
        self.sent = self.received = 0
        self.active = None
        self.checkpoint = None
        self.header = 0
        self.header_bytes = 0
        self.remaining = None

    def __getattr__(self,name):
        if name in ('sendall','recv_into','sendto','recvfrom','sendmsg','recvmsg','sendfile','makefile','detach','dup'):
            self.owner.fail('unobserved_io_path')
        return getattr(self.sock,name)

    def send(self,data,*args,**kwargs):
        if threading.get_native_id()!=self.thread or (args and args[0]) or kwargs.get('flags',0):
            self.owner.fail('concurrent_or_flagged_io')
        if self.checkpoint is not None and self.checkpoint['next_send_enter_ns'] is None:
            self.checkpoint['next_send_enter_ns']=time.perf_counter_ns()
        count = self.sock.send(data,*args,**kwargs)
        try:
            if type(count) is not int or not 0 <= count <= len(data) or self.sent > _MAX-count:
                raise ValueError('counter_overflow')
            self.sent += count
            if self.active is not None:
                row = list(_ROW.unpack_from(self.owner.buffer,self.active*_ROW.size))
                if self.sent == row[1]+row[2]:
                    row[3] = self.sent
                    _ROW.pack_into(self.owner.buffer,self.active*_ROW.size,*row)
                elif self.sent > row[1]+row[2]:
                    raise ValueError('send_boundary')
        except Exception as error:  # noqa: BLE001 - 诊断计数不阻断原事务。
            self.owner.fail(type(error).__name__)
        return count

    def recv(self,*args,**kwargs):
        data = self.sock.recv(*args,**kwargs)
        if threading.get_native_id()!=self.thread or (len(args)>1 and args[1]) or kwargs.get('flags',0):
            self.owner.fail('concurrent_or_flagged_io')
            return data
        try:
            if self.received > _MAX-len(data):
                raise ValueError('counter_overflow')
            self.received += len(data)
            # 只累加四字节长度，body仅按长度跳过，绝不保存/复制内容。
            offset = 0
            while offset < len(data):
                if self.remaining is None:
                    self.header = (self.header << 8)|data[offset]
                    self.header_bytes += 1
                    offset += 1
                    if self.header_bytes == 4:
                        self.remaining = self.header
                        if self.remaining <= 0:
                            raise ValueError('invalid_frame_length')
                        if self.active is not None:
                            row = list(_ROW.unpack_from(self.owner.buffer,self.active*_ROW.size))
                            row[5] = self.remaining
                            _ROW.pack_into(self.owner.buffer,self.active*_ROW.size,*row)
                else:
                    consumed = min(self.remaining,len(data)-offset)
                    offset += consumed
                    self.remaining -= consumed
                    if self.remaining == 0:
                        if self.active is not None:
                            row = list(_ROW.unpack_from(self.owner.buffer,self.active*_ROW.size))
                            row[6] = self.received-(len(data)-offset)
                            _ROW.pack_into(self.owner.buffer,self.active*_ROW.size,*row)
                            self.active = None
                        self.header = self.header_bytes = 0
                        self.remaining = None
        except Exception as error:  # noqa: BLE001 - 数据仍原样交给正式解帧/校验路径。
            self.owner.fail(type(error).__name__)
        return data
