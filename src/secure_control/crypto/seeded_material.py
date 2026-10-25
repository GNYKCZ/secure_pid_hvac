"""D132-7：可信dealer的HMAC种子＋校正；不改变矩阵Beaver/Protocol 2数学。"""

import hashlib
import hmac
import json
import struct
from dataclasses import dataclass, field

import numpy as np

from .matrix_beaver import matrix_shape, matrix_vector
from .secret_sharing import AdditiveShare

SEEDED_PROFILE = "control-dynamic-matrix-seeded-v1"
PREAUTHORIZED_PROFILE = "control-dynamic-matrix-preauthorized-v1"
PREAUTHORIZED_PROFILE_V2 = "control-dynamic-matrix-preauthorized-v2"
PREAUTHORIZED_PROFILES = (PREAUTHORIZED_PROFILE, PREAUTHORIZED_PROFILE_V2)
SEEDED_PROFILES = (SEEDED_PROFILE, *PREAUTHORIZED_PROFILES)
_DOMAIN = b"secure-control.seeded-material.v1\0"
_LABELS = (b"U", b"V", b"W", b"r", b"r-prime")


@dataclass(frozen=True, slots=True)
class SeededContext:
    """只含公开身份和参数；ledger按原记录声明顺序的十个字段编码。"""

    run_id: str
    session_id: str
    epoch: str
    party: int
    modulus: int
    dimensions: tuple[int, int, int]
    ledger: tuple[int, ...]
    security_parameter: int
    profile: str = SEEDED_PROFILE

    def __post_init__(self):
        if (self.profile not in SEEDED_PROFILES or any(type(v) is not str or not 1 <= len(v) <= 256 for v in
                (self.run_id,self.session_id,self.epoch))
                or type(self.party) is not int or self.party not in (0,1)
                or type(self.modulus) is not int or not 3 <= self.modulus < 1 << 256
                or type(self.dimensions) is not tuple or len(self.dimensions) != 3
                or any(type(v) is not int or v < 1 for v in self.dimensions)
                or type(self.ledger) is not tuple or len(self.ledger) != 10
                or any(type(v) is not int or v < 0 for v in self.ledger)
                or type(self.security_parameter) is not int or self.security_parameter < 1):
            raise ValueError("种子公开上下文类型/范围错误")
        n,m,p = self.dimensions
        matrix_shape(n+p,n+m,self.modulus)
        ell = self.ledger[0]
        if self.ledger != (ell,ell,ell,ell,ell,ell,2*ell,ell,2*ell,2*ell) or ell < 1:
            raise ValueError("种子首版需要同ell矩阵尺度")
        if self.modulus.bit_length()-self.security_parameter-2 <= ell:
            raise ValueError("种子截断参数范围错误")

    def digest(self):
        """UTF-8紧凑JSON数组固定顺序；q用十进制文本，所有身份均包含。"""
        value = [self.profile,self.run_id,self.session_id,self.epoch,self.party,
                 str(self.modulus),self.dimensions,self.ledger,self.security_parameter]
        return hashlib.sha256(_DOMAIN+json.dumps(value,ensure_ascii=False,
            separators=(",", ":"),allow_nan=False).encode("utf-8")).digest()


@dataclass(frozen=True, slots=True, repr=False)
class SeededPartyValues:
    """只有单方裸数值，无lifecycle、对方密钥或控制状态；repr不显示份额。"""

    u: np.ndarray = field(repr=False)
    v: np.ndarray = field(repr=False)
    w: np.ndarray | None = field(repr=False)
    truncations: tuple[tuple[int, int], ...] = field(repr=False)


def expand_residue(key, context_digest, step, label, index, modulus):
    """HMAC-SHA256拒绝采样；step:u64/index:u32/retry:u16均大端，最多256次。"""
    if (type(key) is not bytes or len(key) != 32 or type(context_digest) is not bytes
            or len(context_digest) != 32 or type(step) is not int or not 0 <= step < 1 << 64
            or type(label) is not bytes or label not in _LABELS or type(index) is not int
            or not 0 <= index < 1 << 32 or type(modulus) is not int or not 3 <= modulus < 1 << 256):
        raise ValueError("种子扩展参数错误")
    bits = modulus.bit_length()
    width, mask = (bits+7)//8, (1 << bits)-1
    prefix = _DOMAIN+context_digest+struct.pack(">Q",step)+bytes([len(label)])+label+struct.pack(">I",index)
    for retry in range(256):
        block = hmac.digest(key,prefix+struct.pack(">H",retry),"sha256")
        value = int.from_bytes(block[:width],"big") & mask
        if value < modulus:
            return value
    raise RuntimeError("种子域元素拒绝采样耗尽")


def expand_party(key, context, step):
    """只扩展本方；P2不生成dealer的W校正或有界截断明文。"""
    if type(context) is not SeededContext:
        raise TypeError("需要规范种子上下文")
    n,m,p = context.dimensions
    rows,inner = n+p,n+m
    digest = context.digest()
    def values(label,count):
        return [expand_residue(key,digest,step,label,i,context.modulus) for i in range(count)]
    u = np.array(values(b"U",rows*inner),dtype=object).reshape(rows,inner)
    v = np.array(values(b"V",inner),dtype=object).reshape(inner,1)
    w = np.array(values(b"W",rows),dtype=object).reshape(rows,1) if context.party == 0 else None
    truncations = (tuple(zip(values(b"r",n),values(b"r-prime",n),strict=True))
                   if context.party == 0 else ())
    return SeededPartyValues(u,v,w,truncations)


def dealer_corrections(keys, contexts, step, truncation):
    """dealer计算W2与原有界r/r′的第二份分享；不让独立种子冒充乘法相关性。"""
    if (type(keys) is not tuple or len(keys) != 2 or keys[0] == keys[1]
            or type(contexts) is not tuple or len(contexts) != 2
            or any(type(c) is not SeededContext for c in contexts)
            or tuple(c.party for c in contexts) != (0,1)):
        raise ValueError("dealer需要两个独立角色种子")
    left,right = contexts
    if (left.run_id,left.session_id,left.epoch,left.modulus,left.dimensions,left.ledger,left.security_parameter,left.profile) != (
            right.run_id,right.session_id,right.epoch,right.modulus,right.dimensions,right.ledger,right.security_parameter,right.profile):
        raise ValueError("dealer公开上下文不匹配")
    if (truncation.sharing.modulus,truncation.ell,truncation.security_parameter) != (
            left.modulus,left.ledger[0],left.security_parameter):
        raise ValueError("dealer截断参数不匹配")
    a,b = (expand_party(k,c,step) for k,c in zip(keys,contexts,strict=True))
    q = left.modulus
    w2 = (matrix_vector((a.u+b.u)%q,(a.v+b.v)%q,q)-a.w)%q
    result = [int(v) for v in w2.flat]
    for r1,rp1 in a.truncations:
        _,second = truncation.create_auxiliary(first_shares=(AdditiveShare(r1),AdditiveShare(rp1)))
        result.extend((second.r.value,second.r_prime.value))
    return tuple(result)
