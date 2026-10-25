"""D128-1 / 2026论文§2.2：一次性矩阵乘列向量，party0独占公开交叉项。"""

from dataclasses import dataclass, field
from numbers import Integral

import numpy as np

from .beaver import _TripleLifecycle
from .secret_sharing import AdditiveShare, TwoPartySharing


def matrix_shape(rows, inner, modulus):
    """先检查公开尺寸/预算，再允许分配或生成随机材料。"""
    if any(type(v) is not int or v < 1 for v in (rows, inner, modulus)) or modulus < 3:
        raise ValueError("矩阵尺寸与模数必须为严格正整数")
    if (rows * inner + inner + rows) * ((modulus.bit_length() + 7) // 8) > 512 * 1024:
        raise ValueError("矩阵材料超过单轮公开预算")
    return (rows, inner), (inner, 1), (rows, 1)


def matrix_values(value, shape, modulus):
    """只接收精确二维canonical整数；无广播、浮点或隐式列向量转换。"""
    if not isinstance(value, AdditiveShare):
        raise TypeError("需要单方AdditiveShare")
    array = np.asarray(value.value, dtype=object)
    if array.shape != shape or array.ndim != 2:
        raise ValueError("矩阵份额shape错误")
    for item in array.flat:
        if isinstance(item, bool) or not isinstance(item, Integral):
            raise TypeError("矩阵元素必须是非bool整数")
        if not 0 <= item < modulus:
            raise ValueError("矩阵元素不是canonical residue")
    return array


def _standard_share_arrays(sharing, *shares):
    """仅分流当前已校验操作数；非标准表示/子类继续走原通用接口。"""
    return type(sharing) is TwoPartySharing and all(
        type(share) is AdditiveShare and type(share.value) is np.ndarray
        and share.value.dtype == object and all(type(item) is int for item in share.value.flat)
        for share in shares)


def matrix_vector(left, right, modulus):
    """明确的任意精度mod-q乘加，绝不借用逐元素multiply_public。"""
    rows, inner = left.shape
    if right.shape != (inner, 1):
        raise ValueError("矩阵乘列向量尺寸不匹配")
    return np.array([[sum(int(left[i, j]) * int(right[j, 0])
                          for j in range(inner)) % modulus] for i in range(rows)], dtype=object)


@dataclass(frozen=True, slots=True)
class MatrixTripleShare:
    """仅单方U/V/W份额；不包含对方秘密或完整材料。"""

    u: AdditiveShare
    v: AdditiveShare
    w: AdditiveShare
    party_index: int
    rows: int
    inner: int
    _lifecycle: _TripleLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class MatrixMaskedShare:
    """本方E_i/F_i，仅可与同操作的互补方打开。"""

    e: AdditiveShare
    f: AdditiveShare
    party_index: int
    _lifecycle: _TripleLifecycle = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class MatrixPublicMasks:
    """已打开的E/F；仅绑定当前矩阵triple生命周期。"""

    e: np.ndarray
    f: np.ndarray
    _lifecycle: _TripleLifecycle = field(repr=False, compare=False)


class MatrixBeaverMultiplier:
    """复用分享随机源，保持标量Beaver独立且仍拒绝数组。"""

    def __init__(self, sharing: TwoPartySharing):
        self.sharing = sharing

    def create_triple(self, rows, inner, *, rng=None):
        """独立抽取U/V，每步新鲜；W=UV，三者分别独立分享。"""
        us, vs, _ = matrix_shape(rows, inner, self.sharing.modulus)
        def sample(shape):
            return np.array([self.sharing._random_residue(rng) for _ in range(shape[0] * shape[1])],
                            dtype=object).reshape(shape)
        u, v = sample(us), sample(vs)
        w = matrix_vector(u, v, self.sharing.modulus)
        pairs = [self.sharing.share(value, rng=rng) for value in (u, v, w)]
        lifecycle = _TripleLifecycle(self)
        return tuple(MatrixTripleShare(*(pair[i] for pair in pairs), i, rows, inner, lifecycle)
                     for i in (0, 1))

    def _validate(self, triple):
        if type(triple) is not MatrixTripleShare or triple._lifecycle.owner is not self:
            raise ValueError("矩阵材料owner/type不匹配")
        if type(triple.party_index) is not int or triple.party_index not in (0, 1):
            raise ValueError("矩阵材料角色错误")
        shapes = matrix_shape(triple.rows, triple.inner, self.sharing.modulus)
        for value, shape in zip((triple.u, triple.v, triple.w), shapes, strict=True):
            matrix_values(value, shape, self.sharing.modulus)
        return shapes

    def mask_inputs(self, matrix, vector, triple):
        """先校验再领取；一旦开始mask，即使后续传输失败也不得复用。"""
        us, vs, _ = self._validate(triple)
        matrix_values(matrix, us, self.sharing.modulus)
        matrix_values(vector, vs, self.sharing.modulus)
        triple._lifecycle.claim_masking(triple.party_index)
        # 保留原校验/claim顺序，只省去通用入口对标准数组的重复校验副本。
        # 原内核仍新建结果、逐项用Python整数模减；异常不回退、不归还已领取材料。
        if _standard_share_arrays(self.sharing, matrix, triple.u, vector, triple.v):
            e = AdditiveShare(self.sharing._combine_values(matrix.value, triple.u.value, lambda a,b: a-b))
            f = AdditiveShare(self.sharing._combine_values(vector.value, triple.v.value, lambda a,b: a-b))
        else:
            e = self.sharing.subtract(matrix, triple.u)
            f = self.sharing.subtract(vector, triple.v)
        return MatrixMaskedShare(e, f, triple.party_index, triple._lifecycle)

    def open_masked_differences(self, first, second):
        """仅重构掩码，互补方与相同本地操作令牌必需。"""
        if (type(first) is not MatrixMaskedShare or type(second) is not MatrixMaskedShare
                or first._lifecycle is not second._lifecycle
                or first._lifecycle.owner is not self
                or type(first.party_index) is not int or type(second.party_index) is not int
                or {first.party_index, second.party_index} != {0, 1}):
            raise ValueError("矩阵mask身份不匹配")
        lifecycle = first._lifecycle
        shape = np.asarray(first.e.value, dtype=object).shape
        if len(shape) != 2:
            raise ValueError("矩阵mask必须二维")
        us, vs, _ = matrix_shape(*shape, self.sharing.modulus)
        for item in (first, second):
            matrix_values(item.e, us, self.sharing.modulus)
            matrix_values(item.f, vs, self.sharing.modulus)
        # 对端及本方每次都重新完整校验，资格判断不缓存先前调用的有效性。
        if _standard_share_arrays(self.sharing, first.e, second.e, first.f, second.f):
            e = self.sharing._combine_values(first.e.value, second.e.value, lambda a,b: a+b)
            f = self.sharing._combine_values(first.f.value, second.f.value, lambda a,b: a+b)
        else:
            e = self.sharing.reconstruct(first.e, second.e)
            f = self.sharing.reconstruct(first.f, second.f)
        if e.ndim != 2 or f.shape != (e.shape[1], 1):
            raise ValueError("矩阵公开mask尺寸错误")
        lifecycle.claim_opening()
        return MatrixPublicMasks(e, f, lifecycle)

    def finish(self, triple, opened):
        """W_i+U_iF+EV_i+[i=0]EF；公开项恰好一次。"""
        us, vs, _ = self._validate(triple)
        if (type(opened) is not MatrixPublicMasks or opened._lifecycle is not triple._lifecycle
                or not triple._lifecycle.opened):
            raise ValueError("矩阵公开mask不属于当前操作")
        q = self.sharing.modulus
        e = matrix_values(AdditiveShare(opened.e), us, q)
        f = matrix_values(AdditiveShare(opened.f), vs, q)
        value = (triple.w.value + matrix_vector(triple.u.value, f, q)
                 + matrix_vector(e, triple.v.value, q)) % q
        if triple.party_index == 0:
            value = (value + matrix_vector(e, f, q)) % q
        triple._lifecycle.claim_finish(triple.party_index)
        return AdditiveShare(value)


class MatrixPrefix:
    """单方一次性能力：首次前缀领取原triple，后缀仍消费同一owner/token。"""

    def __init__(self, multiplier, triple, matrix, state):
        us, _, _ = multiplier._validate(triple)
        q = multiplier.sharing.modulus
        matrix_values(matrix, us, q)
        state_array = np.asarray(state.value, dtype=object)
        n = state_array.shape[0] if state_array.ndim == 2 else 0
        if not 0 < n < triple.inner:
            raise ValueError("前缀状态维度错误")
        matrix_values(state, (n, 1), q)
        triple._lifecycle.claim_masking(triple.party_index)
        self.owner, self.triple, self.n = multiplier, triple, n
        self.e_share = (matrix.value-triple.u.value) % q
        self.fx_share = (state_array-triple.v.value[:n]) % q
        self.phase = "prefix_sent"

    def open_prefix(self, peer_e, peer_fx):
        if self.phase != "prefix_sent":
            raise ValueError("前缀只能打开一次")
        self.phase = "terminal"
        t, q = self.triple, self.owner.sharing.modulus
        matrix_values(peer_e, (t.rows, t.inner), q)
        matrix_values(peer_fx, (self.n, 1), q)
        t._lifecycle.claim_masking(1-t.party_index)
        e = (self.e_share+peer_e.value) % q
        fx = (self.fx_share+peer_fx.value) % q
        self.l = (t.u.value+(e if t.party_index == 0 else 0)) % q
        self.h = (matrix_vector(e, t.v.value, q)+matrix_vector(self.l[:, :self.n], fx, q)) % q
        self.phase = "prefix_opened"

    def bind(self, w):
        if self.phase != "prefix_opened":
            raise ValueError("前缀已绑定或废弃")
        self.phase = "terminal"
        t = self.triple
        matrix_values(w, (t.rows, 1), self.owner.sharing.modulus)
        self.triple = MatrixTripleShare(t.u, t.v, w, t.party_index, t.rows, t.inner, t._lifecycle)
        self.phase = "bound"
        return self.triple

    def mask_suffix(self, value):
        if self.phase != "bound":
            raise ValueError("后缀只能开始一次")
        self.phase = "suffix_sent"
        q, t = self.owner.sharing.modulus, self.triple
        matrix_values(value, (t.inner-self.n, 1), q)
        self.fv_share = (value.value-t.v.value[self.n:]) % q
        return AdditiveShare(self.fv_share)

    def finish(self, peer_fv):
        if self.phase != "suffix_sent":
            raise ValueError("后缀未开始或已完成")
        self.phase = "terminal"
        t, q = self.triple, self.owner.sharing.modulus
        matrix_values(peer_fv, (t.inner-self.n, 1), q)
        fv = (self.fv_share+peer_fv.value) % q
        t._lifecycle.claim_opening()
        value = (t.w.value+self.h+matrix_vector(self.l[:, self.n:], fv, q)) % q
        t._lifecycle.claim_finish(t.party_index)
        self.phase = "locally_finished"
        return AdditiveShare(value)

    def abort(self):
        self.phase = "terminal"
