# -*- coding: utf-8 -*-
"""权限闸门：风险分级 / 白黑名单 / 路径沙箱 / 调用限额 / 审计。

Copyright (C) 2026 canyueY <https://github.com/canyueY>
SPDX-License-Identifier: AGPL-3.0-or-later

为什么需要这一层
----------------
多数 Agent 框架的工具注册表里，``Tool.risk`` 之类的字段**早就定义了，却没有
任何一处读它** —— 也就是说任何工具只要注册进去就会被无条件执行。一个常驻在
桌面、又能读你屏幕、还要开始碰你文件的进程，"无条件执行"是最高危的组合。
所以能力扩张之前先把闸门装上。

三级风险与三档策略
------------------
risk（工具自己声明的性质）与 decision（当前策略下怎么处理）是**两件事**：

==============  ==========================================================
risk            含义
==============  ==========================================================
``read_only``   不对本机产生副作用（读文件/查进程/读剪贴板）。可重复执行。
``confirm``     会改动本机状态（写文件、启动程序、发消息）。执行前必须有人点头。
``forbidden``   明确禁止（如通用 shell）。
==============  ==========================================================

策略把 risk 映射成决策，可分别配置：

* ``read_only  -> allow``        默认直接放行
* ``confirm    -> need_confirm`` 默认**不执行**，等确认通道
* ``forbidden  -> deny``         默认拒绝

**为什么 ``confirm`` 默认等于不执行**：如果还没有确认通道（气泡问一句
"要这么做吗"），把 need_confirm 当成"先跑了再说"就等于没有闸门；当成"拒绝并
把原因回给模型"才是诚实的 —— 模型会知道该请用户确认，而不是静默失败。
等确认通道就绪，只需给 :class:`PermissionGate` 传一个 ``approver``。

为什么 fail closed
------------------
``allowed_roots`` 为空时**任何路径都不放行**（而不是"默认放开整盘"）。
配错一个键最多让功能不可用，不会让工具去写 C 盘 —— 这个方向的错误是可接受的。

纯函数、可测
------------
:meth:`PermissionGate.check` 不碰除只读的限额计数以外的状态，
时间与限额都支持注入，所以限流不用 ``sleep`` 就能测。
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

__all__ = [
    "DECISION_ALLOW",
    "DECISION_DENY",
    "DECISION_NEED_CONFIRM",
    "RISK_ALIASES",
    "RISK_CONFIRM",
    "RISK_FORBIDDEN",
    "RISK_READ_ONLY",
    "VALID_DECISIONS",
    "VALID_RISKS",
    "AuditSink",
    "JsonlAuditLog",
    "PermissionDecision",
    "PermissionGate",
    "PermissionSettings",
    "describe_policy",
    "normalize_decision",
    "normalize_risk",
    "normalize_root",
    "path_allowed",
    "permission_settings",
]

# ---- 风险等级 ------------------------------------------------------------
RISK_READ_ONLY = "read_only"
RISK_CONFIRM = "confirm"
RISK_FORBIDDEN = "forbidden"

VALID_RISKS = (RISK_READ_ONLY, RISK_CONFIRM, RISK_FORBIDDEN)

# ---- 决策 ----------------------------------------------------------------
DECISION_ALLOW = "allow"
DECISION_NEED_CONFIRM = "need_confirm"
DECISION_DENY = "deny"

VALID_DECISIONS = (DECISION_ALLOW, DECISION_NEED_CONFIRM, DECISION_DENY)

# 既有注册表里 Tool.risk 的常见取值（默认 "low"）与更口语化的别名 -> 三级风险。
# 保留别名是为了**不破坏已有注册表**：现成的 web 工具都是 risk="low"，
# 归一到 read_only 后行为与闸门装上之前完全一致。
RISK_ALIASES: dict[str, str] = {
    "low": RISK_READ_ONLY,
    "safe": RISK_READ_ONLY,
    "read": RISK_READ_ONLY,
    "readonly": RISK_READ_ONLY,
    "read_only": RISK_READ_ONLY,
    "medium": RISK_CONFIRM,
    "mid": RISK_CONFIRM,
    "write": RISK_CONFIRM,
    "confirm": RISK_CONFIRM,
    "high": RISK_FORBIDDEN,
    "danger": RISK_FORBIDDEN,
    "dangerous": RISK_FORBIDDEN,
    "forbidden": RISK_FORBIDDEN,
    "deny": RISK_FORBIDDEN,
}


def normalize_risk(value: Any) -> str:
    """把任意写法归一到三级风险。

    认不出来的一律归为 **confirm**（而不是 read_only）：未知风险按"要确认"
    处理，才不会因为写错一个字符串就把一个新工具当成只读放行。
    """
    s = str(value or "").strip().lower()
    if not s:
        return RISK_CONFIRM
    if s in VALID_RISKS:
        return s
    return RISK_ALIASES.get(s, RISK_CONFIRM)


def normalize_decision(value: Any, default: str) -> str:
    s = str(value or "").strip().lower()
    if s in VALID_DECISIONS:
        return s
    # 允许 JSON/YAML 里用布尔图省事：true=allow / false=deny
    if isinstance(value, bool):
        return DECISION_ALLOW if value else DECISION_DENY
    return default


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------


@dataclass
class PermissionSettings:
    """权限策略。

    可以直接构造，也可以用 :func:`permission_settings` 从配置 dict 读。
    """

    enable: bool = True
    # risk -> decision
    read_only: str = DECISION_ALLOW
    confirm: str = DECISION_NEED_CONFIRM
    forbidden: str = DECISION_DENY
    # 工具级覆盖：先看 deny_tools，再看 allow_tools
    allow_tools: tuple[str, ...] = ()
    deny_tools: tuple[str, ...] = ()
    # 路径沙箱。**空 = 全部拒绝**（fail closed）
    allowed_roots: tuple[str, ...] = ()
    # 每分钟调用上限（0 = 不限）
    max_calls_per_minute: int = 30
    audit: bool = True

    def decision_for_risk(self, risk: str) -> str:
        r = normalize_risk(risk)
        return {
            RISK_READ_ONLY: self.read_only,
            RISK_CONFIRM: self.confirm,
            RISK_FORBIDDEN: self.forbidden,
        }[r]


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return default if value is None else bool(value)


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(x).strip() for x in value if str(x).strip())
    if isinstance(value, str):
        return tuple(x.strip() for x in value.split(",") if x.strip())
    return ()


def permission_settings(cfg: dict[str, Any] | None = None) -> PermissionSettings:
    """从 ``{"agent": {"permissions": {...}}}`` 读设置；缺块时用**保守默认**。

    只认这一种嵌套形状是有意的：策略必须来自一个明确的位置，而不是
    "在配置树里到处找找看" —— 后者会让"我明明配了"变成排查噩梦。
    """
    block: dict[str, Any] = {}
    try:
        agent = (cfg or {}).get("agent")
        if isinstance(agent, dict) and isinstance(agent.get("permissions"), dict):
            block = dict(agent["permissions"])
    except Exception:
        block = {}

    st = PermissionSettings()
    st.enable = _as_bool(block.get("enable"), True)
    st.read_only = normalize_decision(block.get("read_only"), DECISION_ALLOW)
    st.confirm = normalize_decision(block.get("confirm"), DECISION_NEED_CONFIRM)
    st.forbidden = normalize_decision(block.get("forbidden"), DECISION_DENY)
    st.allow_tools = _as_str_tuple(block.get("allow_tools"))
    st.deny_tools = _as_str_tuple(block.get("deny_tools"))
    st.allowed_roots = _as_str_tuple(block.get("allowed_roots"))
    try:
        st.max_calls_per_minute = max(0, int(block.get("max_calls_per_minute", 30)))
    except (TypeError, ValueError):
        st.max_calls_per_minute = 30
    st.audit = _as_bool(block.get("audit"), True)
    return st


# ---------------------------------------------------------------------------
# 路径沙箱
# ---------------------------------------------------------------------------


def normalize_root(root: str | os.PathLike[str]) -> str:
    """把允许根目录规范化成可比较的绝对真实路径（展开 ~ 与相对路径）。"""
    p = os.path.expanduser(str(root))
    if not os.path.isabs(p):
        # 相对路径按**当前工作目录**解析：配 "data/agent" 这种最自然
        p = os.path.join(os.getcwd(), p)
    try:
        return os.path.realpath(p)
    except OSError:
        return os.path.abspath(p)


def path_allowed(
    path: str | os.PathLike[str], roots: Sequence[str] | None
) -> tuple[bool, str]:
    """判断路径是否落在允许的根目录内。返回 ``(是否允许, 原因)``。

    用 ``realpath`` 先解析再比较，所以 ``..`` 穿越与**符号链接逃逸**都会被
    拦下（比较的是解析后的真实路径，不是字面路径）。

    刻意**不**对不存在的路径放行：读文件的工具要读的东西必须真实存在；
    判断"将要创建的文件"时调用方应传其父目录。
    """
    roots = tuple(roots or ())
    if not roots:
        return False, "未配置允许目录（allowed_roots 为空，按 fail closed 拒绝）"
    if path is None or str(path).strip() == "":
        return False, "路径为空"
    raw = os.path.expanduser(str(path))
    try:
        target = os.path.realpath(raw)
    except OSError:
        target = os.path.abspath(raw)
    for root in roots:
        base = normalize_root(root)
        if target == base:
            return True, ""
        # 用 commonpath 而不是 str.startswith：后者会把 /data2 误判为在 /data 内
        try:
            if os.path.commonpath([target, base]) == base:
                return True, ""
        except ValueError:
            # 不同盘符（Windows）会抛 ValueError -> 显然不在同一根内
            continue
    return False, f"路径不在允许目录内：{target}"


# ---------------------------------------------------------------------------
# 审计
# ---------------------------------------------------------------------------


class AuditSink:
    """审计落地接口。

    只需要实现 :meth:`write`。判定本身**不依赖**审计是否成功——
    审计写失败不该让工具调用失败（那是可用性问题），但也不该静默：
    实现里请自己记日志。
    """

    def write(self, record: dict[str, Any]) -> None:  # pragma: no cover - 接口
        raise NotImplementedError


class JsonlAuditLog(AuditSink):
    """把每条判定追加成一行 JSON（JSONL）。

    选 JSONL 而不是 SQLite：追加是一行一次 ``write``，进程被强杀也不会留下
    半个数据库；而且 ``tail -f`` 直接能看。

    :param path: 目标文件；父目录会自动创建
    :param max_bytes: 超过就轮转一次为 ``<path>.1``（只留一代，够用且不会无限增长）
    """

    def __init__(self, path: str | os.PathLike[str], *, max_bytes: int = 8 << 20) -> None:
        self.path = str(path)
        self.max_bytes = int(max_bytes)
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return  # 还不存在
        try:
            os.replace(self.path, self.path + ".1")
        except OSError:
            pass  # 轮转失败也要继续写：宁可文件变大也不要丢审计

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            self._rotate_if_needed()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)


# ---------------------------------------------------------------------------
# 决策
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionDecision:
    """一次权限判定的结果。"""

    decision: str
    risk: str
    reason: str
    tool: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == DECISION_ALLOW

    @property
    def needs_confirmation(self) -> bool:
        return self.decision == DECISION_NEED_CONFIRM

    def model_message(self) -> str:
        """回给模型的话。

        为什么要给模型一句人话而不是空字符串：模型收到空结果会反复重试同一个
        工具（实测的 Agent 通病）。明确告诉它"需要用户确认，先别调"，
        它才会换办法或直接开口问用户。
        """
        if self.allowed:
            return "已允许执行。"
        if self.decision == DECISION_NEED_CONFIRM:
            return (
                f"工具 {self.tool} 会改动本机状态，需要用户确认后才能执行；"
                f"本轮**未执行**。请先向用户说明你要做什么并征求同意，不要重试。"
                f"（原因：{self.reason}）"
            )
        return (
            f"工具 {self.tool} 被权限策略拒绝，本轮**未执行**，"
            f"请改用其他办法或直接告诉用户。（原因：{self.reason}）"
        )

    def as_dict(self) -> dict[str, Any]:
        """转成可 JSON 化的字典（审计用）。"""
        return {
            "tool": self.tool,
            "risk": self.risk,
            "decision": self.decision,
            "reason": self.reason,
        }


#: ``approver(tool_name, args)`` 的返回值：
#: ``True`` / 非空字符串 = 放行（字符串会作为放行理由写进审计），
#: ``False`` / 空字符串 = 不同意。
Approver = Callable[[str, dict[str, Any]], "bool | str"]


class PermissionGate:
    """把 risk + 策略 + 限额 + 沙箱合成一个可测的判定器。

    ``approver`` 是确认通道的注入点：签名 ``(tool_name, args) -> bool | str``。
    不传（``None``）→ ``confirm`` 一律判为"需要确认但不执行"。
    接上气泡确认后，只需在构造时传一个 approver，闸门本身不用改。

    ``audit_sink`` 是可选的审计落地（见 :class:`JsonlAuditLog`）；
    只有 ``settings.audit`` 为真且传了 sink 时才写。

    :param settings: 策略；缺省即默认策略
    :param approver: 确认通道
    :param audit_sink: 审计落地
    :param clock: 单调时钟注入点，便于测试限流而不 sleep
    """

    def __init__(
        self,
        settings: PermissionSettings | None = None,
        *,
        approver: Approver | None = None,
        audit_sink: AuditSink | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.settings = settings or PermissionSettings()
        self.approver = approver
        self.audit_sink = audit_sink
        self._clock = clock or time.monotonic
        self._stamps: list[float] = []

    # ---- 限额 ----
    def _prune(self, now: float) -> None:
        cutoff = now - 60.0
        self._stamps = [t for t in self._stamps if t > cutoff]

    def recent_calls(self, now: float | None = None) -> int:
        now = self._clock() if now is None else now
        self._prune(now)
        return len(self._stamps)

    def _under_quota(self, now: float) -> bool:
        limit = self.settings.max_calls_per_minute
        if limit <= 0:
            return True
        return self.recent_calls(now) < limit

    def note_call(self, now: float | None = None) -> None:
        """真执行了才记账（先问后记：被拒的调用不该占用配额）。"""
        now = self._clock() if now is None else now
        self._prune(now)
        self._stamps.append(now)

    # ---- 审计 ----
    def _audit(
        self,
        decision: PermissionDecision,
        *,
        source: str,
        args: dict[str, Any] | None,
    ) -> None:
        if not (self.settings.audit and self.audit_sink is not None):
            return
        record = {
            "ts": time.time(),
            "source": source,
            "args": _safe_args(args),
            **decision.as_dict(),
        }
        try:
            self.audit_sink.write(record)
        except Exception:
            # 审计失败不能反过来让调用失败；但也不吞掉——交给 sink 自己记日志。
            # 这里保持静默是为了不把可用性问题升级成崩溃。
            pass

    # ---- 主判定 ----
    def check(
        self,
        tool: Any,
        args: dict[str, Any] | None = None,
        *,
        source: str = "chat",
        now: float | None = None,
    ) -> PermissionDecision:
        """判定一次工具调用。``tool`` 可以是对象（读 ``.name`` / ``.risk``）或裸名字。"""
        name = str(getattr(tool, "name", tool) or "").strip()
        risk = normalize_risk(getattr(tool, "risk", None))

        if not self.settings.enable:
            # 闸门整体关闭：**全部放行**是刻意的 —— 这个开关存在的意义是
            # "我现在不想被闸门挡着调试"，而不是"关掉就等于没风险"。
            result = PermissionDecision(
                DECISION_ALLOW, risk, "权限闸门已关闭", name
            )
            self._audit(result, source=source, args=args)
            return result

        if name in self.settings.deny_tools:
            result = PermissionDecision(
                DECISION_DENY, risk, "工具在 deny_tools 名单里", name
            )
            self._audit(result, source=source, args=args)
            return result

        now = self._clock() if now is None else now
        if not self._under_quota(now):
            result = PermissionDecision(
                DECISION_DENY,
                risk,
                f"每分钟调用上限已用尽（{self.settings.max_calls_per_minute} 次/分钟）",
                name,
            )
            self._audit(result, source=source, args=args)
            return result

        # 工具级放行名单可以**提升**风险等级的处理方式（例如把某个写工具
        # 标成 allow 以便无人值守），这是显式的管理员决定，所以要留审计。
        if name in self.settings.allow_tools:
            base = DECISION_ALLOW
            reason = "工具在 allow_tools 名单里（显式放行）"
        else:
            base = self.settings.decision_for_risk(risk)
            reason = f"risk={risk} 的策略为 {base}"

        if base == DECISION_ALLOW:
            result = PermissionDecision(DECISION_ALLOW, risk, reason, name)
        elif base == DECISION_NEED_CONFIRM:
            result = self._ask_approver(name, risk, args)
        else:
            result = PermissionDecision(DECISION_DENY, risk, reason, name)

        self._audit(result, source=source, args=args)
        return result

    def _ask_approver(
        self, name: str, risk: str, args: dict[str, Any] | None
    ) -> PermissionDecision:
        if self.approver is None:
            return PermissionDecision(
                DECISION_NEED_CONFIRM, risk, "尚无确认通道，confirm 一律不执行", name
            )
        try:
            verdict = self.approver(name, dict(args or {}))
        except Exception as exc:  # 确认通道坏了 -> 不执行
            return PermissionDecision(
                DECISION_NEED_CONFIRM, risk, f"确认通道异常：{exc}", name
            )
        # approver 可以返回 bool，也可以返回**原因字符串**（非空即放行）。
        # 后者用于"免确认"这类策略性放行 —— 让理由如实写进审计，
        # 而不是一律记成"用户已确认"（那会让审计看不出到底问没问过）。
        if isinstance(verdict, str):
            text = verdict.strip()
            if text:
                return PermissionDecision(DECISION_ALLOW, risk, text, name)
            return PermissionDecision(DECISION_NEED_CONFIRM, risk, "用户未同意", name)
        if verdict:
            return PermissionDecision(DECISION_ALLOW, risk, "用户已确认", name)
        return PermissionDecision(DECISION_NEED_CONFIRM, risk, "用户未同意", name)

    # ---- 路径沙箱的便捷入口 ----
    def check_path(self, path: str | os.PathLike[str]) -> PermissionDecision:
        """按 ``allowed_roots`` 判定一个路径。永远是 read_only 语义。"""
        ok, why = path_allowed(path, self.settings.allowed_roots)
        result = PermissionDecision(
            DECISION_ALLOW if ok else DECISION_DENY,
            RISK_READ_ONLY,
            why or "路径在允许目录内",
            "path",
        )
        self._audit(result, source="path", args={"path": str(path)})
        return result


_SENSITIVE_KEYS = ("key", "token", "secret", "password", "passwd", "cookie", "auth")


def _safe_args(args: dict[str, Any] | None, *, limit: int = 2000) -> Any:
    """审计前对参数做脱敏 + 限长。

    审计的价值在于**事后能看出发生了什么**，而不是把 API key 抄进日志文件。
    """
    if not args:
        return {}
    out: dict[str, Any] = {}
    for k, v in list(args.items())[:40]:
        if any(s in str(k).lower() for s in _SENSITIVE_KEYS):
            out[k] = "***"
        elif isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        else:
            out[k] = f"<{type(v).__name__}>"
    try:
        if len(json.dumps(out, ensure_ascii=False, default=str)) > limit:
            return {"_truncated": True, "_keys": sorted(out)[:40]}
    except Exception:
        return {"_unserialisable": True}
    return out


# ---------------------------------------------------------------------------
# 给后台 / 提示词用的策略说明
# ---------------------------------------------------------------------------


def describe_policy(
    registry: Any = None,
    settings: PermissionSettings | None = None,
) -> dict[str, Any]:
    """把策略与工具清单摊平成可下发/可展示的结构。

    ``registry`` 只需要有一个 ``all()`` 方法（返回带 ``name`` / ``risk`` /
    ``group`` 属性的对象），不绑定任何具体框架。
    """
    st = settings or PermissionSettings()
    tools: list[dict[str, Any]] = []
    for tool in (registry.all() if registry is not None else []):
        risk = normalize_risk(getattr(tool, "risk", None))
        if not st.enable:
            decision = DECISION_ALLOW
        elif getattr(tool, "name", "") in st.deny_tools:
            decision = DECISION_DENY
        elif getattr(tool, "name", "") in st.allow_tools:
            decision = DECISION_ALLOW
        else:
            decision = st.decision_for_risk(risk)
        tools.append(
            {
                "name": getattr(tool, "name", ""),
                "group": getattr(tool, "group", ""),
                "risk": risk,
                "decision": decision,
            }
        )
    return {
        "enable": st.enable,
        "read_only": st.read_only,
        "confirm": st.confirm,
        "forbidden": st.forbidden,
        "allow_tools": list(st.allow_tools),
        "deny_tools": list(st.deny_tools),
        "allowed_roots": list(st.allowed_roots),
        "max_calls_per_minute": st.max_calls_per_minute,
        "audit": st.audit,
        "tools": tools,
    }
