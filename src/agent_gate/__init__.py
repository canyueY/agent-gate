# -*- coding: utf-8 -*-
"""agent-gate —— 给 LLM Agent 的工具调用装一道 fail-closed 的权限闸门。

Copyright (C) 2026 canyueY <https://github.com/canyueY>
SPDX-License-Identifier: AGPL-3.0-or-later

绝大多数 Agent 框架的工具注册表里都有一个 ``risk`` 字段，而**没有任何一处读它**：
工具一旦注册就会被无条件执行。这个包把那道缺失的闸门补上——风险分级、路径沙箱、
调用限额、确认通道、审计，全部零依赖、可注入、可测。

快速上手::

    from agent_gate import PermissionGate, PermissionSettings

    gate = PermissionGate(PermissionSettings(allowed_roots=("~/notes",)))
    decision = gate.check(my_tool, {"path": "~/notes/a.md"})
    if decision.allowed:
        run(my_tool, ...)
    elif decision.needs_confirmation:
        print(decision.model_message())   # 回给模型的一句人话
"""
from __future__ import annotations

from .gate import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_NEED_CONFIRM,
    RISK_ALIASES,
    RISK_CONFIRM,
    RISK_FORBIDDEN,
    RISK_READ_ONLY,
    VALID_DECISIONS,
    VALID_RISKS,
    Approver,
    AuditSink,
    JsonlAuditLog,
    PermissionDecision,
    PermissionGate,
    PermissionSettings,
    describe_policy,
    normalize_decision,
    normalize_risk,
    normalize_root,
    path_allowed,
    permission_settings,
)

__version__ = "0.1.0"

__all__ = [
    "Approver",
    "AuditSink",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "DECISION_NEED_CONFIRM",
    "JsonlAuditLog",
    "PermissionDecision",
    "PermissionGate",
    "PermissionSettings",
    "RISK_ALIASES",
    "RISK_CONFIRM",
    "RISK_FORBIDDEN",
    "RISK_READ_ONLY",
    "VALID_DECISIONS",
    "VALID_RISKS",
    "__version__",
    "describe_policy",
    "normalize_decision",
    "normalize_risk",
    "normalize_root",
    "path_allowed",
    "permission_settings",
]
