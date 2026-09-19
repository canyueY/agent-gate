# -*- coding: utf-8 -*-
"""最小可运行示例：给一个假工具集装上闸门，看每条判定为什么是这个结果。

Copyright (C) 2026 canyueY <https://github.com/canyueY>
SPDX-License-Identifier: AGPL-3.0-or-later

直接跑：

    python examples/quickstart.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_gate import (  # noqa: E402
    JsonlAuditLog,
    PermissionGate,
    PermissionSettings,
    describe_policy,
)


class Tool:
    """工具替身。真实框架里的对象只要有 name / risk 就够了。"""

    def __init__(self, name: str, risk: str, group: str = "demo") -> None:
        self.name = name
        self.risk = risk
        self.group = group


class Registry:
    def __init__(self, *tools: Tool) -> None:
        self._tools = list(tools)

    def all(self):
        return list(self._tools)

    def get(self, name: str):
        return next((t for t in self._tools if t.name == name), None)


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="agent-gate-demo-"))
    notes = workdir / "notes"
    notes.mkdir()
    (notes / "todo.md").write_text("写点东西", encoding="utf-8")

    registry = Registry(
        Tool("read_file", "low"),        # 只读
        Tool("write_file", "medium"),    # 会改动本机
        Tool("run_shell", "high"),       # 明确禁止
        Tool("send_msg", "medium"),      # 会改动本机
    )

    asked: list[str] = []

    def ask_user(name: str, args: dict) -> bool | str:
        """确认通道。这里自动回答：send_msg 走免确认策略，其余问一次答否。"""
        asked.append(name)
        if name == "send_msg":
            return "在免确认名单里（演示用）"
        return False

    gate = PermissionGate(
        PermissionSettings(
            allowed_roots=(str(notes),),
            max_calls_per_minute=10,
        ),
        approver=ask_user,
        audit_sink=JsonlAuditLog(workdir / "audit.jsonl"),
    )

    calls = [
        ("read_file", {"path": str(notes / "todo.md")}),
        ("read_file", {"path": str(workdir / "outside.txt")}),   # 沙箱外
        ("write_file", {"path": str(notes / "new.md")}),
        ("send_msg", {"to": "someone", "text": "hi"}),
        ("run_shell", {"cmd": "rm -rf /"}),
        ("read_file", {"path": str(notes / "todo.md"), "api_key": "sk-secret"}),
    ]

    print(f"工作目录：{workdir}\n")
    print(f"{'工具':<12} {'risk':<10} {'决策':<13} 原因")
    print("-" * 78)
    for name, args in calls:
        tool = registry.get(name)
        decision = gate.check(tool, args, source="demo")

        # 路径沙箱是独立的一层：闸门放行了，路径仍可能越界
        if decision.allowed and "path" in args:
            path_ok = gate.check_path(args["path"])
            if not path_ok.allowed:
                decision = path_ok

        marker = "OK " if decision.allowed else "---"
        print(f"{marker}{name:<9} {decision.risk:<10} {decision.decision:<13} {decision.reason}")
        if decision.allowed:
            gate.note_call()

    print("\n" + "=" * 78)
    print("回给模型的话（不是空字符串——空结果会让模型反复重试同一个工具）：")
    d = gate.check(registry.get("write_file"), {"path": "x"})
    print("  " + d.model_message())

    print(f"\n确认通道被问了 {len(asked)} 次：{asked}")

    print("\n策略摘要（适合下发给前端设置面板，或注入提示词）：")
    policy = describe_policy(registry, gate.settings)
    for t in policy["tools"]:
        print(f"  {t['name']:<12} risk={t['risk']:<10} -> {t['decision']}")

    print(f"\n审计（JSONL，tail -f 直接能看）：")
    audit = (workdir / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    for line in audit[:3]:
        print("  " + line)
    print(f"  ... 共 {len(audit)} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
