# -*- coding: utf-8 -*-
"""权限闸门测试。

Copyright (C) 2026 canyueY <https://github.com/canyueY>
SPDX-License-Identifier: AGPL-3.0-or-later

重点覆盖那些"配错了也不会报错、但会让闸门形同虚设"的地方：
未知 risk 的归属、空 allowed_roots 的语义、符号链接逃逸、限额是先问后记。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_gate import (  # noqa: E402
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_NEED_CONFIRM,
    RISK_CONFIRM,
    RISK_FORBIDDEN,
    RISK_READ_ONLY,
    JsonlAuditLog,
    PermissionGate,
    PermissionSettings,
    describe_policy,
    normalize_decision,
    normalize_risk,
    normalize_root,
    path_allowed,
    permission_settings,
)


class Tool:
    """最小工具替身：只需要 name / risk / group。"""

    def __init__(self, name: str, risk: str = "low", group: str = "test") -> None:
        self.name = name
        self.risk = risk
        self.group = group


class Registry:
    def __init__(self, *tools: Tool) -> None:
        self._tools = list(tools)

    def all(self):
        return list(self._tools)


class FakeClock:
    """可手动推进的单调时钟，用来测限流而不 sleep。"""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# ---------------------------------------------------------------------------
# risk 归一
# ---------------------------------------------------------------------------


class TestNormalizeRisk:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("read_only", RISK_READ_ONLY),
            ("confirm", RISK_CONFIRM),
            ("forbidden", RISK_FORBIDDEN),
            ("low", RISK_READ_ONLY),
            ("safe", RISK_READ_ONLY),
            ("read", RISK_READ_ONLY),
            ("readonly", RISK_READ_ONLY),
            ("medium", RISK_CONFIRM),
            ("mid", RISK_CONFIRM),
            ("write", RISK_CONFIRM),
            ("high", RISK_FORBIDDEN),
            ("danger", RISK_FORBIDDEN),
            ("dangerous", RISK_FORBIDDEN),
            ("deny", RISK_FORBIDDEN),
        ],
    )
    def test_known_values_map(self, raw, expected):
        assert normalize_risk(raw) == expected

    def test_case_and_whitespace_insensitive(self):
        assert normalize_risk("  READ_ONLY  ") == RISK_READ_ONLY
        assert normalize_risk("Low") == RISK_READ_ONLY

    @pytest.mark.parametrize("raw", [None, "", "   ", "whatever", 42, [], {}])
    def test_unknown_falls_back_to_confirm_not_read_only(self, raw):
        # 关键安全属性：写错一个字符串不能把新工具当成只读放行
        assert normalize_risk(raw) == RISK_CONFIRM

    def test_normalize_risk_wants_the_value_not_the_object(self):
        # normalize_risk 收的是 risk **值**；对象由 gate.check 负责解包。
        # 传对象进去会被 str() 成一个认不出的字符串 -> 保守归为 confirm。
        # 这里把这个边界钉住：不要把 Tool 对象喂给 normalize_risk。
        assert normalize_risk(Tool("t", "high").risk) == RISK_FORBIDDEN
        assert normalize_risk(Tool("t", "high")) == RISK_CONFIRM

    def test_gate_unpacks_tool_object(self):
        assert PermissionGate().check(Tool("t", "high")).decision == DECISION_DENY


class TestNormalizeDecision:
    def test_valid_values_pass_through(self):
        for d in (DECISION_ALLOW, DECISION_NEED_CONFIRM, DECISION_DENY):
            assert normalize_decision(d, DECISION_DENY) == d

    def test_bool_shorthand(self):
        assert normalize_decision(True, DECISION_DENY) == DECISION_ALLOW
        assert normalize_decision(False, DECISION_ALLOW) == DECISION_DENY

    def test_garbage_uses_default(self):
        assert normalize_decision("nope", DECISION_DENY) == DECISION_DENY
        assert normalize_decision(None, DECISION_ALLOW) == DECISION_ALLOW


# ---------------------------------------------------------------------------
# 配置解析
# ---------------------------------------------------------------------------


class TestPermissionSettings:
    def test_defaults_are_conservative(self):
        st = PermissionSettings()
        assert st.enable is True
        assert st.read_only == DECISION_ALLOW
        assert st.confirm == DECISION_NEED_CONFIRM
        assert st.forbidden == DECISION_DENY
        assert st.allowed_roots == ()
        assert st.max_calls_per_minute == 30

    def test_reads_nested_block(self):
        cfg = {
            "agent": {
                "permissions": {
                    "read_only": "deny",
                    "confirm": "allow",
                    "forbidden": "allow",
                    "allow_tools": ["a", "b"],
                    "deny_tools": "c,d",
                    "allowed_roots": ["~/notes"],
                    "max_calls_per_minute": 5,
                    "audit": False,
                }
            }
        }
        st = permission_settings(cfg)
        assert st.read_only == DECISION_DENY
        assert st.confirm == DECISION_ALLOW
        assert st.forbidden == DECISION_ALLOW
        assert st.allow_tools == ("a", "b")
        assert st.deny_tools == ("c", "d")  # 逗号串也认
        assert st.allowed_roots == ("~/notes",)
        assert st.max_calls_per_minute == 5
        assert st.audit is False

    @pytest.mark.parametrize(
        "cfg",
        [
            None,
            {},
            {"agent": None},
            {"agent": {"permissions": None}},
            {"agent": "not-a-dict"},
            {"agent": {"permissions": []}},
        ],
    )
    def test_missing_or_malformed_block_uses_defaults(self, cfg):
        assert permission_settings(cfg).read_only == DECISION_ALLOW

    def test_bad_int_falls_back(self):
        cfg = {"agent": {"permissions": {"max_calls_per_minute": "abc"}}}
        assert permission_settings(cfg).max_calls_per_minute == 30

    def test_negative_limit_clamped_to_zero(self):
        cfg = {"agent": {"permissions": {"max_calls_per_minute": -5}}}
        assert permission_settings(cfg).max_calls_per_minute == 0

    def test_decision_for_risk(self):
        st = PermissionSettings(read_only="deny", confirm="allow")
        assert st.decision_for_risk("low") == "deny"
        assert st.decision_for_risk("medium") == "allow"
        assert st.decision_for_risk("unknown") == "allow"  # 归一成 confirm


# ---------------------------------------------------------------------------
# 路径沙箱
# ---------------------------------------------------------------------------


class TestPathSandbox:
    def test_empty_roots_denies_everything(self, tmp_path):
        # fail closed：配置缺失时不能默认放开整盘
        ok, why = path_allowed(tmp_path / "a.txt", ())
        assert ok is False
        assert "fail closed" in why

    def test_none_roots_denied(self):
        assert path_allowed("/etc/passwd", None)[0] is False

    def test_inside_root_allowed(self, tmp_path):
        (tmp_path / "sub").mkdir()
        f = tmp_path / "sub" / "a.txt"
        f.write_text("hi", encoding="utf-8")
        ok, why = path_allowed(f, (str(tmp_path),))
        assert ok is True
        assert why == ""

    def test_root_itself_allowed(self, tmp_path):
        assert path_allowed(tmp_path, (str(tmp_path),))[0] is True

    def test_outside_root_denied(self, tmp_path):
        outside = tmp_path.parent / "elsewhere.txt"
        ok, why = path_allowed(outside, (str(tmp_path / "root"),))
        assert ok is False
        assert "不在允许目录内" in why

    def test_dotdot_traversal_denied(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        evil = root / ".." / "secret.txt"
        assert path_allowed(evil, (str(root),))[0] is False

    def test_sibling_prefix_not_confused(self, tmp_path):
        # /data2 不能被当成在 /data 内 —— startswith 的经典漏洞
        a = tmp_path / "data"
        b = tmp_path / "data2"
        a.mkdir()
        b.mkdir()
        (b / "x.txt").write_text("x", encoding="utf-8")
        assert path_allowed(b / "x.txt", (str(a),))[0] is False

    def test_empty_path_denied(self, tmp_path):
        assert path_allowed("", (str(tmp_path),))[0] is False
        assert path_allowed("   ", (str(tmp_path),))[0] is False

    def test_relative_path_resolved_against_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "f.txt").write_text("x", encoding="utf-8")
        ok, _ = path_allowed("f.txt", (str(tmp_path),))
        assert ok is True

    def test_tilde_expanded(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        (tmp_path / "f.txt").write_text("x", encoding="utf-8")
        ok, _ = path_allowed("~/f.txt", (str(tmp_path),))
        assert ok is True

    def test_second_root_matches(self, tmp_path):
        r1 = tmp_path / "r1"
        r2 = tmp_path / "r2"
        r1.mkdir()
        r2.mkdir()
        (r2 / "a.txt").write_text("x", encoding="utf-8")
        assert path_allowed(r2 / "a.txt", (str(r1), str(r2)))[0] is True

    @pytest.mark.skipif(
        os.name == "nt", reason="Windows 创建符号链接需要管理员权限或开发者模式"
    )
    def test_symlink_escape_denied(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("s", encoding="utf-8")
        link = root / "link"
        link.symlink_to(outside, target_is_directory=True)
        # realpath 解析后落在 root 之外，必须拒绝
        assert path_allowed(link / "secret.txt", (str(root),))[0] is False

    def test_normalize_root_is_absolute(self):
        p = normalize_root(".")
        assert os.path.isabs(p)


# ---------------------------------------------------------------------------
# 闸门判定
# ---------------------------------------------------------------------------


class TestGateBasics:
    def test_read_only_allowed_by_default(self):
        g = PermissionGate()
        d = g.check(Tool("read_file", "low"))
        assert d.allowed and d.decision == DECISION_ALLOW
        assert d.risk == RISK_READ_ONLY

    def test_confirm_needs_confirmation_without_approver(self):
        g = PermissionGate()
        d = g.check(Tool("write_file", "medium"))
        assert d.needs_confirmation
        assert not d.allowed

    def test_forbidden_denied(self):
        g = PermissionGate()
        d = g.check(Tool("shell", "high"))
        assert d.decision == DECISION_DENY
        assert not d.allowed

    def test_bare_name_accepted(self):
        g = PermissionGate()
        # 裸名字没有 risk -> 归一到 confirm -> 需要确认（保守）
        d = g.check("some_tool")
        assert d.needs_confirmation

    def test_unknown_risk_is_confirm(self):
        g = PermissionGate()
        assert g.check(Tool("t", "banana")).needs_confirmation

    def test_enable_false_allows_everything(self):
        g = PermissionGate(PermissionSettings(enable=False))
        for risk in ("low", "medium", "high"):
            d = g.check(Tool("t", risk))
            assert d.allowed
            assert "已关闭" in d.reason

    def test_deny_tools_wins_over_allow_tools(self):
        st = PermissionSettings(allow_tools=("x",), deny_tools=("x",))
        d = PermissionGate(st).check(Tool("x", "low"))
        assert d.decision == DECISION_DENY

    def test_allow_tools_promotes_write_tool(self):
        st = PermissionSettings(allow_tools=("writer",))
        d = PermissionGate(st).check(Tool("writer", "high"))
        assert d.allowed
        assert "显式放行" in d.reason

    def test_policy_can_be_fully_reversed(self):
        st = PermissionSettings(
            read_only=DECISION_DENY,
            confirm=DECISION_ALLOW,
            forbidden=DECISION_ALLOW,
        )
        g = PermissionGate(st)
        assert g.check(Tool("r", "low")).decision == DECISION_DENY
        assert g.check(Tool("w", "medium")).allowed
        assert g.check(Tool("x", "high")).allowed


class TestApprover:
    def test_approver_true_allows(self):
        g = PermissionGate(approver=lambda name, args: True)
        d = g.check(Tool("write_file", "medium"))
        assert d.allowed
        assert d.reason == "用户已确认"

    def test_approver_false_keeps_pending(self):
        g = PermissionGate(approver=lambda name, args: False)
        d = g.check(Tool("write_file", "medium"))
        assert d.needs_confirmation
        assert "未同意" in d.reason

    def test_approver_string_reason_recorded_verbatim(self):
        # 策略性放行要如实写进审计，而不是一律记成"用户已确认"
        g = PermissionGate(approver=lambda name, args: "在免确认名单里")
        d = g.check(Tool("write_file", "medium"))
        assert d.allowed
        assert d.reason == "在免确认名单里"

    def test_approver_empty_string_means_no(self):
        g = PermissionGate(approver=lambda name, args: "   ")
        assert g.check(Tool("w", "medium")).needs_confirmation

    def test_approver_exception_fails_closed(self):
        def boom(name, args):
            raise RuntimeError("确认通道挂了")

        d = PermissionGate(approver=boom).check(Tool("w", "medium"))
        assert d.needs_confirmation
        assert "确认通道异常" in d.reason

    def test_approver_receives_name_and_args(self):
        seen = {}

        def spy(name, args):
            seen["name"] = name
            seen["args"] = args
            return True

        PermissionGate(approver=spy).check(Tool("w", "medium"), {"path": "/x"})
        assert seen["name"] == "w"
        assert seen["args"] == {"path": "/x"}

    def test_approver_not_called_for_read_only(self):
        calls = []
        g = PermissionGate(approver=lambda n, a: calls.append(n) or True)
        g.check(Tool("read", "low"))
        assert calls == []

    def test_approver_not_called_when_denied(self):
        calls = []
        g = PermissionGate(
            PermissionSettings(deny_tools=("x",)),
            approver=lambda n, a: calls.append(n) or True,
        )
        g.check(Tool("x", "medium"))
        assert calls == []


class TestRateLimit:
    def test_under_limit_allows(self):
        # 限额 3：第 1、2 次已记账后仍可问（recent=1、2），第 3 次记账后
        # 到 3 -> 用尽。所以循环只跑到第 3 次记账之前。
        clock = FakeClock()
        g = PermissionGate(PermissionSettings(max_calls_per_minute=3), clock=clock)
        for _ in range(3):
            assert g.check(Tool("r", "low")).allowed
            g.note_call()

    def test_exactly_at_limit_denies_next(self):
        clock = FakeClock()
        g = PermissionGate(PermissionSettings(max_calls_per_minute=3), clock=clock)
        for _ in range(3):
            g.note_call()
        assert g.check(Tool("r", "low")).decision == DECISION_DENY

    def test_limit_reached_denies(self):
        clock = FakeClock()
        g = PermissionGate(PermissionSettings(max_calls_per_minute=2), clock=clock)
        g.note_call()
        g.note_call()
        d = g.check(Tool("r", "low"))
        assert d.decision == DECISION_DENY
        assert "上限已用尽" in d.reason

    def test_window_slides(self):
        clock = FakeClock()
        g = PermissionGate(PermissionSettings(max_calls_per_minute=1), clock=clock)
        g.note_call()
        assert g.check(Tool("r", "low")).decision == DECISION_DENY
        clock.advance(61)
        assert g.check(Tool("r", "low")).allowed

    def test_zero_means_unlimited(self):
        clock = FakeClock()
        g = PermissionGate(PermissionSettings(max_calls_per_minute=0), clock=clock)
        for _ in range(500):
            g.note_call()
        assert g.check(Tool("r", "low")).allowed

    def test_rejected_calls_do_not_consume_quota(self):
        # 先问后记：被拒的调用不该占用配额，否则一次拒绝会连锁拒绝一整个窗口
        clock = FakeClock()
        g = PermissionGate(PermissionSettings(max_calls_per_minute=1), clock=clock)
        g.check(Tool("write", "medium"))  # 需要确认 -> 未执行
        assert g.recent_calls() == 0
        g.note_call()
        assert g.recent_calls() == 1

    def test_recent_calls_prunes(self):
        clock = FakeClock()
        g = PermissionGate(PermissionSettings(max_calls_per_minute=0), clock=clock)
        g.note_call()
        assert g.recent_calls() == 1
        clock.advance(120)
        assert g.recent_calls() == 0


class TestModelMessage:
    def test_allowed_message(self):
        d = PermissionGate().check(Tool("r", "low"))
        assert d.model_message() == "已允许执行。"

    def test_confirm_message_tells_model_not_to_retry(self):
        d = PermissionGate().check(Tool("w", "medium"))
        msg = d.model_message()
        assert "不要重试" in msg
        assert "未执行" in msg

    def test_deny_message(self):
        d = PermissionGate().check(Tool("shell", "high"))
        msg = d.model_message()
        assert "被权限策略拒绝" in msg
        assert "未执行" in msg

    def test_as_dict_is_json_safe(self):
        d = PermissionGate().check(Tool("w", "medium"))
        json.dumps(d.as_dict())


# ---------------------------------------------------------------------------
# 审计
# ---------------------------------------------------------------------------


class TestAudit:
    def test_jsonl_appends_one_line_per_decision(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        g = PermissionGate(
            PermissionSettings(allowed_roots=(str(tmp_path),)),
            audit_sink=JsonlAuditLog(log),
        )
        g.check(Tool("r", "low"), {"path": "a"}, source="chat")
        g.check(Tool("w", "medium"), source="task")
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["tool"] == "r"
        assert first["decision"] == DECISION_ALLOW
        assert first["source"] == "chat"

    def test_disabled_by_settings(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        g = PermissionGate(
            PermissionSettings(audit=False), audit_sink=JsonlAuditLog(log)
        )
        g.check(Tool("r", "low"))
        assert not log.exists()

    def test_no_sink_means_no_crash(self):
        PermissionGate().check(Tool("r", "low"))  # 不抛即可

    def test_sensitive_args_redacted(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        g = PermissionGate(audit_sink=JsonlAuditLog(log))
        g.check(
            Tool("t", "low"),
            {"api_key": "sk-secret", "token": "abc", "path": "a", "count": 3},
        )
        rec = json.loads(log.read_text(encoding="utf-8").strip())
        assert rec["args"]["api_key"] == "***"
        assert rec["args"]["token"] == "***"
        assert rec["args"]["path"] == "a"
        assert rec["args"]["count"] == 3

    def test_non_scalar_args_summarised(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        g = PermissionGate(audit_sink=JsonlAuditLog(log))
        g.check(Tool("t", "low"), {"blob": object(), "lst": [1, 2, 3]})
        rec = json.loads(log.read_text(encoding="utf-8").strip())
        assert rec["args"]["blob"] == "<object>"
        assert rec["args"]["lst"] == "<list>"

    def test_sink_exception_does_not_break_gate(self):
        class Broken(JsonlAuditLog):
            def write(self, record):
                raise OSError("disk full")

        g = PermissionGate(audit_sink=Broken(os.devnull))
        assert g.check(Tool("r", "low")).allowed

    def test_rotation(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        sink = JsonlAuditLog(log, max_bytes=200)
        for i in range(50):
            sink.write({"i": i})
        assert log.exists()
        assert (tmp_path / "audit.jsonl.1").exists()

    def test_parent_dir_created(self, tmp_path):
        log = tmp_path / "deep" / "nested" / "audit.jsonl"
        JsonlAuditLog(log).write({"a": 1})
        assert log.exists()

    def test_append_does_not_truncate(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        sink = JsonlAuditLog(log)
        sink.write({"a": 1})
        sink.write({"b": 2})
        assert len(log.read_text(encoding="utf-8").strip().splitlines()) == 2


# ---------------------------------------------------------------------------
# check_path / describe_policy
# ---------------------------------------------------------------------------


class TestCheckPath:
    def test_allowed(self, tmp_path):
        (tmp_path / "a.txt").write_text("x", encoding="utf-8")
        st = PermissionSettings(allowed_roots=(str(tmp_path),))
        d = PermissionGate(st).check_path(tmp_path / "a.txt")
        assert d.allowed
        assert d.risk == RISK_READ_ONLY

    def test_denied(self, tmp_path):
        g = PermissionGate(PermissionSettings(allowed_roots=(str(tmp_path),)))
        assert g.check_path(tmp_path.parent / "x").decision == DECISION_DENY

    def test_audited(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        st = PermissionSettings(allowed_roots=(str(tmp_path),))
        PermissionGate(st, audit_sink=JsonlAuditLog(log)).check_path(tmp_path)
        assert json.loads(log.read_text(encoding="utf-8").strip())["tool"] == "path"


class TestDescribePolicy:
    def test_shape_without_registry(self):
        out = describe_policy()
        assert out["enable"] is True
        assert out["tools"] == []
        assert isinstance(out["allowed_roots"], list)

    def test_lists_tools_with_decisions(self):
        reg = Registry(
            Tool("read_file", "low"),
            Tool("write_file", "medium"),
            Tool("shell", "high"),
        )
        out = describe_policy(reg)
        by_name = {t["name"]: t for t in out["tools"]}
        assert by_name["read_file"]["decision"] == DECISION_ALLOW
        assert by_name["write_file"]["decision"] == DECISION_NEED_CONFIRM
        assert by_name["shell"]["decision"] == DECISION_DENY

    def test_registry_may_be_none(self):
        assert describe_policy(None)["tools"] == []

    def test_deny_list_reflected(self):
        reg = Registry(Tool("read_file", "low"))
        st = PermissionSettings(deny_tools=("read_file",))
        out = describe_policy(reg, st)
        assert out["tools"][0]["decision"] == DECISION_DENY

    def test_disable_shows_everything_allowed(self):
        reg = Registry(Tool("shell", "high"))
        out = describe_policy(reg, PermissionSettings(enable=False))
        assert out["tools"][0]["decision"] == DECISION_ALLOW

    def test_json_serialisable(self):
        json.dumps(describe_policy(Registry(Tool("a"), Tool("b", "high"))))
