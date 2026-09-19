# Changelog

本文件记录 agent-gate 的对外变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-09-19

首次发布。从 [MurasamePet](https://github.com/canyueY/MurasamePet) 的
`Murasame/agent/permissions.py` 抽出并补上审计落地。

### Added

- `PermissionGate`：把 risk + 策略 + 限额 + 沙箱 + 审计合成一个可判定器。
- `PermissionSettings` / `permission_settings(cfg)`：策略即数据，可逐项反转。
- 三级风险 `read_only` / `confirm` / `forbidden` 与三档决策
  `allow` / `need_confirm` / `deny`，外加覆盖 `low`/`medium`/`high` 的别名表。
- `path_allowed` / `normalize_root`：基于 `realpath` + `commonpath` 的路径沙箱。
- `PermissionDecision`：带 `allowed` / `needs_confirmation` / `model_message()`
  / `as_dict()` 的判定结果。
- `describe_policy(registry, settings)`：摊平成可下发/可展示的策略摘要。
- **`AuditSink` / `JsonlAuditLog`**：新增审计落地（抽取前的实现只有
  `PermissionSettings.audit` 开关，没有任何写入端）。JSONL 追加、自动轮转一代、
  参数脱敏。
- **`PermissionGate(clock=...)`**：新增单调时钟注入点。抽取前限流依赖
  `time.monotonic()`，测限流必须 `sleep`。

### Changed

- 工具级放行名单的**提升语义**写进了文档与类型：`approver` 现在可以返回
  非空字符串作为放行理由，该理由原文进审计 —— 用于"免确认"这类策略性放行，
  避免把策略放行一律记成"用户已确认"。
- `PermissionDecision` 不再叫"主人"：面向通用 Agent 框架，文案改为"用户"。

### Security

- 未知风险值归为 `confirm` 而不是 `read_only`（写错字符串不能把新工具放行）。
- `allowed_roots` 为空时**任何路径都不放行**（fail closed）。
- 无确认通道时 `confirm` 一律不执行；确认通道抛异常同样不执行。
- 审计参数对 `key`/`token`/`secret`/`password`/`cookie`/`auth` 键脱敏。
- 被拒的调用不占用调用配额（先问后记），避免一次拒绝连锁影响整个窗口。

[0.1.0]: https://github.com/canyueY/agent-gate/releases/tag/v0.1.0
