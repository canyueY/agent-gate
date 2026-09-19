# agent-gate

给 LLM Agent 的工具调用装一道 **fail-closed** 的权限闸门：风险分级、路径沙箱、
调用限额、确认通道、审计。**零运行时依赖**（纯标准库）。

```python
from agent_gate import PermissionGate, PermissionSettings

gate = PermissionGate(PermissionSettings(allowed_roots=("~/notes",)))

decision = gate.check(my_tool, {"path": "~/notes/a.md"})
if decision.allowed:
    result = my_tool.run(**args)
    gate.note_call()                      # 真执行了才记账
else:
    reply = decision.model_message()      # 回给模型的一句人话
```

## 这个包解决什么问题

多数 Agent 框架的工具注册表里，**风险字段早就定义了，却没有任何一处读它** ——
也就是说任何工具只要注册进去就会被无条件执行。对于一个能读你屏幕、能写你文件、
还常驻在后台的进程来说，"无条件执行"是最危险的默认值。

`agent-gate` 把那道缺失的闸门补上，而且默认值是**保守**的：

| risk（工具声明的性质） | 默认决策 | 含义 |
| --- | --- | --- |
| `read_only` | `allow` | 无副作用，可重复执行 |
| `confirm` | `need_confirm` | **不执行**，等确认通道 |
| `forbidden` | `deny` | 明确拒绝 |

三个决策都可在配置里逐项反转，所以策略是数据，不是代码。

## 五条刻意的设计决定

**① 未知风险归为 `confirm`，不是 `read_only`。**
写错一个字符串不该把新工具当成只读放行。`normalize_risk("banana")` → `confirm`。
同理，别名表覆盖了 `low` / `medium` / `high` 这类既有取值，所以接上闸门不会
改变已有注册表的行为。

**② `allowed_roots` 为空 = 全部拒绝（fail closed）。**
不是"默认放开整盘"。配错一个键最多让功能不可用，不会让工具去写 C 盘 ——
这个方向的错误是可接受的。

**③ 没有确认通道时，`confirm` 等于不执行。**
如果还没有气泡问一句"要这么做吗"，把 `need_confirm` 当成"先跑了再说"就等于
没有闸门；当成"拒绝并把原因回给模型"才是诚实的 —— 模型会知道该请你确认，
而不是静默失败。

**④ 被拒的调用不占配额（先问后记）。**
`check()` 只判定，`note_call()` 才记账。否则一次拒绝会连锁拒绝一整个窗口。

**⑤ 回给模型的是人话，不是空字符串。**
模型收到空结果会反复重试同一个工具（实测的 Agent 通病）。`model_message()`
明确告诉它"本轮未执行，先征求同意，不要重试"，它才会换办法。

## 安装

```bash
pip install git+https://github.com/canyueY/agent-gate.git
# 或从源码
git clone https://github.com/canyueY/agent-gate.git
cd agent-gate && pip install -e ".[dev]"
```

> 暂未发布到 PyPI。

## 接上你自己的工具注册表

闸门对 `tool` 参数的要求极低：它只读 `.name` 和 `.risk` 两个属性，
传字符串名字也行。所以任何框架都能直接接：

```python
from agent_gate import PermissionGate, PermissionSettings, permission_settings, describe_policy

# 从配置读策略（只认 {"agent": {"permissions": {...}}} 这一种形状）
settings = permission_settings(config)

gate = PermissionGate(
    settings,
    approver=ask_user,                    # (tool_name, args) -> bool | str
    audit_sink=JsonlAuditLog("log/agent_audit.jsonl"),
)

for call in model_requested_calls:
    tool = registry.get(call.name)
    decision = gate.check(tool, call.args, source="chat")
    if not decision.allowed:
        transcript.append(decision.model_message())
        continue
    result = tool.run(**call.args)
    gate.note_call()
    transcript.append(result)
```

`describe_policy(registry, settings)` 会摊平出「每个工具当前是什么决策」，
适合直接下发给前端做设置面板，或者注入提示词让模型知道自己的权限边界。

### 确认通道

`approver` 的返回值有讲究：

| 返回 | 效果 |
| --- | --- |
| `True` | 放行，审计记「用户已确认」 |
| `False` | 不放行 |
| `"在免确认名单里"` | **放行，审计原文记录这句话** |
| 抛出异常 | **不放行**（确认通道坏了不能默认放行） |

字符串形式是为了策略性放行 —— 让理由如实进审计，而不是一律记成"用户已确认"
（那会让审计看不出到底问没问过）。

## 路径沙箱

```python
from agent_gate import path_allowed

path_allowed("~/notes/a.md", ("~/notes",))   # (True, "")
path_allowed("/etc/passwd",   ("~/notes",))  # (False, "路径不在允许目录内：/etc/passwd")
```

用 `realpath` **先解析再比较**，所以 `..` 穿越和符号链接逃逸都会被拦下；
用 `os.path.commonpath` 而不是 `str.startswith`，所以 `data2` 不会被误判成
在 `data` 内。刻意**不**对不存在的路径放行 —— 判断"将要创建的文件"时请传其父目录。

## 审计

```python
from agent_gate import JsonlAuditLog

gate = PermissionGate(settings, audit_sink=JsonlAuditLog("log/agent_audit.jsonl"))
```

一行一条 JSON，`tail -f` 直接能看，进程被强杀也不会留下半个数据库。
超过 `max_bytes` 自动轮转一代。参数会**脱敏**后再落盘：键名含
`key`/`token`/`secret`/`password`/`cookie`/`auth` 的值一律写成 `***`，
非标量写成 `<list>` 这样的类型摘要 —— 审计的价值是事后能看出发生了什么，
不是把 API key 抄进日志。

审计写失败**不会**让工具调用失败（那是可用性问题），但也不该静默：
`AuditSink` 的实现里请自己记日志。

## 可测性

时间和限额都支持注入，所以限流不用 `sleep` 就能测：

```python
class FakeClock:
    def __init__(self): self.now = 1000.0
    def __call__(self): return self.now
    def advance(self, s): self.now += s

clock = FakeClock()
gate = PermissionGate(PermissionSettings(max_calls_per_minute=2), clock=clock)
```

## 授权

**AGPL-3.0-or-later**，见 [LICENSE](LICENSE)。

本包从作者自己的桌宠项目 [MurasamePet](https://github.com/canyueY/MurasamePet)
（AGPL-3.0）中抽出。代码是那个项目自己新增的部分，但既然来自 AGPL 项目，
这里就继续沿用 AGPL，不做改许可。

## 来源与开发位置

> **本仓库是镜像；权威源码在 MurasamePet 仓库里。**
>
> 开发位置：`MurasamePet/packages/agent-gate/`。
> 桌宠通过 **path 依赖**直接使用它 —— 不再保留任何副本，改这里立即可见。
> 这个独立仓库用于对外发布与展示，内容由 Monorepo 同步而来。
>
> **为什么不反过来（本仓库为源、桌宠用 `git` 依赖）？**
> 开发机上网关受限：`github.com` 必须走本地代理，而 `uv` 拉 git 依赖时
> 用不上该代理（实测 `git fetch` 失败）。path 依赖离线可用、不受代理开关影响。

## 测试

```bash
uv run --python 3.10 --extra dev python -m pytest tests -q
```

97 个用例，零外部依赖，无需任何 fixture 就能跑。重点覆盖那些
"配错了也不会报错、但会让闸门形同虚设"的地方：未知 risk 的归属、
空 `allowed_roots` 的语义、`..` 穿越与符号链接逃逸、限额的先问后记。
