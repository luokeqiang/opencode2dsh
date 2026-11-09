# opencode2dsh 本地 OpenCode 委托 — 设计与安全姿态

> 状态：已实现（issue #76）；本 fork 追加 429 立即委托与工具中继（design B，§4.2）。关联：`docs/ts-adapter.md`（adapter 形态）、`docs/ip-pool.md`（多出口轮换，委托触发前的第一道兜底）。
> 参考实现（MIT）：[reisen-ww/opengate](https://github.com/reisen-ww/opengate) 的 `delegate.mjs` + `vendor/`（dsh-opencode-xdbridge）。本模块的协议形状、凭据种子、版本门槛、内存约束、工具中介均移植自该实现，协议分歧一律以参考实现为准。

## 0. 动机：匿名通道救不回来的那部分用户

0.3.12 之后，Zen 免费层的风控门槛从「认流量形状」升级为「认身份」（凭据）。issue #76 的 A/B 证据：同一机器/IP/TLS 栈，无凭据直连 100% 403 `FreeTierError`；带真实 opencode 二进制（`auth.json` 里的 `oc_sk_` 凭据）100% 通过。逐项 A/B 过 TLS 指纹、permission、payload、`--pure`、system prompt、session 级 permission 数组、watchEvents 轮询——**全部与门禁无关**。

所以 `#67`/`#74`/`#75` 这条「继续修 session id / agent-shape 门」的路线到此为止：`canonicalSessionID()` 派生再准，缺凭据照样 403。委托是「同形伪装」设计的自然延伸：不再自造上游 HTTP 客户端，而是让插件在本地驱动**真实的 opencode**——真实 CLI 怎么活，委托就怎么活；上游再改风控，等 opencode 官方适配即可。

边际价值要诚实：`#80` 的姊妹主机重试已覆盖**间歇性**拒绝；委托真正不可替代的是「形状正确 + IP 干净 + **仍稳定拒绝**」的那部分用户（issue 作者用 A/B 证明了它存在）。

## 1. 触发条件（什么时候委托）

委托是**最后兜底**，不是首选通道。全部条件同时成立才触发：

1. 匿名车道一次尝试在**送达任何内容之前**失败；
2. 失败属于以下两类之一：
   - `FreeTierError` 凭据门禁（`isFreeTierRefusal`，不是 `RegionError`）；
   - 免费额度限流：`FreeUsageLimitError` 或 `free usage limit reached`（分类为 `limited`，不是 `refused`）；
3. 对 `FreeTierError`，**姊妹主机重试也拒绝**（持续拒绝）——旋转循环耗尽（`attempt ≥ 1`）；
   额度类错误不会触发姊妹主机重放，首次失败（`attempt = 0`）即可委托；
4. 用户**显式开启** `delegation.enabled` 且委托就绪（见 §3）。

任一不满足 → 原样透出匿名车道的诚实错误，委托完全不进路径。开启委托但缺凭据 / 委托进程起不来 / 委托回合失败，同样回退到诚实错误，**绝不**把半成品内容漏给用户。

```text
匿名直连 →（403 FreeTierError）→ 姊妹主机重试 →（仍 403 FreeTierError）→ 本地 opencode 委托 →（失败）→ 诚实错误
匿名直连 →（429 FreeUsageLimitError / free usage limit reached）──────────→ 本地 opencode 委托 →（失败）→ 诚实错误
              └────── IP 池有其它出口时，中间还可能插入出口轮换（docs/ip-pool.md §3.4）──────┘
```

## 2. 安全姿态（本功能的核心代价）

默认**关闭**。开启后插件从「无状态匿名客户端」（Key 就是字面量 `public`，不存任何机密）变成**凭据保管人**——这是风险等级的实质上移，必须用户显式知情同意：

- **凭据落地第二份**：从用户既有的 `~/.local/share/opencode/auth.json` 里**只挑 `opencode` 这一个 provider 条目**，种进隔离 XDG 根 `<dataDir>/delegate/opencode/data/opencode/auth.json`，**0600**。
- **绝不外泄**：凭据值**永不写日志**（任何路径），只记录来源文件路径；隔离运行时只读它自己数据目录里的那一份。
- **绝不搬运无关密钥**：其它 provider 的 key 不读入结果对象、不落盘、不日志。
- **账号风险自负**：把个人凭据灌进第三方 adapter 做代理，若被上游判定为异常使用，后果由用户账号承担。**这是开启前必须接受的风险**，README 与本文档均如实标注。
- **本地执行面**：默认纯文本模式靠 ask-then-reject 三层纵深（§4.1）；`tools: true` 时仍然不批准任何本地审批，改为在审批门捕获调用并 abort，由宿主执行（§4.2）。两种模式都必须保证本地零执行——中介出 bug 就是本地命令执行，所以这是硬约束。

## 3. 配置

`cordis.patch.yml` 顶层 `delegation` 块（普通配置，不是设置页表单——把凭据保管的决定留在「编辑 profile 补丁」这个刻意的动作里）：

```yaml
- id: opencode2dsh
  name: '@opencode2dsh/dsh-plugin'
  config:
    delegation:
      enabled: true        # 总开关，默认 false
      # opencodePath: ''   # 显式指定 opencode 二进制；设置后跳过 managed/全局/npm 解析
      # minVersion: '1.18.0'  # 版本下限，低于此的候选直接跳过
      # memLimit: '96MiB'  # 注入子进程的 GOMEMLIMIT
      # gcPercent: 30      # 注入子进程的 GOGC
      # trimIntervalMs: 60000  # EmptyWorkingSet 内存回收节拍；0 关闭
      # startTimeoutMs: 60000  # 等子进程健康的预算
      # tools: false       # 工具中继开关（design B）；true = 原生调用回传宿主执行
      # cwd: ''            # 工具模式工作目录；空 = DSH 进程 cwd
```

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `false` | 总开关。`false` 时插件保持无状态匿名客户端，匿名路径与今天逐字节一致。 |
| `opencodePath` | — | 显式二进制路径。设置后跳过 managed → 全局 → npm 的回退链（仍做版本校验）。 |
| `minVersion` | `1.18.0` | 版本下限。免费层要求 ≥ 1.18.0，更低的二进制「看着健康、每个请求都失败」，所以直接跳过。 |
| `memLimit` | `96MiB` | 注入子进程的 `GOMEMLIMIT`（Go 堆软上限）。 |
| `gcPercent` | `30` | 注入子进程的 `GOGC`（更激进的 GC 频率）。 |
| `trimIntervalMs` | `60000` | Windows 上 `EmptyWorkingSet` 换出物理页的节拍；`0` 关闭（内存约束仍生效）。 |
| `startTimeoutMs` | `60000` | 等 `opencode serve` 健康的预算。 |
| `tools` | `false` | 工具中继开关（§4.2）。`false` 保持纯文本 ask-then-reject；`true` 把原生工具调用捕获后回传宿主执行。 |
| `cwd` | `''` | 工具模式的委托工作目录。空 = DSH 进程的 `process.cwd()`；绝对路径 = 固定目录；不存在时回退隔离目录。文本模式忽略。 |

没登录过 opencode CLI（找不到凭据）→ 委托不就绪，触发时回退诚实错误并在日志给出明确提示（「run `opencode` once to log in」）。

## 4. 工具中介：默认纯文本，可选回传宿主

### 4.1 默认：纯文本（ask-then-reject）

委托默认只做「聊天通道」。模型在 opencode 会话里想调任何原生工具，都被按住：

1. **会话级 permission 数组**：`POST /session` 带 `{permission: '*', action: 'ask'}`（每个原生操作都先问）+ `question/websearch/webfetch/task/plan_*` 等显式 `deny`。这份策略与注入运行时的 `OPENCODE_CONFIG_CONTENT` 用**同一份常量**，两份副本永不漂移（参考实现曾因漂移踩过免费层门禁）。
2. **ask-then-reject 监视器**：回合进行中并发轮询 `GET /permission`，对每个挂起审批回 `POST /permission/{id}/reply {reply:'reject'}`，附「本会话无工具，只用纯文本回答」。每回合拒绝数有上限，超限即中止（防模型死循环卡死回合）。
3. **响应体扫描**：回合完成按 **`info.error` 有无** 判成败后（见 §5），扫描 `parts`——任何「非已拒绝且已报错」的 `tool` part 都是中介失效，整回合拒绝并报错。没有任何原生动作可能执行。

### 4.2 工具中继（`tools: true`，design B）

开启后，模型的原生工具调用不再被永久拒绝，而是回传给 DSH 执行；opencode 本地仍然零执行：

1. **权限策略**：`DELEGATE_TOOL_PERMISSION_POLICY` 仍是 `*: ask`，但只本地 `deny` 没有宿主对应的 `task`/`codesearch`/`plan_enter`/`plan_exit`。`question`/`websearch`/`webfetch`/`todowrite` 可以进入捕获。
2. **审批门捕获 + abort**：监视器发现当前会话的待审批项后，快照 `callID`/`permission`/`metadata`，等 200ms 收齐并行调用，然后 `POST /session/{id}/abort`。它**从不 reply allow**，所以本地不执行。
3. **权限列表坏掉时的回退**：OpenCode 1.18.35 的 `grep` 会让全局 `GET /permission` 因 `metadata.include = undefined` 返回 400。监视器改用 `GET /session/{id}/message`，从 in-flight tool part 的 `callID` + `state.input` 捕获，再 abort；不会在 400 上空转。
4. **只回传捕获到的调用**：被本地 deny 的工具不进入回传；响应里任何 `status !== 'error'` 的 tool part 都说明本地执行泄漏，整回合以 `native_tool_activity` 失败。正常 abort 的响应是 `MessageAbortedError` + interrupted-error tool parts；即使响应丢了 parts，门快照仍能提供 name/input。
5. **收尾**：abort 之后，对当前会话捕获到的审批 id reply `reject`（拒绝不会执行工具），再删除会话。`GET /permission` 是全局的，旧会话/外部会话的条目一律不碰，避免下一次新会话把旧 callID 当成自己的调用无限回放。
6. **回传与重播种**：捕获到的调用变成 DSH 的 `tool-call` 块，由宿主执行；下一次请求把包含 `toolResult` 的完整历史以 JSON 重新播种给新的 opencode 会话，循环到模型给出文本。每个 DSH 请求都是新会话，无状态。

工具名/参数改写：

| 委托原生 | DSH 宿主 | 参数改写 |
|---|---|---|
| `bash` | `bash` | 自动补必填 `description` |
| `read` | `read` | `path` → `file_path` |
| `edit` | `edit` | `filePath/oldString/newString/replaceAll` → `file_path/old_string/new_string/replace_all` |
| `write` | `write` | `filePath` → `file_path` |
| `glob` / `grep` | 同名 | — |
| `webfetch` | `web_fetch` | 未知键按宿主 schema 裁剪 |
| `websearch` | `web_search` | `query` → `queries[]` |
| `question` | `ask_user_question` | — |
| `todowrite` | `todo_write` | — |
| `task` / `codesearch` / `plan_*` | 无对应 | **本地 deny** |

`cwd`：空字符串 = DSH 进程的 `process.cwd()`；绝对路径 = 固定工作目录；路径不存在时回退到隔离 project 目录。文本模式忽略 `cwd`，始终待在隔离目录。

环境隔离：子进程用隔离 XDG 根 + 白名单环境变量（`PATH/HOME/…`，**不继承任何第三方 key 或 OpenCode auth 覆盖**）+ `OPENCODE_DISABLE_CLAUDE_CODE` / `OPENCODE_DISABLE_EXTERNAL_SKILLS` / `OPENCODE_DISABLE_AUTOUPDATE` / `OPENCODE_DISABLE_PROJECT_CONFIG` + 随机服务密码 + 每次启动全新隔离目录（不读用户自己的 opencode 配置/会话）。两种模式共用这套隔离。

## 5. 判成败的坑：HTTP 200 + `info.error`

`POST /session/{id}/message` 门禁失败时返回 **HTTP 200**，错误藏在响应体 `info.error.name = "APIError"`。按「有没有 text part」判成败会得出一整批假成功（issue 作者怀疑 `#72` 的部分报告被这个坑污染）。本实现**只看 `info.error` 有无**——响应可以同时带 text part 和 `info.error`，此时一律判失败。这条编码成显式测试（mock 服务器返回 200 + text part + `info.error`，断言判失败）。

## 6. 进程生命周期与内存

- **二进制解析顺序**：显式 `opencodePath` → `<dataDir>/delegate/runtime/<version>/`（曾下载的托管安装）→ 用户自己的安装（`OPENCODE_BINARY_PATH`、`~/.opencode/bin`、npm 全局树、PATH 查找，拷进托管树自包含）→ 官方 npm 下载（sha512 校验，校验不过即中止）。每个候选都过版本探针，低于 `minVersion` 跳过。
- **隔离启动**：随机回环端口、`serve --pure --hostname 127.0.0.1`、健康轮询 `/global/health`（版本须与二进制一致）。
- **内存**：Go 常驻进程裸跑 300–500MB。注入 `GOMEMLIMIT=96MiB` + `GOGC=30`；Windows 上周期性 `EmptyWorkingSet`（参考实现实测 419MB → 38MB）。判占用看 `WorkingSet64`，别看 `PrivateMemorySize64`（虚拟保留量，会误报 500MB+）。EmptyWorkingSet 用一次性 PowerShell 调用实现，**插件保持零原生依赖**；非 Windows 平台跳过（`trimIntervalMs` 只影响 Windows）。
- **惰性 + 幂等**：进程在**首次**持续拒绝才拉起（`start()` 幂等、并发共享同一次启动）；插件 dispose 时 `SIGTERM`（4s 后 `SIGKILL`）回收，无孤儿进程。

## 7. 已知限制

- **非增量流式**：一回合用同步 `POST /message` 拿完整结果再翻译成 chunk 流（参考实现的同一条主路径）。用户要等整回合结束才看到文本；token 级增量流式（消费 `/event` SSE）是后续增强。
- **reasoning effort 不穿透**：委托回合不传 `variant`，用运行时默认推理档位（插件 catalog 不暴露 variants 元数据）。
- **MEMORY/GOGC 与 EmptyWorkingSet 是尽力而为**：GOMEMLIMIT 是软上限，极端负载下物理占用仍可能冲高；内存回收只在 Windows 生效。
- **凭据刷新语义**：种子的 `auth.json` 是用户登录时的快照；opencode CLI 侧刷新/登出不会自动同步（删 `<dataDir>/delegate/opencode/data/opencode/auth.json` 可强制重种）。
- **协议形状来自参考实现**：本机出口 IP 被 opencode 生成接口全拒（2026-10-19 起），无法对 live 服务器做形状验证；所有端到端验证走本地 mock `opencode serve`。若上游协议漂移，以参考实现（reisen-ww/opengate）为准。
- **工具中继是回合制的**：每个工具批次都会结束一次委托回合并重新播种历史，多步任务会产生多次委托请求；不是 token 级增量，也不是同会话续命。
- **`grep` 权限列表毒化**：OpenCode 1.18.35 的 `grep` 会让全局 `GET /permission` 返回 400。回退路径能避免卡死并完成工具回合，但列表本身要重启运行时（重启 DSH）才恢复；期间其他本地 opencode 会话的审批列表也不可用。
- **`cwd` 必须存在**：工具模式写绝对路径时，路径不存在会回退到隔离目录，模型看到的路径可能与 DSH 不一致。
- **本地 deny 的工具没有宿主对应**：`task`/`codesearch`/`plan_*` 会立即收到本地错误；需要这些能力时得先在宿主侧提供同名工具。
- **429 仍可能出现**：委托解决的是「额度错误无法触发委托」的 bug，不改变上游免费额度本身。

## 8. 测试

`test/delegate.test.ts`（29 项，mock `opencode serve` 本地端口）+ `test/delegation-adapter.test.ts`（10 项，adapter 兜底顺序）；全仓 `pnpm test` 449 项。覆盖：凭据种子（只取 `opencode` 条目 / 0600 / 候选优先级 / 缺凭据）、版本门槛 accept/reject、二进制回退顺序、HTTP-200-with-`info.error` 判失败、工具 ask-then-reject、工具中继的捕获/abort/回传、权限列表 400 时从 session message 回退、会话隔离清理、429 首次委托、非预期 tool part 拒绝、空回合诚实报错、adapter 兜底链（匿名 → 姊妹 → 委托 → 诚实错误）与「委托关闭路径逐字节不变」。
