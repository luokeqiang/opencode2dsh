# 维护分支说明（fork）

本仓库是 [FishBottle7/opencode2dsh](https://github.com/FishBottle7/opencode2dsh)
的维护 fork。上游 `master` 停在 `37d3ea2`（2026-11-03），本 fork 在该提交之上
维护免费模型委托的工具中继与权限门回退。

> English: This is a maintained fork of opencode2dsh. Upstream `master` is kept
> at `37d3ea2`; fork-only work lives on `dsh/tools-relay`.

## 为什么 fork

上游的委托默认是纯文本模式：模型能回答，但不能调用工具。DSH 需要的
`bash`/`read`/`edit` 等工具在委托回合里会被 ask-then-reject 全部拒绝。
这个 fork 增加 design B 工具中继：在审批门捕获原生调用，abort 回合，交给
DSH 执行，再把 `toolResult` 重新播种回下一轮。

同时修复了 2026-11-09 实测到的两个阻塞：

- 免费额度 `429 FreeUsageLimitError` 在旧的 `attempt >= 1` 条件下永远不会触发委托；
- OpenCode 1.18.35 的 `grep` 会把全局 `GET /permission` 毒化成 400
  （`metadata.include = undefined`），旧监视器空转，工具回合卡死。

## 新增内容

- `delegation.tools`（默认 `false`）：工具中继开关。
- `delegation.cwd`（默认 `''`）：工具模式的委托工作目录；空 = DSH 进程 cwd。
- 审批门捕获 + abort；只捕获当前 `sessionID`，从不 `allow`。
- `GET /permission` 失败时回退到 `GET /session/{id}/message` 的 in-flight tool parts。
- 429 额度错误首次失败即可委托；403 `FreeTierError` 仍先走姊妹主机重放。
- 宿主工具别名/参数改写（`webfetch`→`web_fetch`、`read.path`→`file_path` 等）。
- 丢弃同回合内缺失必填参数的重复工具调用（如只有 `description` 的第二个
  `bash`），避免 DSH 报 `INVALID_ARGS`；只有调用是唯一一条时仍原样中继，
  让模型看到宿主错误。
- 回归测试：委托套件 30 项，adapter 套件 10 项，全仓 451 项。

细节见 [docs/delegation.md](docs/delegation.md) §4.2。

## 分支与发布

| 分支/标签 | 用途 |
|---|---|
| `master` | 上游镜像，保持与 `FishBottle7/opencode2dsh` 一致 |
| `dsh/tools-relay` | fork 功能分支（本仓库默认分支） |
| `v0.3.15-dsh.N` | 从 `dsh/tools-relay` 打的发布标签 |

发布流程由 `.github/workflows/release.yml` 执行：`pnpm typecheck` →
`pnpm test` → `pnpm pack` → 创建 GitHub Release，附带 `.tgz` 与
`SHA256SUMS`。Release 正文取自 `CHANGELOG.md` 中对应版本的小节（Keep a
Changelog 格式，带日期），并自动追加安装命令、`SHA256SUMS` 与 Full Changelog
链接；工作流会校验 tag、`package.json` 和 `CHANGELOG.md` 的版本一致。CI 在
`.github/workflows/ci.yml`。

上游更新时：

```bash
git fetch upstream
git checkout master
git merge --ff-only upstream/master
git checkout dsh/tools-relay
git rebase master   # 或 merge master
```

## 安装

本 fork 不发布到 npm；请从 Releases 下载 tarball：

```bash
# 下载 opencode2dsh-dsh-plugin-<version>.tgz 与 SHA256SUMS 后
sha256sum -c SHA256SUMS
dsh plugin --profile web add ./opencode2dsh-dsh-plugin-<version>.tgz
```

或从源码构建：

```bash
git clone https://github.com/luokeqiang/opencode2dsh.git
cd opencode2dsh/packages/plugin
pnpm install
pnpm pack
```

安装后重启 DSH。插件名仍是 `@opencode2dsh/dsh-plugin`，避免改 profile
依赖名；但 npm 上的同名包是上游发布，不含本 fork 的工具中继。

## 验证基线

- DSH `0.2.1-rc.5`
- OpenCode 委托运行时 `1.18.35`
- Node `>=20`（CI 用 24；本地测试用 26）
- `pnpm typecheck` 干净，`pnpm test` 451/451
- 实机：`grep`/`bash` 工具回合能返回 `tool_call` → `tool_result`，退出码 0

## 许可

MIT。保留上游版权声明；fork 新增代码同样以 MIT 发布。
