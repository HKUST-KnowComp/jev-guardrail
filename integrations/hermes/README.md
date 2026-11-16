# Hermes 插件维护与部署

[`jev-guard/`](jev-guard/) 是可直接放入 Hermes profile 的原生目录插件。这里维护当前精简部署源码：22 个 Python 运行模块，以及插件清单、初始策略、管理面板和原始许可声明，共 26 个文件。

插件清单版本保持 `0.1.0`。Hugging Face 下载包中的 wheel 版本 `0.1.1` 是独立的打包版本；版本号相同也可能包含不同提交的源码，维护时应记录 Git 提交号。

## 文件位置

| 路径 | 作用 |
|---|---|
| `jev-guard/__init__.py`、`plugin.yaml` | 注册审核钩子、`jev-chat` 命令及会话命令 |
| `jev-guard/runtime.py`、`session.py`、`client.py` | 运行时、会话证据和审核服务连接 |
| `jev-guard/core/` | 分类路由、请求准入、动作审核、权限约束和策略存储 |
| `jev-guard/host_patch.py`、`web_adapter.py`、`delegation.py`、`exa_keyless.py`、`credential_scan.py` | 宿主适配、网页工具、子任务约束、搜索和凭据检查 |
| `jev-guard/editor.py`、`panel.html` | `/safety-policy` 管理面板 |
| `jev-guard/initial-config.json` | 首次初始化使用的策略树和阈值默认值 |
| `jev-guard/LICENSE-NOTICE.md` | 原始来源与许可声明 |

安装器、兼容 Hermes 运行包和 wheel 继续通过 [Hugging Face 模型仓库](https://huggingface.co/hubin/jev-guard-v3.2-2b/tree/main/downloads)分发。本目录用于维护原生插件源码，不包含独立安装命令 `jev configure`、模型权重或审核服务端。首次安装请先按[模型卡中的部署指引](https://huggingface.co/hubin/jev-guard-v3.2-2b)配置兼容 Hermes、审核服务地址和模型 provider。

## 更新已有 Linux/WSL profile

以下步骤面向已经能够运行 `hermes -p <profile> jev-chat` 的环境。在 WSL 的 Linux 终端中执行；源码使用 `fcntl` 等 Linux 接口，不能作为原生 Windows Python 插件运行。宿主需提供插件所依赖的审核钩子、按 profile 隔离的工具覆盖及子任务接口，不能仅凭 Hermes 版本号判断兼容性。

先退出目标 profile 的 Hermes 进程。进入本仓库根目录，把 `my-profile` 改为实际 profile 名称；如果 profile 存放在自定义目录，也相应修改 `profile_home`。下面会把旧插件备份到 profile 下的独立目录，再复制当前源码。

```bash
(
  set -eu
  profile_name='my-profile'
  profile_home="$HOME/.hermes/profiles/$profile_name"

  test -f integrations/hermes/jev-guard/plugin.yaml
  if [ ! -f "$profile_home/jev-guard/settings.json" ]; then
    printf '%s\n' '未找到已有 JEV 配置，请先完成首次安装或检查 profile 路径。' >&2
    exit 1
  fi

  mkdir -p "$profile_home/plugins"
  if [ -e "$profile_home/plugins/jev-guard" ]; then
    backup_dir="$(mktemp -d "$profile_home/jev-plugin-backup.XXXXXX")"
    mv "$profile_home/plugins/jev-guard" "$backup_dir/jev-guard"
    printf '旧插件备份：%s\n' "$backup_dir/jev-guard"
  fi
  cp -a integrations/hermes/jev-guard "$profile_home/plugins/jev-guard"
  git rev-parse HEAD
  hermes -p "$profile_name" jev-chat
)
```

默认 profile 的目录通常是 `~/.hermes`；更新它时使用实际目录，并以 `hermes jev-chat` 启动。上述命令只替换 `plugins/jev-guard/`，已有的 `jev-guard/settings.json`、`jev-guard/policy/` 和 `jev-guard/permissions.json` 都保存在 profile 的另一个目录中。不要用仓库里的初始策略覆盖已保存的策略。

如果宿主尚未启用此插件，在目标 profile 的 `config.yaml` 中合并以下配置，保留其他插件条目。支持工具覆盖授权的宿主需要 `allow_tool_override: true`，以便安装写文件和网页工具适配器。

```yaml
plugins:
  enabled:
    - jev-guard
  entries:
    jev-guard:
      allow_tool_override: true
```

启动后确认 `jev-chat` 命令可以加载，并在会话中通过 `/safety-policy` 检查策略和权限。`/jev-scope show` 查看当前会话权限；`/jev-task show` 查看任务证据状态。用户请求的模型调用前审核由 `jev-chat` 提供，应使用该入口开启受保护会话。

## 请求阈值

在 `/safety-policy` 面板中勾选“启用请求阈值”，填写 `0` 到 `1` 之间的数值，然后点击“Save policy tree”保存。取消勾选并保存会恢复原请求准入规则。

| 配置 | 行为 |
|---|---|
| `unsafe_threshold: null` 或缺省 | 默认模式：使用模型安全标签，低于 `decision_probability` 的决策进入 `ask` |
| `unsafe_threshold: t` | 请求不安全分数 `>= t` 时拦截，`< t` 时准入 |
| `decision_probability: 0.55` | 保留当前默认置信度门槛；启用自定义请求阈值时，请求阶段不再叠加该门槛，工具动作审核仍使用它 |

提高请求阈值会减少拦截，也可能增加漏放；源码没有预设推荐调优值。此开关仅影响用户请求准入，工具权限、动作审核及明确禁止条件仍独立执行。审核失败或服务不可用时，插件会阻止执行。

新 profile 的 `unsafe_threshold` 默认为 `null`，已有 profile 继续使用其保存的配置。默认值位于 `initial-config.json`；配置校验和准入规则分别位于 `core/store.py`、`core/engine.py`，面板开关位于 `panel.html`。

## 维护范围

修改原生插件时在 `jev-guard/` 中维护，并在 Linux/WSL 环境检查导入、策略校验、请求阈值边界和宿主加载。测试脚本、运行日志和本机配置不放入部署目录。不要提交 profile 数据、API 密钥、审核记录或 Python 缓存。

GitHub 源码更新不会自动重建或发布 Hugging Face wheel。需要更新下载包时，应单独核对其内容与安装入口；发布过程不属于目录插件的运行逻辑。来源和许可沿用 [`LICENSE-NOTICE.md`](jev-guard/LICENSE-NOTICE.md)。
