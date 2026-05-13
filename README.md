# Skill Scanner / Agent Skill Surface Diff

> "这个版本让 Agent 的权限越过了哪条 policy？" — 类比 Snyk for Agent Skills

[![Tests](https://github.com/jasoneip01-pixel/skill-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/jasoneip01-pixel/skill-scanner/actions/workflows/test.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://img.shields.io/pypi/v/skill-scanner)](https://pypi.org/project/skill-scanner/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

---

## 定位

**Skill Surface Diff** — 检测 Agent Skill 在生产前的危险性能力扩张。不是 "你的 LLM 输出安全吗？"（vs Promptfoo），也不是 "你的 Agent trace 怎么看？"（vs LangSmith），而是 **"这个 Skill 有毒吗？"**（类比 Snyk）。

专注 Agent Skill 供应链安全：扫描 SKILL.md、脚本、配置，检测 prompt injection、数据外泄、权限越界、guardrail 缺失等安全风险。

## 安装

```bash
pip install skill-scanner
```

需要 Python 3.10+。

## Quick Start

### 扫描一个 Skill 目录

```bash
agent-skills scan path/to/skill-directory
```

输出示例：

```
╭─────────────────────────────── Skill Scanner ────────────────────────────────╮
│ ✖ MERGE BLOCKED                                                              │
├─────────────────────────────────── v0.3.0 ───────────────────────────────────┤
│ Skill:       demos/skill-scanner/test-skill/   Policy:      moderate         │
│ Duration:    13ms                             Checks:      13                │
│ 4 critical · 8 warnings · 1 passed                                           │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### 输出格式

```bash
# JSON
agent-skills scan ./skill --format json

# SARIF (GitHub CodeQL 兼容)
agent-skills scan ./skill --format sarif -o results.sarif

# JUnit XML (CI 集成)
agent-skills scan ./skill --format junit -o results.xml

# Markdown (PR Comment 格式)
agent-skills scan ./skill --format markdown -o report.md
```

### 初始化项目 policy

```bash
agent-skills init
# 生成 .agent-skills/policy.yaml
```

### 选择 Policy 级别

```bash
agent-skills scan ./skill --policy moderate   # 默认：阻止 critical
agent-skills scan ./skill --policy strict     # 零容忍
agent-skills scan ./skill --policy permissive # 仅阻止高危
```

### Version Diff

```bash
agent-skills scan ./skill-v2 --diff --baseline ./skill-v1
```

## CLI 命令

| 命令 | 用途 |
|------|------|
| `agent-skills scan` | 扫描 Skill 目录的安全风险 |
| `agent-skills init` | 初始化项目安全 policy |
| `agent-skills audit` | 全 Agent 表面审计 (7 维度) |
| `agent-skills compliance` | 生成合规报告 (SOC2/GDPR/PCI) |
| `agent-skills policies` | 列出可用 Policy 模板 |
| `agent-skills registry` | 扫描公共 Skill Registry |
| `agent-skills trace` | Trace 录制与比较 |
| `agent-skills notify` | 发送扫描结果到 Slack/Teams |

## GitHub Action

在仓库中创建 `.github/workflows/scan.yml`：

```yaml
name: Skill Scanner
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jasoneip01-pixel/skill-scanner@main
        with:
          path: './skills/my-skill'
          policy: 'moderate'
          format: 'sarif'
```

Action 会自动：
1. 安装 `pip install skill-scanner`
2. 运行 `agent-skills scan`
3. 上传 SARIF 到 GitHub CodeQL
4. 根据 `fail-on` 阈值决定 CI pass/fail

## 检测能力

| 类别 | 规则 | 示例 |
|------|------|------|
| Prompt Injection | `PI001` | system_prompt_append / ignore_safety |
| 数据外泄 | `DX001-4` | curl --data-binary / base64\|curl |
| 凭证泄露 | `SC001` | sk-... API keys in instructions |
| 危险操作 | `WS001-6` | chmod 777 / rm -rf / os.system() |
| 权限越界 | `TOOL001` | 高危工具无 guardrails |
| 网络未声明 | `NET001` | network:true 无 endpoint 说明 |
| Tool Schema 不一致 | `TS001` | POST 方法标注 read-only |
| Secret 文件访问 | `FS001` | /etc/secrets / ~/.ssh |
| 恶意脚本 | `RS001-3` | resources 目录可执行文件 |
| 指令篡改 | `PO001` | "never mention" / "pretend" |
| Manifest 缺失 | `MF001-5` | 缺 name/version / 路径穿越 |

## 项目状态

**v0.3.0 (Alpha)** — 安全代码经过 3 轮 Codex 对抗式审计。核心 CLI 可用，但仍在 Alpha。

**发布缺口**（欢迎贡献）：
- [ ] PyPI 发布 (已配置但未 publish)
- [ ] `.github/workflows/test.yml` (CI)
- [ ] 更多测试覆盖 (现有 102 个)
- [ ] Helm chart 部署文档

## 架构

```
skill_scanner/
├── cli.py              # CLI 入口 (Click + Rich)
├── engine.py           # 扫描引擎 — 协调 scanners + policy
├── parser.py           # SKILL.md 解析 (front matter + YAML)
├── trace_engine.py     # Trace 录制 & 比较
├── policy_engine.py    # OPA Rego + 内置 YAML policy
├── registry.py         # 公共 Registry 扫描 (SSRF 防护)
├── agent_surface.py    # Agent 全表面审计 (7 维度)
├── enterprise.py       # RBAC + Compliance + Notifications
├── scanners/           # 专项扫描器
│   ├── manifest.py     # Manifest 扫描 (prompt injection)
│   ├── instruction.py  # 指令文件扫描 (篡改/凭证)
│   ├── permission.py   # 权限扫描 (guardrails/network)
│   ├── script.py       # 脚本扫描 (外泄/危险命令)
│   └── dependency.py   # 依赖扫描 (resources)
└── policies/           # Policy 定义 (moderate/strict/permissive)
```

## License

MIT License — 详见 [LICENSE](LICENSE)。

Enterprise features (RBAC/Compliance) available under commercial license。

## 文档

- [Product Definition](https://jasoneip01-pixel.github.io/skill-scanner/demos/skill-scanner-product-definition.html)
- [Interactive Demo](https://jasoneip01-pixel.github.io/skill-scanner/demos/agent-skills-scanner-demo.html)
- [Product Positioning](https://github.com/jasoneip01-pixel/skill-scanner/blob/main/docs/business-positioning.md)

## 路线图

- **Phase 1** ✅ CLI + GitHub Action (完成)
- **Phase 2** ✅ Policy Engine + Trace Replay (完成)
- **Phase 3** ✅ Registry Scanner (完成)
- **Phase 4** ✅ Enterprise (RBAC/Compliance/Notifications — 完成)
- **v1.0** 🎯 PyPI 发布 + CI + 文档站 + 测试覆盖

---

*Built with 🔥 for the Agent Skill ecosystem. Questions? Open an issue.*
