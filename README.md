# Skill Scanner / Agent Skill Surface Diff

> "这个版本让 Agent 的权限越过了哪条 policy？" — 类比 Snyk for Agent Skills

## 定位

**Skill Surface Diff** — 不是 "你的 LLM 输出安全吗？"（Promptfoo），也不是 "你的 Agent trace 怎么看？"（LangSmith），而是 **"这个 Skill 有毒吗？"**（类比 Snyk）。

专注 Agent Skill 供应链安全：扫描 SKILL.md、脚本、配置，检测 prompt injection、数据外泄、权限越界、guardrail 缺失等安全风险。

## 为什么是现在

OpenAI/Anthropic 全面推 Agent Skills 生态，Skills 会像 npm 包一样爆发。但目前 **没有** 同类工具。时间窗口合适。

## 当前状态

- **CLI 原型** (`demos/skill-scanner/agent-skills-scan.py`)：单文件，仅依赖 pyyaml，13ms 完成扫描
- **Demo 页** (`demos/agent-skills-scanner-demo.html`)：安全性 vs 可用性对白互动
- **产品定义** (`demos/skill-scanner-product-definition.html`)
- **测试夹具** (`demos/skill-scanner/test-skill/`)：恶意 Skill 测试用例

## 竞争格局

| 工具 | 问什么 |
|------|--------|
| Promptfoo | 你的 LLM 输出安全吗？ |
| LangSmith | 你的 Agent trace 怎么看？ |
| Snyk | 这个依赖有 CVE 吗？ |
| **Skill Scanner** | 这个 Skill 让 Agent 的权限越过了哪条 policy？ |

## License

MIT
