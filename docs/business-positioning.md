# Skill Scanner — 产品定位

> 公开版 | 完整商业计划内部持有

---

## 市场背景

Agent Skills 生态正快速发展（OpenAI / Anthropic / MCP）。有 Skill Registry 就有恶意包，有恶意包就需要安全扫描。

## 产品定位

Agent Skills 的 Surface Diff — 检测能力边界变化，不是检测恶意代码（Snyk 在做），而是检测"这个版本多了什么权限"。

## 商业模式

Open Core — 核心扫描引擎 MIT 开源。企业功能（合规报告、RBAC、SSO）付费。详见 LICENSE。

## 竞争要点

- **Promptfoo** — LLM eval，不覆盖 skill 供应链
- **LangSmith** — Observability，不做发布前扫描
- **Snyk ToxicSkills** — 恶意 pattern 匹配，不做版本能力对比
- **Skill Scanner** — Skill Surface Diff + Policy-as-Code + 7 维全表面审计
