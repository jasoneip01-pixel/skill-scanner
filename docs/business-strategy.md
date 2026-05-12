# Skill Scanner — 商业分析 & 战略路径图

> 基于产品定义书 v1.0 | 2026-05-12

---

## 一、产品路径图（4 Phase × 18 个月）

### Phase 1: MVP — CLI + CI/CD Gate（0-3 月）

**目标：** 让早期 adopters 在 PR 中能用

| 里程碑 | 交付物 | 验证指标 |
|--------|--------|----------|
| M1.1 核心扫描引擎 | 5 个 scanner（Manifest/Script/Instruction/Permission/Dependency），13+ 检查项全部就绪 | 对 test-skill 夹具扫描准确率 100% |
| M1.2 CLI 正式版 | `agent-skills scan`、`--policy`、`--diff`、`--format sarif` 等完整命令 | <100ms 扫描单个 skill |
| M1.3 GitHub Action | Marketplace 发布 `agent-skills/scan-action` | 任意仓库一键接入 |
| M1.4 策略模板库 | security.strict / moderate / permissive 三套预置策略 | 用户可 `policy init` 一键生成 |
| M1.5 文档站 | 产品定义书 + 使用指南 + 策略语法文档 | 开发者 5 分钟内跑通首次扫描 |

**此阶段核心差异化点：Skill Surface Diff**（版本间能力边界对比）——这是 Snyk 还没做、Promptfoo 做不了的东西。

---

### Phase 2: Policy Engine + Trace（3-8 月）

**目标：** 从"扫描器"升级为"安全门"

| 里程碑 | 交付物 | 商业意义 |
|--------|--------|----------|
| M2.1 OPA/Rego 策略引擎 | 用户可写自定义 Rego 规则，`policy validate` | 企业级可编程安全策略 |
| M2.2 基线轨迹回放 | `agent-skills trace` — 记录 skill 运行时的工具调用链，与基线对比 | "Dev 说的"vs"Prod 做的"——差异化护城河 |
| M2.3 工具权限契约测试 | 声明`read-only`的工具实际调了`write` API → 自动告警 | 解决 MCP 生态最大痛点 |
| M2.4 生产事故→回归测试 | 生产中发现越权 → 一键生成 regression test case | 闭环——安全事件不重复出现 |
| M2.5 Slack/Teams 通知集成 | PR 评论外，支持 ChatOps 通知 | 企业工作流嵌入 |
| M2.6 自托管版 | Docker 镜像 + Helm chart，支持私有部署 | 金融/医疗等合规敏感客户 |

---

### Phase 3: Registry Scanner（8-14 月）

**目标：** 成为 Skill 生态的基础设施

| 里程碑 | 交付物 | 生态价值 |
|--------|--------|----------|
| M3.1 公共 Registry 监控 | 自动扫描 OpenAI/Anthropic/MCP 官方 skill registry 新发布 skill | 像 npm audit 一样，`skill audit` |
| M3.2 恶意 Skill 数据库 | 社区提交 + 自动发现 → 公共恶意 skill 列表 | 网络效应——个人贡献数据，企业消费数据 |
| M3.3 社区签名机制 | Skill 作者可签名，Scanner 验证签名 | "这个 skill 真的是原作者发布的吗" |
| M3.4 Skill Trust Score | 基于扫描结果 + 社区反馈 + 下载量的信誉评分 | 类似 Chrome Web Store 评分 |
| M3.5 VS Code Extension | IDE 内扫描 + 实时提示 | 开发体验——在写 skill 时就看到安全问题 |

---

### Phase 4: Agent Release Gate（14-18 月）

**目标：** 不只是扫描 skill，而是扫描 Agent 的整个能力面

| 里程碑 | 交付物 | 愿景 |
|--------|--------|------|
| M4.1 Agent Surface 全量扫描 | skill + tool + prompt + model + RAG + memory + permission 七维扫描 | 每次 Agent release 前的完整安全门 |
| M4.2 企业 SSO + RBAC | SAML/OIDC 集成，角色权限管理 | 大企业采购前提 |
| M4.3 合规报告 | SOC2/GDPR/PCI-DSS 就绪的合规审计报告 | 卖给 CISO，不是卖给 dev |
| M4.4 多云部署 | AWS/Azure/GCP marketplace | 政府采购/大企业私有云 |

---

## 二、商业模式 & 盈利模型

### 核心判断：Open Core（开源核心 + 付费功能）

| 层 | 内容 | 定价策略 |
|----|------|----------|
| **开源社区版** | CLI + GitHub Action + 5 个基础 scanner + 公开 registry 扫描 | 永远免费，MIT 协议 |
| **Pro 个人版** | 高级策略引擎 + Trace replay + 私有 registry 扫描 + VS Code 插件 | $19/月 或 $190/年 |
| **Team 团队版** | 自定义 Rego 策略 + 团队协作 + Slack 集成 + 优先支持 | $49/席位/月 |
| **Enterprise 企业版** | 自托管 + SSO + RBAC + 合规报告 + SLA + 专属支持 | $25K-150K/年 |

### 为什么是 Open Core 而不是纯 SaaS 或纯开源？

| 路径 | 优点 | 致命问题 | 结论 |
|------|------|----------|------|
| 纯开源 | 社区增长快，信任度高 | 没有收入，无法持续投入 | ❌ |
| 纯 SaaS | 收入直接 | 安全工具天然有"我的 skill 数据不想上传"的顾虑 | ❌ |
| 闭源单机 | 定价清晰 | 安全工具需要透明——"你凭什么说我的 skill 有毒？" | ❌ |
| **Open Core** | 社区增长 + 企业付费 + 代码透明建立信任 | 需要平衡免费/付费边界 | ✅ |

关键：**扫描核心必须开源**——安全工具的信任建立在可审计性上。"你判断我的 skill 有毒？让我看看你的检测逻辑。"

### 收入模型（18 个月预测）

| 阶段 | 时间 | 累计用户 | ARR | 主要收入源 |
|------|------|----------|-----|------------|
| MVP | 0-3 月 | 500 | $0 | 免费，积累 GitHub stars + 案例 |
| Phase 2 | 3-8 月 | 5,000 | $120K | Pro 个人版（5% 转化率） |
| Phase 3 | 8-14 月 | 25,000 | $800K | Team 版（200 团队）+ Pro |
| Phase 4 | 14-18 月 | 80,000 | $3.5M | Enterprise（15-20 家）+ Team |

**盈利拐点：** 预计第 14-18 个月实现 EBITDA 盈利。

---

## 三、竞争格局深度分析

### 3.1 竞争金字塔

```
          ┌──────────────────────┐
          │  Agent Release Gate   │  ← 我们 Phase 4
          │  (Snyk + Wiz 逻辑)    │
          ├──────────────────────┤
          │  Skill Surface Diff   │  ← 我们 Phase 1-2 (核心差异)
          │  Policy-as-Code Gate  │
          ├──────────────────────┤
          │  Skill Supply Scan    │  ← Snyk ToxicSkills 已进入
          │  (恶意 pattern 检测)  │
          ├──────────────────────┤
          │  Prompt Eval / Obs    │  ← Promptfoo, LangSmith
          │  (不直接竞争)         │
          └──────────────────────┘
```

### 3.2 逐家分析

#### Snyk（最危险的竞争对手）

- **2026 年已发布 ToxicSkills 研究** + mcp-scan
- 优势：品牌、渠道、资金、现有企业客户群
- 劣势：Snyk 的基因是"扫描代码里的 CVE"，不是"理解 Agent 的行为意图"。Agent 安全需要不同的 threat model
- **我们的策略：** 不做 Snyk 已经在做的事（恶意 pattern 匹配），做 Snyk 还没做的事（版本间能力边界对比 + 策略引擎 + trace replay）
- **时间窗口：** Snyk 可能在 12-18 个月内进入全面竞争。我们必须在 12 个月内建立社区护城河

#### Promptfoo

- 定位：LLM output eval + prompt 级别的 security scan
- 不覆盖：skill 目录的脚本、指令、权限、资源文件
- **差异化：** "你的 prompt 被注入了吗？" vs "你装的这个 skill 把你卖了吗？"——完全不同的 threat model

#### LangSmith / Langfuse

- 定位：Agent observability + trace
- 不覆盖：发布前安全扫描
- **互补而非竞争：** Phase 2 的 trace replay 功能可以与 LangSmith 集成——"在 LangSmith 观察到异常 → 在 Skill Scanner 生成 regression test"

#### 潜在新进入者

- **GitHub**（如果推出 Skill Marketplace 的 security scanning）——最大的威胁，但也是最大的机会（可能被收购）
- **OpenAI / Anthropic 官方扫描器** —— 最可能出现的局面：我们定义标准，他们官方实现。策略：开源 + 社区 + 跨平台（支持所有 agent 框架），成为事实标准而非官方工具

### 3.3 竞争护城河

| 护城河 | 强度 | 说明 |
|--------|------|------|
| Skill Surface Diff 概念 | 🔴 强 | 能力边界对比这个 framing 是首创，Snyk 没做 |
| 社区网络效应 | 🟡 中 | Registry 扫描 → 恶意 skill DB → 社区贡献 → 数据越好 → 用户越多 |
| 开源透明性 | 🔴 强 | 安全工具不开源 = 没人信。这是对闭源竞品的天然壁垒 |
| 跨平台兼容 | 🟡 中 | 不绑定 OpenAI/Anthropic，支持所有 Skill 格式 |
| 先发时间窗口 | 🟢 弱（6-12 月） | 只能靠速度，不能靠专利 |

---

## 四、开源 vs 闭源：深度分析

### 4.1 结论：Open Core，核心扫描引擎 MIT 协议

**推理链：**

1. **信任需求** — 安全扫描工具的本质是"我判断你的代码有风险"。如果扫描逻辑不透明，这个判断无意义。→ **核心必须开源**

2. **社区增长** — 目标用户（Agent 开发者）天然偏好开源工具。闭源安全工具在 dev 社区几乎没有成功案例。→ **开源是增长引擎，不是成本**

3. **收入来源** — 个人开发者不会为 CLI 付费，但企业会为合规报告、SSO、自托管、SLA 付费。→ **企业功能是收入来源**

4. **护城河** — 开源本身就是对闭源竞品的护城河。"你凭什么说我 skill 有毒？"——"代码在这，你自己看。"闭源竞品无法回答这个问题。

### 4.2 开源策略细节

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 协议 | MIT | 最大化采用。GPL 会吓跑企业用户 |
| CLA | 不需要 | 社区贡献 MIT 协议直接合入，降低摩擦 |
| 开源范围 | 核心扫描引擎 + CLI + GitHub Action + 公共 registry 扫描 | "开发者需要的都免费" |
| 闭源范围 | 企业功能：Trace replay engine、合规报告生成器、SSO/RBAC、自托管管理面板 | "企业买单的都付费" |
| 社区治理 | 维护者说了算，接受社区 PR | 初期不需要 formal governance |
| 商标 | 注册商标，防止混淆 | 类似 GitLab CE vs EE 的商标策略 |

### 4.3 开源风险 & 应对

| 风险 | 概率 | 应对 |
|------|------|------|
| 大厂 fork 做竞品 | 中 | 商标保护 + 社区是护城河 + 速度优势 |
| 开源后收入不够 | 低-中 | 企业功能闭源 + 自托管壁垒足够高 |
| 社区贡献质量差 | 中 | CI 门禁 + 核心维护者 review |
| 安全漏洞被利用 | 中 | 这是安全工具的特有问题——开源意味着攻击者也能看到检测逻辑。应对：规则 vs 引擎分离，规则可定期更新 |

---

## 五、融资策略

### 5.1 融资阶段规划

| 轮次 | 时间 | 金额 | 估值 | 用途 | 里程碑 |
|------|------|------|------|------|--------|
| Pre-seed | M0-M3 | $500K | $5M | MVP 开发 + 内容营销 | GitHub 1K stars, 500 用户 |
| Seed | M6-M9 | $2-3M | $15-20M | Phase 2 开发 + 3 人团队 | 10K 用户, 20 付费团队 |
| Series A | M14-M18 | $8-12M | $60-80M | Phase 3-4 + 10 人团队 | 50K 用户, ARR $1M+ |

### 5.2 为什么需要融资而不是 Bootstrap？

- 时间窗口只有 6-12 个月（Snyk 已注意到这个赛道）
- 需要快速建立社区护城河（内容、集成、案例）
- 企业销售需要人手（SSO、合规、支持）

### 5.3 投资人叙事（Pitch Deck 主线）

```
          现在                         未来
           │                           │
 OpenAI/Anthropic 推 Skills ──→ Skill Registry 出现 ──→ 恶意 Skill 爆发
           │                           │
       没有人做安全扫描          Skill Scanner 在这里
           │                           │
    ┌──────┴──────┐              ┌─────┴─────┐
    │  npm 2013   │              │ Snyk 2015 │
    │ 没有 audit  │  ──类比──→   │ $7.4B 估值│
    └─────────────┘              └───────────┘
```

- **市场 timing：** Agent Skills 生态 = 2013 年的 npm。安全扫描工具 = 2015 年的 Snyk。我们现在就是 2015。
- **为什么是现在：** OpenAI 和 Anthropic 同时推 Skills，MCP 协议标准化。2026 是 Skill 供应链安全的元年。
- **为什么是我们：** 产品定义书的 "Skill Surface Diff" 是一种新的安全 paradigm——不是扫描恶意代码，是扫描能力边界变化。Snyk 在扫"有没有毒"，我们在扫"这个版本多了什么能力"。
- **退出路径：** GitHub / GitLab 收购（如果推出 Skill Marketplace）或 Snyk / Wiz 收购（补齐 Agent 安全线），或 IPO（如果市场规模足够大）。

### 5.4 融资要避免的坑

- ❌ 不要说"我们是 Agent 安全的 Snyk"——投资人会问"那 Snyk 自己做怎么办？"
- ✅ 要说"我们定义了新的安全原语——Skill Surface Diff。Snyk 扫 CVE，我们扫能力边界。"
- ❌ 不要过早承诺收入数字——Phase 1 就是做社区
- ✅ 用 GitHub stars / 下载量 / 社区案例做 traction 指标

---

## 六、关键风险 & 对冲

| 风险 | 影响 | 概率 | 对冲策略 |
|------|------|------|----------|
| Snyk 全量进入 | 高 | 中（12-18 月） | 差异化：Surface Diff + Policy Engine，不做 pure pattern match |
| OpenAI 推出官方扫描器 | 高 | 中-高 | 跨平台兼容（不只支持 OpenAI），开源社区标准 |
| 市场规模小于预期 | 高 | 低-中 | Phase 3 Registry 扫描 → 如果 Skill 生态不够大，pivot 到 MCP tool security |
| 开源后商业转化率低 | 中 | 中 | 企业功能 (SSO/RBAC/合规报告) 对 developer tools 有强付费意愿 |
| 安全责任 | 中 | 低 | 明确免责声明，不承担"扫描通过=绝对安全"的责任 |

---

## 七、行动建议（接下来 30 天）

1. **完成 CLI MVP** — 把 agent-skills-scan.py 升级为可发布的 pip 包
2. **发布 GitHub Action** — Marketplace 上线，这是最快的分发渠道
3. **写 3 篇技术博客** — "Agent Skill 供应链安全威胁模型"、"为什么 promptfoo 不够"、"Skill Surface Diff 是什么"
4. **在 Hacker News / Reddit r/agenticai 发布** — 社区是第一增长引擎
5. **联系 10 个早期用户** — Agent SDK 开发者、MCP 工具作者，拿真实反馈
6. **准备 Seed Deck** — 按上面的叙事主线做 12 页 pitch deck
