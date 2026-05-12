# Codex Round 2 — 吸收总结

**日期：** 2026-05-12
**基线：** `ff5e3dc`（审计时）→ `d076dbe`（修复后）
**标题：** 10 issues, 10 fixes — 安全工具免疫 + Policy 驱动决策 + 不空洞合规

---

## 审计范围

Codex 第二轮审计聚焦 `skill_scanner/` 自身安全、边界攻击、Diff 引擎、企业层。

**不审计：** `demos/skill-scanner/agent-skills-scan.py`（提交 #1 的单文件 PoC，不反映生产代码）

---

## 吸收清单

### 1. 安全工具免疫（建立"扫描器假设自身输入是恶意的"原则）

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| Manifest 路径拼接无校验，`../../etc/passwd` 可读扫描器外部文件 | `safe_join()` — normalize → resolve → 确认在 skill_dir 内，拒绝绝对路径 + symlink escape | `parser.py` |
| TraceRecorder 的 `skill_name`/`version` 拼文件名，可路径穿越写入 | `_sanitize_id()` 只允许 `[A-Za-z0-9._-]` + `resolve()` 确认在 storage_dir 内 | `trace_engine.py` |
| Registry scanner 任意 URL 直接 urlopen，SSRF 风险 | 域名 allowlist (`raw.githubusercontent.com`/`github`/`clawhub`) + 私有 IP 检测 + 1MB 响应限制 + 10s timeout | `registry.py` |
| OPA subprocess 无资源边界 | 有参数式调用（非 shell），policy 路径限制在 policy_dir 内，timeout 默认短 | `policy_engine.py` |

### 2. Policy 必须驱动决策

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| `engine.py` 的 blocked 由 `len(critical) > 0` 决定，不是 policy verdict | 改为 `blocked = verdict.get("verdict") is False` | `engine.py` |
| `PolicyEngine._evaluate_with_builtin()` 的 `block_on`/`warn_on` 未真正决定 block | 统一走 policy verdict 判断 | `engine.py` |
| Diff 失败静默吞掉 | 生成 `DF000` finding（critical + block） | `engine.py` |

### 3. 所有 Scanner 统一解析入口

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| instruction/permission/dependency scanner 仍直接 `yaml.safe_load(SKILL.md)` | 全部改用 `parse_skill()`，支持 front matter + body 和纯 YAML 双模式 | `scanners/*.py` |
| manifest scanner 已接入但其他 scanner 未跟 | 全部统一 | 以上全部 |
| `_build_baseline_trace()` 用 raw `yaml.safe_load` | 改为 `parse_skill()` | `engine.py` |

### 4. 格式输出规范

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| `--format junit`/`markdown` 是假选项（fallback to terminal） | 完整实现 JUnit XML + Markdown PR comment 格式 | `cli.py` |
| SARIF format 不规范（无 severity 映射、rules 重复、passed 进入 results） | dedup rules、extract line number、排除 passed、severity→SARIF level | `cli.py` |

### 5. 边界攻击防护

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| Parser 无输入大小限制 | 1MB max file size, CRLF 支持, UTF-8 errors=replace | `parser.py` |
| AgentSurfaceScanner 递归 glob 无上限 | `_safe_glob()` — 排除 `.git`/`node_modules`/`venv`/`__pycache__` + 500 文件限制 | `agent_surface.py` |
| Encoding 绕过 / YAML bomb | YAML SafeLoader + 字节数 pre-check | `parser.py` |

### 6. 企业层修复

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| Compliance report 空洞合规 — 未扫 dimension 仍标 compliant | 增加 `coverage_status: covered/not_covered/no_evidence`，`not_covered` 不能标 compliant | `enterprise.py` |
| RBAC 不识别 config 中自定义 roles | `can()` 改为从 `self.config.get("roles", self.ROLES)` 读取 | `enterprise.py` |
| RBAC 缺 baseline_approve/exception_approve 权限 | 补充权限定义 | `enterprise.py` |
| Finding schema 无校验 | `validate_finding()` 在 parser.py 中，要求 `id`/`severity`/`rule`/`title`/`file` 等 | `parser.py` |

---

## 保留待办（不急但值得）

| 待办项 | 优先级 | 说明 |
|--------|--------|------|
| Source→sink capability flow tracking | P2 | 不在当前 scanner 范围内，需新数据结构 |
| Baseline 签名/digest/baseline manifest | P2 | 目前是路径比较，无内容 hash |
| 真正 Skill Surface Diff 数据结构 | P2 | 当前是伪 trace diff，需要 unified SkillSurface |
| Webhook domain allowlist / redaction | P2 | 企业功能，当前阶段不紧急 |
| OPA eval memory limit | P2 | 当前有 timeout 无 mem limit |
| Agent surface audit 声明 coverage: partial | P2 | 企业用户预期管理 |
| 编码绕过 pattern | P2 | 当前 regex 可被 python requests / node fetch 绕过 |

---

## 状态变化

```
v0.3.0 (ff5e3dc) → v0.3.0 (d076dbe)
├─ 11 files changed, +393/-163
├─ 4 P0 security fixes
├─ 6 P1 boundary/enterprise fixes
├─ 5 scanners → all unified under parse_skill()
├─ SARIF/JUnit/Markdown → all implemented
└─ 3 fixtures passing
```
