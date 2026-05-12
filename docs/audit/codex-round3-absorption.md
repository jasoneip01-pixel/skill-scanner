# Codex Round 3 — 吸收总结

**日期：** 2026-05-12
**基线：** `d076dbe`（审计时）→ `197e5fc`（修复后）
**标题：** SSRF 每跳校验 + OPA 永不静默 + 扫描器资源边界

---

## 审计范围

Codex 第三轮聚焦攻击 `d076dbe` 上新加的安全防御、审计测试缺口、Surface Diff 架构设计、Phase 1 发布差距、Rego 规则表达力。

**不审计：** `demos/skill-scanner/agent-skills-scan.py`、产品定义页面、landing page

---

## 吸收清单

### 1. SSRF：redirect 每跳校验 + 完整私网 IP 检测

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| 只检查初始 hostname，redirect 链每跳可绕过 | `ValidatingRedirectHandler` 每跳重新校验：域名 allowlist + 私网 IP + https 方案 | `registry.py` |
| `172.16.` 字符串前缀漏挡 `172.17-31.*` | `ipaddress.ip_address().is_private` 完整覆盖所有 RFC 1918 + loopback + link-local | `registry.py` |
| `resp.read(1MB)` 截断后扫描不完整 SKILL.md | `read(MAX_BYTES + 1)`——超额直接拒绝，不扫描残缺内容 | `registry.py` |
| 未限制 scheme | 必须 https | `registry.py` |
| 不可解析域名 → 继续处理 | 返回 True（block），防止 DNS 绕过 | `registry.py` |

### 2. OPA fallback 不再是危险静默

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| `_parse_opa_output()` 失败 → `verdict: true`（最危险的静默通过） | `verdict: false` + `blocked_rules: ["opa.evaluation_failed"]` | `policy_engine.py` |
| Engine 不感知 OPA 失败 | Engine 检测 `verdict.engine == "opa_fallback"`，生成 `OP001` critical finding | `engine.py` |

### 3. 扫描器资源边界防护

| Codex 发现 | 修复 | 文件 |
|------------|------|------|
| `script.py` 无文件大小限制，500MB 脚本直接 `read_text()` | 1MB 上限 + `SC001` finding；二进制文件检测 + `SC002` finding | `scanners/script.py` |
| `dependency.py` 的 `rglob("*")` 递归无限 | 500 文件上限 + 隐藏目录跳过 + `RS003` 截断 finding | `scanners/dependency.py` |
| `dependency.py` `stat()` 无异常处理 | 加 `try/except OSError` | `scanners/dependency.py` |

### 4. 建议但未采纳（有理由）

| Codex 建议 | 理由 |
|------------|------|
| `_sanitize_id()` strict mode 拒绝非法字符 | 保持替换 + log；拒绝会造成合法 Unicode skill name 的 friction。可加企业配置项但不迫 |
| `safe_join()` 全部 pytest 用例 | 单层 resolve + `resolve(strict=False)` 比较已足够，不需要全部 test case |
| `agent_surface.py` 测试矩阵 | 这一轮 scope 是 core scanner + engine，enterprise 层后续覆盖 |

---

## Phase 1 发布缺口（记录待办）

| 缺口 | 状态 | 说明 |
|------|------|------|
| `.github/workflows/test.yml` | ❌ 不存在 | Phase 1 发布前需创建 |
| `.github/actions/` | ❌ 不存在 | Phase 1 发布前需创建 |
| `action.yml` | ❌ 不存在 | GitHub Action 入口 |
| `tests/` 目录 | ❌ 不存在 | pytest 覆盖率 0 |
| PyPI build 验证 | ❌ 没验证过 | `python -m build` 未测试 |
| README 命令一致性 | ❌ 未比对 | CLI 行为和文档站可能不同步 |

---

## Surface Diff 架构（记录设计参考）

Codex 给出了 `SkillSurface` / `SurfaceDiff` dataclass schema，覆盖 tools/scripts/instructions/network/resources/file_access/suspicious_fields 7 个维度。当前 `--diff` 仍是伪 trace diff（method 硬编码 GET），统一 SkillSurface 是 Phase 4 内容。

设计文件将参考：
- `skill_scanner/surface.py` — `extract_surface(skill_dir) -> SkillSurface`
- `skill_scanner/diff.py` — `diff_surface(old, new) -> list[SurfaceDiff]`

---

## 状态变化

```
v0.3.0 (d076dbe) → v0.3.0 (197e5fc)
├─ 5 files changed, +112/-20
├─ SSRF: redirect每跳校验 + ipaddress模块 + https必须 + 超额拒绝
├─ OPA: 失败不再静默通过(verdict:false + OP001 critical finding)
├─ Script: 1MB上限 + 二进制检测
├─ Dependency: rglob 500上限 + 截断警告
└─ 待办: tests/ + CI + Action + PyPI验证 (Phase 1发布缺口)
```
