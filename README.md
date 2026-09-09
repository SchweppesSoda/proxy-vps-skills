# proxy-vps-skills

这是给 `ProxyConfig` 使用的 Codex skills 集合，把跨客户端代理配置维护中
容易漏改、容易漂移、容易误写 generated 文件的操作沉淀成可复用工作流。
当前覆盖 Mihomo、Surge、Stash、Loon、Egern，以及与 CustomRules 的公开规则
产物关系。

## Skills

| Skill | 用途 | 触发边界 |
| --- | --- | --- |
| `proxy-groups` | 维护代理组、provider source、Sub-Store collection、节点前缀和消费者引用。 | 普通 provider/group 身份、成员和 source 变更；跨 generated writer 时联合 `proxy-generated-config-sync`。 |
| `proxy-dns-routing` | 维护 AirportServers、机场节点域名、DoH、DNS upstream、Host 映射和实际 DNS 解析。 | 普通 DNS 语义和人工投影；涉及 Airport DNS/Provider Compatibility writer 时联合 generated skill。 |
| `proxy-rule-policy-routing` | 维护 rule-provider、规则顺序和 rule-to-policy 映射。 | 普通规则与策略语义；涉及 CustomRules build、marker 或派生文件时联合 generated skill。 |
| `proxy-config-consistency-audit` | 只读编排五客户端、规则、DNS、provider 和 generated writer 一致性。 | 用户要求的审计或跨领域漂移；不作为每次修改的前后置门禁。 |
| `proxy-generated-config-sync` | 维护 generated writer ownership、marker/field/whole-file scope、锁、事务和跨仓发布边界。 | 仅用于 Airport DNS、Provider Compatibility、OpenWrt→WAN2、Surge full→split、CustomRules 发布及 writer 合同。 |

## 安装

发布到远程仓库后，分别安装需要的 skill：

```powershell
npx skills add SchweppesSoda/proxy-vps-skills --skill proxy-groups
npx skills add SchweppesSoda/proxy-vps-skills --skill proxy-dns-routing
npx skills add SchweppesSoda/proxy-vps-skills --skill proxy-rule-policy-routing
npx skills add SchweppesSoda/proxy-vps-skills --skill proxy-config-consistency-audit
npx skills add SchweppesSoda/proxy-vps-skills --skill proxy-generated-config-sync
```

开发中的未提交版本不会被 `npx` 从远程仓库拉取；应先同步本机源码与 skill
安装目录，发布并推送后再使用上述命令安装或更新。

常见联合路由：

| 变更 | 必选 skill | 条件性联动 |
| --- | --- | --- |
| provider URL/path/collection | `proxy-groups` | URL host 同时是节点解析对象时加 `proxy-dns-routing`；跨 generated scope 时再加 generated skill。 |
| 可见 group/policy rename | `proxy-groups` | 存在 rule consumer 时加 `proxy-rule-policy-routing`。 |
| rule target add/remap/delete | `proxy-rule-policy-routing` | 同时新增、删除或重命名 group 时加 `proxy-groups`。 |
| Airport DNS / Provider Compatibility / derivative / publication | 对应 domain skill | 必须同时使用 `proxy-generated-config-sync`。 |

## Source of truth

```text
Surge/AutoSurge.conf                    canonical full profile
    └─ Surge/Split Conf/AutoSurge/       generated split output

Mihomo/AutoMihomo.OpenWrt.yaml           canonical OpenWrt baseline
    └─ Mihomo/AutoMihomo.OpenWrt-WAN2.yaml generated whole-file derivative

CustomRules master sources               reviewed rule inputs
    └─ CustomRules auto-build branch     generated YAML/MRS/LIST artifacts
```

`Sub-Store/config/generated-writers.json` 是 schema 1 的薄 ownership 索引；
它只记录 writer、输入、目标 scope、workflow、锁、validator 和有意排除项，
不记录 provider 数据、完整 capability URL、token 或 credential。具体算法和
易变数据仍由仓库脚本、manifest、registry、workflow 与测试负责。

## 推荐用法

在 Codex 中点名 skill，例如：

```text
用 $proxy-groups 检查一个 provider rename 的 source → collection → artifact → consumer 链。
```

```text
用 $proxy-dns-routing 审计 AirportServers 和某个节点域名的 DNS 路径。
```

```text
用 $proxy-rule-policy-routing 调整规则并保持 AI → PayPal → Banking → Crypto 顺序。
```

```text
用 $proxy-generated-config-sync review Provider Compatibility writer 的 marker 和锁。
```

```text
用 $proxy-config-consistency-audit 审计当前 ProxyConfig 的跨客户端和 generated 漂移。
```

## 审计脚本

命令中的 `<proxyconfig-root>` 是包含 `Mihomo/`、`Surge/`、`Stash/`、`Loon/`、
`Egern/` 的 checkout；`<proxy-vps-skills-root>` 是包含 `skills/` 的 checkout。
不要把本机盘符或个人安装路径写进 skill、日志或提交：

```powershell
& "<python>" "<proxy-vps-skills-root>/skills/proxy-groups/scripts/audit_proxy_refs.py" "<proxyconfig-root>" --target "<name>"
& "<python>" "<proxy-vps-skills-root>/skills/proxy-dns-routing/scripts/audit_dns_routing.py" "<proxyconfig-root>" --airportservers
& "<python>" "<proxy-vps-skills-root>/skills/proxy-rule-policy-routing/scripts/audit_rule_policy_refs.py" "<proxyconfig-root>"
& "<python>" "<proxy-vps-skills-root>/skills/proxy-config-consistency-audit/scripts/audit_proxy_consistency.py" "<proxyconfig-root>"
```

Surge split 同步由 ProxyConfig 的现有 workflow 负责，不新增一个重复的
split skill。编辑 canonical full profile，报告 split drift，并等待 workflow
完成后再使用需要 generated sync 已完成的验收项。

## 设计边界

- 普通 group、DNS、rule 工作分别由前三个 domain skill 负责；generated
  skill 只在跨越 writer 合同时触发。
- 同一物理文件允许多个 writer，但 marker/field scope 必须不重叠且共享同一
  concurrency group。
- generated 文件只能由授权 repo-owned CLI/generator 生成；手工配置主体和
  canonical input 保持在其各自 scope。
- consistency audit 是只读入口；需要修复时转交具体 domain skill，再由
  generated skill 负责生成/发布验收。
- 不在 skill 内复制仓库同步算法、provider inventory 或 secret-bearing source。

## 仓库维护入口

[AGENTS.md](./AGENTS.md) 记录本仓 `main`、单仓写入、验证与提交约定。此仓只维护工作流和审计工具；公共规则源与发布在 [CustomRules](https://github.com/SchweppesSoda/CustomRules)，运维脚本在 [VPS-Toolkit](https://github.com/SchweppesSoda/VPS-Toolkit)，配置及设备恢复资料在各自私有仓库。修改 skill 入口、引用或 UI 元数据时同步对应个人安装副本；仅仓库 README/AGENTS 修改不重装 skill。


## 渐进读取与完成标准

`SKILL.md` 只保留能力边界、路由和关键合同；`references/` 承载有条件的业务细节。
从任务对象与直接消费者开始，重命名/删除共享身份才扩展引用检查。无需每次
先后运行全局审计。`--target`、`--domain`、`--policy` 主要聚焦报告，脚本仍可执行
共享检查；不要把既有无关发现自动升级为本次修复范围。Mihomo kernel helper 用
重复 `--config` 限定受影响 profiles。正式生成/发布保留对应门禁。

本地完成包括请求的修改、相关生成/检查、文档和范围明确的提交。已授权的操作
继续执行；没有发布授权时报告已完成的本地结果和待发布状态。

路由复核示例：

| 请求 | 主路由及范围 |
| --- | --- |
| 只改一个人工 DNS mapping | DNS；该 mapping/upstream 引用，非全部 writer |
| 把某服务改到已有策略组 | Rule；目标与邻接顺序，不重做组定义 |
| provider 改名并清理消费者 | Groups；跨客户端 aliases，存在 rule 消费者才联动 Rule |
| 修复 WAN2 生成逻辑 | Generated；WAN2 tests/check 与受影响语义，非全部流水线 |
| 审计并修复所有客户端漂移 | Audit 后按发现进入维护路由；原请求已包含修复授权 |
| 只改 Skill 或 README | 指令/frontmatter/链接核验，不运行真实配置生成、部署或全套业务测试 |
