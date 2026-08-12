# proxy-vps-skills

这是给 `ProxyConfig` 仓库使用的 Codex skills 集合，目标是把代理配置维护中容易漏改、容易跨客户端不一致的操作沉淀成可复用工作流。

当前重点覆盖 Egern、Mihomo、Stash、Surge、Loon 的代理组、DNS 路由、规则策略和一致性审计。Surge split config 同步不在本仓库实现，因为已经由专门的 GitHub Action 处理。

## 命名约定

本仓库里的所有 skill 都要使用明确的域名前缀，方便在 Codex 中搜索和调用。目录名和 `SKILL.md` frontmatter 的 `name` 必须一致，并优先使用 `proxy-`、`vps-` 这类前缀；`agents/openai.yaml` 里的 default prompt 也要使用相同的 `$skill-name`。

## Skills

| Skill | 用途 | 典型场景 |
| --- | --- | --- |
| `proxy-groups` | 维护代理组、机场 provider、自建 VPS 组、地区组、Relay/Dialer、`MassData`、`Others`，并维护 provider source 元数据。 | 新增/删除/重命名机场；新增 `PO0 SG`；拆分 `Core JP`/`Edge JP`；修改 provider URL、Sub-Store 名称、cache path、节点 prefix。 |
| `proxy-dns-routing` | 维护 DNS 解析路径，重点关注 AirportServers、机场节点域名、provider 专用 DoH、Egern `dns.forward`、Mihomo `proxy-server-nameserver-policy`、Surge Host 映射。 | 更新 AirportServers 引用；给机场节点域名指定 DoH；排查节点域名解析路径；避免代理启动前 DNS 依赖错误。 |
| `proxy-rule-policy-routing` | 维护 rule-provider 到 policy group 的路由关系和跨客户端规则顺序。 | 新增/调整 `AI Suite`、`PayPal`、`Banking`、`Crypto`、`Apple Push`、`HTTPDNS`、流媒体、`Speedtest`、`MyProxy`/`MyDirect` 等规则；检查规则目标与优先级契约。 |
| `proxy-config-consistency-audit` | 只读一致性审计，不直接修改配置。 | 检查 Egern/Mihomo/Surge provider 是否不一致；地区组是否缺 HK/TW/SG/JP/US；删除机场后是否还有残留引用；规则是否指向不存在的策略组。 |

## 推荐用法

在 Codex 中直接点名 skill，例如：

```text
用 $proxy-groups 给 Egern 和 Mihomo 增加 LiangXin 机场，各地区组用 select。
```

```text
用 $proxy-dns-routing 检查 AirportServers 和 CTC 节点域名的 DNS 路由。
```

```text
用 $proxy-rule-policy-routing 把 PayPal、Banking、Crypto 连续放到 AI 后面，并检查所有客户端顺序。
```

```text
用 $proxy-config-consistency-audit 审计当前 ProxyConfig 有没有漏引用。
```

## 审计脚本

每个维护型 skill 都带一个只读审计脚本，脚本均不依赖第三方库：

```powershell
& "<python>" "skills/proxy-groups/scripts/audit_proxy_refs.py" "D:\GitRepo\ProxyConfig" --target LiangXin
```

```powershell
& "<python>" "skills/proxy-dns-routing/scripts/audit_dns_routing.py" "D:\GitRepo\ProxyConfig" --airportservers --domain ctcxianyu.com
```

```powershell
& "<python>" "skills/proxy-rule-policy-routing/scripts/audit_rule_policy_refs.py" "D:\GitRepo\ProxyConfig"
```

```powershell
& "<python>" "skills/proxy-config-consistency-audit/scripts/audit_proxy_consistency.py" "D:\GitRepo\ProxyConfig"
```

## 边界

- 不实现 `sync-surge-split-config`，Surge split 同步交给现有 GitHub Action。
- Provider source 维护没有单独拆成独立 skill，已经并入 `proxy-groups`。
- `proxy-config-consistency-audit` 是只读审计入口；需要修复时，再切到更具体的维护 skill。
- skill 内部不放额外 README；具体操作模型放在各自 `references/` 下，脚本放在各自 `scripts/` 下。
