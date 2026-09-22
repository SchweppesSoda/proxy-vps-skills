# 2026-09-21 审计工具现役覆盖

规则审计原有固定清单遗漏独立 canonical `Egern/AutoEgernLite.yaml`，却保留退役 `Loon/AutoLoonLite.conf`。现改为 Egern Full/Lite、Mihomo Mobile/OpenWrt/Safe、Loon Full、Stash 共七份现役 canonical 配置；Egern Lite 沿用自己的组定义、finance 合同和规则子序列，不要求完整 Apple/TV 等服务集。

规则审计与全局 consistency 审计均输出 `checked`、`skipped`、`missing`。全局保留 `scanned` 兼容键。缺失 canonical 文件时退出 2，表示检查不完整；全局检查只覆盖可见定义和 writer 结构，规则语义、DNS 与核心运行验证仍各自归属现有工具。发现衍生文件不等于执行生成器或证明生成文件一致。退役 Loon Lite 若仍存在，明确归为 skipped，不再计入现役消费者。

离线验证：规则 10 项、全局 10 项全部通过；新增 Egern Lite 未定义 policy、缺失现役配置、退役文件存在仍不能代替现役 Lite 的反例。测试禁止网络与子进程，临时写入隔离目录。两份受影响 SKILL 的 quick_validate 通过。现有仓库只读检查显示七份已检查、三份衍生跳过、零缺失；规则审计零问题，全局保留既有四条 PO0 四地区合同造成的提示，未把它们当作本轮回归或自动修复。

只改 skill 源码。本轮没有安装/更新个人 skill，没有请求订阅、生成业务配置或发布。后续安装须获得授权并比较个人副本差异；回退本次源码提交即可恢复工具行为，但会恢复 Lite 漏检，因此回退期间应人工执行 Lite 自有合同检查。

## 2026-09-22 本地落地

经明确授权，十一文件候选已应用到原 main。应用时逐文件 SHA256 与受测候选一致；仅本记录追加落地状态。原仓 fresh 回归 20/20、两份 SKILL 结构检查及本地链接/语法检查通过，真实 ProxyConfig 只读覆盖仍为 7 checked、3 skipped、0 missing；四条既有 PO0 提示保留。Windows 默认编码导致结构检查首轮失败，以 Python UTF-8 模式重跑通过，未修改工具以放宽检查。

本次仅本地提交；未推送、安装个人 skill、生成配置、触发 CI 或部署。既有候选验证边界继续有效。
