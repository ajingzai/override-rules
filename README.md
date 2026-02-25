## powerfullz 的覆写规则仓库

> 🤖 此行由 AI 助手自动添加 - 测试写入功能正常！

此处存放我用于 Mihomo/Substore 的覆写规则（**不建议用于 Stash**），Inspired by [mihomo-party-org/override-hub](https://github.com/mihomo-party-org/override-hub) 内的 ACL4SSR，具有以下优点：

*   集成 [SukkaW/Surge](https://github.com/SukkaW/Surge) 和 [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules) 规则
*   新增 Truth Social、E-Hentai、TikTok、加密货币等分流规则
*   移除冗余规则集
*   引入 [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) GeoSite/GeoIP
*   针对 IP 规则添加 `no-resolve` 参数，避免不必要的本地 DNS 解析，提升上网速度
*   JS 格式覆写现已实现节点国家动态识别与分组，自动为实际存在的各国家/地区节点生成对应代理组，节点变动时分组自动变化，省心省力。