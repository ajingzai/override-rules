/*!
powerfullz 的 Substore 订阅转换脚本 (极速秒开复刻版)
https://github.com/powerfullz/override-rules

配置说明：
1. [DNS复刻] 1:1 还原你提供的截图配置，使用腾讯/阿里 DoH 作为主力，配合 Fake-IP 实现全球秒开。
2. [规则复刻] 使用 ACL4SSR 规则集，涵盖国内外几乎所有网站。
3. [手动优化] 置顶了 Grok/Doubao/TikTok 规则，防止规则集更新不及时。
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing);
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 规则集 (ACL4SSR 原版) =================
const ruleProviders = {
    LocalAreaNetwork: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/LocalAreaNetwork.list", path: "./ruleset/LocalAreaNetwork.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    UnBan: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/UnBan.list", path: "./ruleset/UnBan.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    BanAD: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/BanAD.list", path: "./ruleset/BanAD.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    BanProgramAD: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/BanProgramAD.list", path: "./ruleset/BanProgramAD.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    GoogleFCM: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/GoogleFCM.list", path: "./ruleset/GoogleFCM.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    GoogleCN: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/GoogleCN.list", path: "./ruleset/GoogleCN.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    SteamCN: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/SteamCN.list", path: "./ruleset/SteamCN.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Bing: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Bing.list", path: "./ruleset/Bing.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    OneDrive: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/OneDrive.list", path: "./ruleset/OneDrive.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Microsoft: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Microsoft.list", path: "./ruleset/Microsoft.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Apple: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Apple.list", path: "./ruleset/Apple.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Telegram: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Telegram.list", path: "./ruleset/Telegram.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    OpenAi: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/OpenAi.list", path: "./ruleset/OpenAi.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    NetEaseMusic: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/NetEaseMusic.list", path: "./ruleset/NetEaseMusic.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Epic: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Epic.list", path: "./ruleset/Epic.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Origin: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Origin.list", path: "./ruleset/Origin.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Sony: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Sony.list", path: "./ruleset/Sony.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Steam: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Steam.list", path: "./ruleset/Steam.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Nintendo: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Nintendo.list", path: "./ruleset/Nintendo.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    YouTube: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/YouTube.list", path: "./ruleset/YouTube.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Netflix: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Netflix.list", path: "./ruleset/Netflix.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Bahamut: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Bahamut.list", path: "./ruleset/Bahamut.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    BilibiliHMT: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/BilibiliHMT.list", path: "./ruleset/BilibiliHMT.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Bilibili: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Bilibili.list", path: "./ruleset/Bilibili.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    ChinaMedia: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaMedia.list", path: "./ruleset/ChinaMedia.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    ProxyMedia: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ProxyMedia.list", path: "./ruleset/ProxyMedia.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    ProxyGFWlist: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ProxyGFWlist.list", path: "./ruleset/ProxyGFWlist.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    ChinaDomain: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaDomain.list", path: "./ruleset/ChinaDomain.list", behavior: "domain", interval: 86400, format: "text", type: "http" },
    ChinaCompanyIp: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaCompanyIp.list", path: "./ruleset/ChinaCompanyIp.list", behavior: "ipcidr", interval: 86400, format: "text", type: "http" },
    Download: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Download.list", path: "./ruleset/Download.list", behavior: "classical", interval: 86400, format: "text", type: "http" }
};

// ================= 3. 规则配置 (Grok置顶 + ACL4SSR) =================
const baseRules = [
    // 1. 特殊修复 (豆包/Grok/X)
    "DOMAIN-SUFFIX,doubao.com,🎯 全球直连",
    "DOMAIN-SUFFIX,volces.com,🎯 全球直连",
    "DOMAIN-SUFFIX,grok.com,💬 OpenAi",
    "DOMAIN-SUFFIX,x.ai,💬 OpenAi",
    "DOMAIN-SUFFIX,x.com,🚀 节点选择",
    "DOMAIN-SUFFIX,twitter.com,🚀 节点选择",

    // 2. ACL4SSR 原版规则
    "RULE-SET,LocalAreaNetwork,🎯 全球直连",
    "RULE-SET,UnBan,🎯 全球直连",
    "RULE-SET,BanAD,🛑 广告拦截",
    "RULE-SET,BanProgramAD,🍃 应用净化",
    "RULE-SET,GoogleFCM,📢 谷歌FCM",
    "RULE-SET,GoogleCN,🎯 全球直连",
    "RULE-SET,SteamCN,🎯 全球直连",
    "RULE-SET,Bing,Ⓜ️ 微软Bing",
    "RULE-SET,OneDrive,Ⓜ️ 微软云盘",
    "RULE-SET,Microsoft,Ⓜ️ 微软服务",
    "RULE-SET,Apple,🍎 苹果服务",
    "RULE-SET,Telegram,📲 电报消息",
    "RULE-SET,OpenAi,💬 OpenAi",
    "RULE-SET,NetEaseMusic,🎶 网易音乐",
    "RULE-SET,Epic,🎮 游戏平台",
    "RULE-SET,Origin,🎮 游戏平台",
    "RULE-SET,Sony,🎮 游戏平台",
    "RULE-SET,Steam,🎮 游戏平台",
    "RULE-SET,Nintendo,🎮 游戏平台",
    "RULE-SET,YouTube,📹 油管视频",
    "RULE-SET,Netflix,🎥 奈飞视频",
    "RULE-SET,Bahamut,📺 巴哈姆特",
    "RULE-SET,BilibiliHMT,📺 哔哩哔哩",
    "RULE-SET,Bilibili,📺 哔哩哔哩",
    "RULE-SET,ChinaMedia,🌏 国内媒体",
    "RULE-SET,ProxyMedia,🌍 国外媒体",
    "RULE-SET,ProxyGFWlist,🚀 节点选择",
    "RULE-SET,ChinaDomain,🎯 全球直连",
    "RULE-SET,ChinaCompanyIp,🎯 全球直连",
    "RULE-SET,Download,🎯 全球直连",
    "GEOIP,CN,🎯 全球直连",
    "MATCH,🐟 漏网之鱼"
];

// ================= 4. DNS 配置 (1:1 还原截图) =================
// 核心秘密：全部走国内 DoH，配合 Fake-IP，速度极快
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: false, // 截图显示 IPv6 关闭
        "prefer-h3": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        // 1. 解析节点 IP：用国内 UDP (截图默认)
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        
        // 2. 主 DNS：用国内 DoH (截图配置)
        // 这里的关键是：虽然填的是国内DNS，但因为是 Fake-IP，
        // Clash 会直接返回假 IP，不会真的去等 DNS 结果，所以国外网站也能秒开。
        nameserver: [
            "https://doh.pub/dns-query",      // 腾讯 DoH
            "https://dns.alidns.com/dns-query" // 阿里 DoH
        ],
        
        // 3. 代理 DNS：用于解析代理服务器域名
        "proxy-server-nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        
        // 4. Fallback：截图里也填了国内的，或者留空
        // 我们这里保持一致，不强制走 8.8.8.8，相信 Fake-IP 的能力
        fallback: [],
        
        // 5. 假 IP 过滤 (截图配置)
        "fake-ip-filter": [
            "*.lan", "*.local", "time.*.com", "ntp.*.com", "+.market.xiaomi.com", 
            "*.stun.*.*", "*.stun.*.*.*",
            "+.doubao.com", "+.volces.com" // 手动加几个AI的以防万一
        ]
    };
}

const snifferConfig = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, 8080, 8880] }, QUIC: { ports: [443, 8443] } }
};

// ================= 5. 辅助函数 =================
function getCountryCode(name) {
    if (/香港|HK|Hong Kong/i.test(name)) return "HK";
    if (/台湾|TW|Taiwan/i.test(name)) return "TW";
    if (/新加坡|SG|Singapore/i.test(name)) return "SG";
    if (/日本|JP|Japan/i.test(name)) return "JP";
    if (/美国|US|America/i.test(name)) return "US";
    if (/韩国|KR|Korea/i.test(name)) return "KR";
    return "OT";
}

// ================= 6. 主程序 =================
function main(e) {
    let rawProxies = e.proxies || [];
    let finalProxies = [];
    const countryCounts = {};
    const excludeKeywords = /套餐|官网|剩余|时间|节点|重置|异常|邮箱|网址|Traffic|Expire|Reset/i;
    const strictLandingKeyword = "落地";

    // 1. 节点重命名与链式处理
    rawProxies.forEach(p => {
        if (excludeKeywords.test(p.name)) return;

        if (p.name.includes(strictLandingKeyword)) {
            if (landing) {
                finalProxies.push({
                    ...p,
                    "dialer-proxy": "🚀 前置代理", 
                    name: `${p.name} -> 前置`
                });
            } else {
                finalProxies.push(p);
            }
        } else {
            const code = getCountryCode(p.name);
            if (!countryCounts[code]) countryCounts[code] = 0;
            countryCounts[code]++;
            finalProxies.push({
                ...p,
                name: `${code}-${countryCounts[code].toString().padStart(2, '0')}`
            });
        }
    });

    const proxyNames = finalProxies.map(p => p.name);

    // 2. 动态生成国家分组
    const groupsHK = proxyNames.filter(n => n.startsWith("HK-"));
    const groupsJP = proxyNames.filter(n => n.startsWith("JP-"));
    const groupsUS = proxyNames.filter(n => n.startsWith("US-"));
    const groupsTW = proxyNames.filter(n => n.startsWith("TW-"));
    const groupsSG = proxyNames.filter(n => n.startsWith("SG-"));
    const groupsKR = proxyNames.filter(n => n.startsWith("KR-"));

    // 3. 构建 Proxy Groups (与 ACL4SSR 匹配)
    const groups = [
        {
            name: "🚀 节点选择",
            type: "select",
            proxies: ["♻️ 自动选择", "🇭🇰 香港节点", "🇨🇳 台湾节点", "🇸🇬 狮城节点", "🇯🇵 日本节点", "🇺🇲 美国节点", "🇰🇷 韩国节点", "🚀 手动切换", "DIRECT"]
        },
        { name: "🚀 手动切换", type: "select", proxies: proxyNames }, 
        { name: "♻️ 自动选择", type: "url-test", proxies: proxyNames, interval: 300, tolerance: 50 },
        
        { name: "📲 电报消息", type: "select", proxies: ["🚀 节点选择", "♻️ 自动选择", "🇸🇬 狮城节点", "🇭🇰 香港节点", "🇺🇲 美国节点"] },
        { name: "💬 OpenAi", type: "select", proxies: ["🚀 节点选择", "🇺🇲 美国节点", "🇸🇬 狮城节点", "🇯🇵 日本节点"] },
        { name: "📹 油管视频", type: "select", proxies: ["🚀 节点选择", "♻️ 自动选择", "🇭🇰 香港节点", "🇺🇲 美国节点", "🇯🇵 日本节点"] },
        { name: "🎥 奈飞视频", type: "select", proxies: ["🚀 节点选择", "🎥 奈飞节点", "🇭🇰 香港节点", "🇸🇬 狮城节点"] },
        { name: "📺 巴哈姆特", type: "select", proxies: ["🇨🇳 台湾节点", "🚀 节点选择"] },
        { name: "📺 哔哩哔哩", type: "select", proxies: ["🎯 全球直连", "🇨🇳 台湾节点", "🇭🇰 香港节点"] },
        { name: "🌍 国外媒体", type: "select", proxies: ["🚀 节点选择", "♻️ 自动选择"] },
        { name: "🌏 国内媒体", type: "select", proxies: ["DIRECT", "🇭🇰 香港节点"] },
        { name: "📢 谷歌FCM", type: "select", proxies: ["DIRECT", "🚀 节点选择", "🇺🇲 美国节点"] },
        { name: "Ⓜ️ 微软Bing", type: "select", proxies: ["DIRECT", "🚀 节点选择", "🇺🇲 美国节点"] },
        { name: "Ⓜ️ 微软云盘", type: "select", proxies: ["DIRECT", "🚀 节点选择"] },
        { name: "Ⓜ️ 微软服务", type: "select", proxies: ["🚀 节点选择", "DIRECT"] },
        { name: "🍎 苹果服务", type: "select", proxies: ["DIRECT", "🚀 节点选择", "🇺🇲 美国节点"] },
        { name: "🎮 游戏平台", type: "select", proxies: ["DIRECT", "🚀 节点选择"] },
        { name: "🎶 网易音乐", type: "select", proxies: ["DIRECT", "🚀 节点选择"] },
        
        { name: "🎯 全球直连", type: "select", proxies: ["DIRECT", "🚀 节点选择"] },
        { name: "🛑 广告拦截", type: "select", proxies: ["REJECT", "DIRECT"] },
        { name: "🍃 应用净化", type: "select", proxies: ["REJECT", "DIRECT"] },
        { name: "🐟 漏网之鱼", type: "select", proxies: ["🚀 节点选择", "DIRECT"] },

        { name: "🇭🇰 香港节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsHK.length > 0 ? groupsHK : ["DIRECT"] },
        { name: "🇯🇵 日本节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsJP.length > 0 ? groupsJP : ["DIRECT"] },
        { name: "🇺🇲 美国节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsUS.length > 0 ? groupsUS : ["DIRECT"] },
        { name: "🇨🇳 台湾节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsTW.length > 0 ? groupsTW : ["DIRECT"] },
        { name: "🇸🇬 狮城节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsSG.length > 0 ? groupsSG : ["DIRECT"] },
        { name: "🇰🇷 韩国节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsKR.length > 0 ? groupsKR : ["DIRECT"] },
        { name: "🎥 奈飞节点", type: "select", proxies: [...groupsSG, ...groupsHK, ...groupsUS] }
    ];

    if (landing) {
        groups.push({
            name: "🚀 前置代理",
            type: "select",
            proxies: proxyNames.filter(n => !n.includes("-> 前置"))
        });
        groups[0].proxies.push("🚀 前置代理");
    }

    // 4. 端口映射
    const autoListeners = [];
    let startPort = 8000;
    finalProxies.forEach(proxy => {
        autoListeners.push({
            name: `mixed-${startPort}`,
            type: "mixed",
            address: "0.0.0.0",
            port: startPort, 
            proxy: proxy.name
        });
        startPort++;
    });

    const t = { 
        proxies: finalProxies,
        "mixed-port": 7890,
        "allow-lan": true,
        ipv6: ipv6Enabled, 
        mode: "rule",
        "unified-delay": true,
        "tcp-concurrent": true,
        "global-client-fingerprint": "chrome",
        "listeners": autoListeners,
        "proxy-groups": groups,
        "rule-providers": ruleProviders,
        rules: baseRules,
        sniffer: snifferConfig,
        dns: buildDnsConfig(),
        "geodata-mode": true,
        "geox-url": {
            geoip: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
            geosite: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
            mmdb: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"
        }
    };

    return t;
}
