/*!
powerfullz 的 Substore 订阅转换脚本 (ACL4SSR 复刻版)
https://github.com/powerfullz/override-rules

核心逻辑：
1. [规则复刻] 完全照搬 ACL4SSR 的 Rule-Providers 和 Rules，确保分流逻辑与你提供的文件一致。
2. [DNS重写] 使用 Fake-IP + 分流策略 (国外8.8.8.8 / 国内223.5.5.5)，配合 Rules 实现极速。
3. [功能保留] 链式代理、端口映射、自动重命名。
*/

// ================= 1. 基础工具 =================
const NODE_SUFFIX = "节点";
function parseBool(val) {
    if (typeof val === "boolean") return val;
    if (typeof val === "string") return val.toLowerCase() === "true" || val === "1";
    return false;
}
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing);
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 规则集定义 (完全照搬 ACL4SSR) =================
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

// ================= 3. 规则 (照搬 ACL4SSR) =================
const baseRules = [
    // 手动置顶 Grok/X 防止规则集漏网
    "DOMAIN-SUFFIX,grok.com,💬 OpenAi",
    "DOMAIN-SUFFIX,x.ai,💬 OpenAi",
    "DOMAIN-SUFFIX,x.com,🚀 节点选择",
    "DOMAIN-SUFFIX,twitter.com,🚀 节点选择",

    // ACL4SSR 原版规则
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

// ================= 4. DNS 配置 (Meta 最佳实践) =================
// 这就是 ACL4SSR 能够秒开的秘密：Fake-IP + 国内直连解析
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: ipv6Enabled,
        "prefer-h3": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        // 1. 默认 Nameserver：走国外，保证无污染
        nameserver: [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query"
        ],
        
        // 2. 分流：所有 geosite:cn 强制走国内 DNS
        // 这样国内网站就是毫秒级直连
        "nameserver-policy": {
            "geosite:cn,private,apple,huawei,xiaomi": [
                "223.5.5.5",
                "119.29.29.29"
            ]
        },
        
        // 3. 节点域名解析
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
        
        fallback: [],
        "fallback-filter": { "geoip": true, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"] },
        "fake-ip-filter": ["geosite:cn", "geosite:private", "*.lan", "*.local"]
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
                    "dialer-proxy": "🚀 前置代理", // 注意这里对应下面的组名
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

    // 2. 动态生成国家分组 (用于填充 Select)
    // 根据重命名后的前缀 (HK-, US- 等) 筛选
    const groupsHK = proxyNames.filter(n => n.startsWith("HK-"));
    const groupsJP = proxyNames.filter(n => n.startsWith("JP-"));
    const groupsUS = proxyNames.filter(n => n.startsWith("US-"));
    const groupsTW = proxyNames.filter(n => n.startsWith("TW-"));
    const groupsSG = proxyNames.filter(n => n.startsWith("SG-"));
    const groupsKR = proxyNames.filter(n => n.startsWith("KR-"));

    // 3. 构建 Proxy Groups (照搬 ACL4SSR 结构)
    const groups = [
        {
            name: "🚀 节点选择",
            type: "select",
            proxies: ["♻️ 自动选择", "🇭🇰 香港节点", "🇨🇳 台湾节点", "🇸🇬 狮城节点", "🇯🇵 日本节点", "🇺🇲 美国节点", "🇰🇷 韩国节点", "🚀 手动切换", "DIRECT"]
        },
        { name: "🚀 手动切换", type: "select", proxies: proxyNames }, // 全部节点
        { name: "♻️ 自动选择", type: "url-test", proxies: proxyNames, interval: 300, tolerance: 50 },
        
        // 功能分组
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

        // 国家/地区分组 (填充筛选后的节点)
        { name: "🇭🇰 香港节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsHK.length > 0 ? groupsHK : ["DIRECT"] },
        { name: "🇯🇵 日本节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsJP.length > 0 ? groupsJP : ["DIRECT"] },
        { name: "🇺🇲 美国节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsUS.length > 0 ? groupsUS : ["DIRECT"] },
        { name: "🇨🇳 台湾节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsTW.length > 0 ? groupsTW : ["DIRECT"] },
        { name: "🇸🇬 狮城节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsSG.length > 0 ? groupsSG : ["DIRECT"] },
        { name: "🇰🇷 韩国节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsKR.length > 0 ? groupsKR : ["DIRECT"] },
        { name: "🎥 奈飞节点", type: "select", proxies: [...groupsSG, ...groupsHK, ...groupsUS] }
    ];

    // 如果开启了 landing，添加前置代理组
    if (landing) {
        groups.push({
            name: "🚀 前置代理",
            type: "select",
            proxies: proxyNames.filter(n => !n.includes("-> 前置"))
        });
        // 把“落地节点”逻辑融入“手动切换”或“节点选择”比较复杂，
        // 这里简单地把落地组作为备选
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
