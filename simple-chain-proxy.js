/*!
powerfullz 的 Substore 订阅转换脚本 (经典前置/落地分组版)
https://github.com/powerfullz/override-rules

配置说明：
1. [分组回归] 恢复“前置代理”和“落地节点”作为主入口的经典结构，逻辑最清晰。
2. [内核保持] 继续使用 ACL4SSR 规则集 + 豆包/Grok 修复，保证分流精准。
3. [速度保持] 延续国内 DoH DNS 配置，保证秒开。
*/

// ================= 1. 基础工具 =================
const NODE_SUFFIX = "节点";
function parseBool(val) {
    if (typeof val === "boolean") return val;
    if (typeof val === "string") return val.toLowerCase() === "true" || val === "1";
    return false;
}
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); // 记得开启 landing=true
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 组名定义 (经典版) =================
const PROXY_GROUPS = {
    SELECT: "🚀 节点选择",
    FRONT: "⚡ 前置代理",
    LANDING: "🛫 落地节点",
    MANUAL: "🔄 手动切换",
    DIRECT: "🎯 全球直连",
    AUTO: "♻️ 自动选择"
};

// ================= 3. 规则集 (ACL4SSR) =================
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

// ================= 4. 规则配置 (Grok/豆包修复 + ACL4SSR) =================
const baseRules = [
    // 1. 特殊修复 (豆包/Grok/X) - 必须置顶
    "DOMAIN-SUFFIX,doubao.com,DIRECT",
    "DOMAIN-SUFFIX,volces.com,DIRECT",
    "DOMAIN-SUFFIX,grok.com,💬 OpenAi",
    "DOMAIN-SUFFIX,x.ai,💬 OpenAi",
    "DOMAIN-SUFFIX,x.com,🚀 节点选择",
    "DOMAIN-SUFFIX,twitter.com,🚀 节点选择",

    // 2. ACL4SSR 原版规则
    "RULE-SET,LocalAreaNetwork,🎯 全球直连",
    "RULE-SET,UnBan,🎯 全球直连",
    "RULE-SET,BanAD,REJECT",
    "RULE-SET,BanProgramAD,REJECT",
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

// ================= 5. DNS 配置 (秒开不泄露) =================
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: false,
        "prefer-h3": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        
        // 核心：使用国内 DoH 加速 + Fake-IP
        nameserver: [
            "https://doh.pub/dns-query",      
            "https://dns.alidns.com/dns-query" 
        ],
        
        "proxy-server-nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        
        fallback: [],
        "fake-ip-filter": [
            "*.lan", "*.local", "time.*.com", "ntp.*.com", "+.market.xiaomi.com", 
            "*.stun.*.*", "*.stun.*.*.*", "+.doubao.com", "+.volces.com"
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

// ================= 6. 策略组生成 (核心分组逻辑) =================
function buildProxyGroups(params) {
    const isLanding = params.landing;
    const groups = [];

    // 1. 定义核心分组结构
    // 如果开启 landing，主选择器包含：前置、落地、手动、直连
    const selectProxies = isLanding 
        ? [PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, PROXY_GROUPS.DIRECT] 
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, PROXY_GROUPS.DIRECT];

    // 🚀 主节点选择
    groups.push({
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: selectProxies
    });

    // ⚡ 前置代理 (如果开启 landing)
    if (isLanding) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select",
            "include-all": true,
            "exclude-filter": " -> 前置" // 前置组包含所有【未】被标记为前置的节点
        });
        
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select",
            "include-all": true,
            filter: " -> 前置" // 落地组只包含被标记为前置(即落地)的节点
        });
    }

    // 🔄 手动切换 & ♻️ 自动选择
    groups.push({ name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", "include-all": true, type: "select" });
    groups.push({ name: PROXY_GROUPS.AUTO, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png", "include-all": true, type: "url-test", interval: 300, tolerance: 50 });
    
    // 🎯 直连
    groups.push({ name: PROXY_GROUPS.DIRECT, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png", type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });

    // === 功能分组 (全部指向主节点选择) ===
    const commonProxies = [PROXY_GROUPS.SELECT, PROXY_GROUPS.AUTO];
    if (isLanding) {
        // 如果有前置/落地，也可以加进去，但通常指向 SELECT 最简单
        // commonProxies.push(PROXY_GROUPS.FRONT);
    }

    groups.push({ name: "📲 电报消息", type: "select", proxies: commonProxies });
    groups.push({ name: "💬 OpenAi", type: "select", proxies: commonProxies });
    groups.push({ name: "📹 油管视频", type: "select", proxies: commonProxies });
    groups.push({ name: "🎥 奈飞视频", type: "select", proxies: commonProxies });
    groups.push({ name: "📺 巴哈姆特", type: "select", proxies: commonProxies });
    groups.push({ name: "📺 哔哩哔哩", type: "select", proxies: ["🎯 全球直连", PROXY_GROUPS.SELECT] });
    groups.push({ name: "🌍 国外媒体", type: "select", proxies: commonProxies });
    groups.push({ name: "🌏 国内媒体", type: "select", proxies: ["🎯 全球直连", PROXY_GROUPS.SELECT] });
    groups.push({ name: "📢 谷歌FCM", type: "select", proxies: commonProxies });
    groups.push({ name: "Ⓜ️ 微软Bing", type: "select", proxies: ["🎯 全球直连", PROXY_GROUPS.SELECT] });
    groups.push({ name: "Ⓜ️ 微软云盘", type: "select", proxies: ["🎯 全球直连", PROXY_GROUPS.SELECT] });
    groups.push({ name: "Ⓜ️ 微软服务", type: "select", proxies: [PROXY_GROUPS.SELECT, "🎯 全球直连"] });
    groups.push({ name: "🍎 苹果服务", type: "select", proxies: ["🎯 全球直连", PROXY_GROUPS.SELECT] });
    groups.push({ name: "🎮 游戏平台", type: "select", proxies: ["🎯 全球直连", PROXY_GROUPS.SELECT] });
    groups.push({ name: "🎶 网易音乐", type: "select", proxies: ["🎯 全球直连", PROXY_GROUPS.SELECT] });
    
    groups.push({ name: "🛑 广告拦截", type: "select", proxies: ["REJECT", "DIRECT"] });
    groups.push({ name: "🍃 应用净化", type: "select", proxies: ["REJECT", "DIRECT"] });
    groups.push({ name: "🐟 漏网之鱼", type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });

    return groups;
}

// 辅助函数：重命名
function getCountryCode(name) {
    if (/香港|HK|Hong Kong/i.test(name)) return "HK";
    if (/台湾|TW|Taiwan/i.test(name)) return "TW";
    if (/新加坡|SG|Singapore/i.test(name)) return "SG";
    if (/日本|JP|Japan/i.test(name)) return "JP";
    if (/美国|US|America/i.test(name)) return "US";
    if (/韩国|KR|Korea/i.test(name)) return "KR";
    return "OT";
}

// ================= 7. 主程序 =================
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
                // 如果开启 landing，落地节点强制加 dialer-proxy，名字加 "-> 前置"
                // 这样它会被过滤进 【🛫 落地节点】 组
                finalProxies.push({
                    ...p,
                    "dialer-proxy": PROXY_GROUPS.FRONT,
                    name: `${p.name} -> 前置`
                });
            } else {
                finalProxies.push(p);
            }
        } else {
            // 普通节点 (前置节点)
            const code = getCountryCode(p.name);
            if (!countryCounts[code]) countryCounts[code] = 0;
            countryCounts[code]++;
            finalProxies.push({
                ...p,
                name: `${code}-${countryCounts[code].toString().padStart(2, '0')}`
            });
        }
    });

    // 2. 端口映射
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

    const u = buildProxyGroups({ landing: landing });
    const d = u.map(e => e.name);
    u.push({name:"GLOBAL", icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png", "include-all":true, type:"select", proxies:d});

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
        "proxy-groups": u,
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
