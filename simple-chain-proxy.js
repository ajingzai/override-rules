/*!
powerfullz 的 Substore 订阅转换脚本 (魔改精简版)
https://github.com/powerfullz/override-rules

修改日志：
1. [DNS] 替换为截图同款配置：全国内 DoH (腾讯/阿里) + Fake-IP，追求极致秒开。
2. [分组] 强制精简为 6 个国家分组 (港/台/狮/日/美/韩) + 核心选择组。
3. [重命名] 植入自动重命名逻辑 (HK-01, US-02...)。
4. [链式] 植入落地节点自动挂前置代理逻辑。
5. [端口] 植入 8000+ 自动端口映射。
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

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT: "🚀 节点选择",
    FRONT: "⚡ 前置代理",
    LANDING: "🛫 落地节点",
    MANUAL: "🔄 手动切换",
    AUTO: "♻️ 自动选择",
    DIRECT: "🎯 全球直连",
    ADBLOCK: "🛑 广告拦截"
};

// ================= 3. 规则集 (保留原文件逻辑) =================
const ruleProviders = {
    ADBlock: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://adrules.top/adrules-mihomo.mrs", path: "./ruleset/ADBlock.mrs" },
    SogouInput: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt", path: "./ruleset/SogouInput.txt" },
    StaticResources: { type: "http", behavior: "domain", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/domainset/cdn.txt", path: "./ruleset/StaticResources.txt" },
    CDNResources: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/cdn.txt", path: "./ruleset/CDNResources.txt" },
    TikTok: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list", path: "./ruleset/TikTok.list" },
    EHentai: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list", path: "./ruleset/EHentai.list" },
    SteamFix: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list", path: "./ruleset/SteamFix.list" },
    GoogleFCM: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list", path: "./ruleset/FirebaseCloudMessaging.list" },
    AdditionalFilter: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list", path: "./ruleset/AdditionalFilter.list" },
    AdditionalCDNResources: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list", path: "./ruleset/AdditionalCDNResources.list" },
    Crypto: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list", path: "./ruleset/Crypto.list" }
};

// ================= 4. 规则配置 (原文件规则 + 优化) =================
const baseRules = [
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT", // 阻断QUIC
    "RULE-SET,ADBlock,🛑 广告拦截",
    "RULE-SET,AdditionalFilter,🛑 广告拦截",
    "RULE-SET,SogouInput,🎯 全球直连",
    "DOMAIN-SUFFIX,truthsocial.com,🚀 节点选择",
    "RULE-SET,StaticResources,🎯 全球直连",
    "RULE-SET,CDNResources,🎯 全球直连",
    "RULE-SET,AdditionalCDNResources,🎯 全球直连",
    "RULE-SET,Crypto,🚀 节点选择",
    "RULE-SET,EHentai,🚀 节点选择",
    "RULE-SET,TikTok,🚀 节点选择",
    "RULE-SET,SteamFix,🎯 全球直连",
    "RULE-SET,GoogleFCM,🎯 全球直连",
    "DOMAIN,services.googleapis.cn,🚀 节点选择",
    "GEOSITE,CATEGORY-AI-!CN,🚀 节点选择",
    "GEOSITE,GOOGLE-PLAY@CN,🎯 全球直连",
    "GEOSITE,MICROSOFT@CN,🎯 全球直连",
    "GEOSITE,ONEDRIVE,🚀 节点选择",
    "GEOSITE,MICROSOFT,🚀 节点选择",
    "GEOSITE,TELEGRAM,🚀 节点选择",
    "GEOSITE,YOUTUBE,🚀 节点选择",
    "GEOSITE,GOOGLE,🚀 节点选择",
    "GEOSITE,NETFLIX,🚀 节点选择",
    "GEOSITE,SPOTIFY,🚀 节点选择",
    "GEOSITE,BAHAMUT,🚀 节点选择",
    "GEOSITE,BILIBILI,🎯 全球直连",
    "GEOSITE,PIKPAK,🚀 节点选择",
    "GEOSITE,GFW,🚀 节点选择",
    "GEOSITE,CN,🎯 全球直连",
    "GEOSITE,PRIVATE,🎯 全球直连",
    "GEOIP,NETFLIX,🚀 节点选择,no-resolve",
    "GEOIP,TELEGRAM,🚀 节点选择,no-resolve",
    "GEOIP,CN,🎯 全球直连",
    "GEOIP,PRIVATE,🎯 全球直连",
    "MATCH,🚀 节点选择"
];

// ================= 5. DNS 配置 (截图同款：全国内DoH + FakeIP) =================
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: false,
        "prefer-h3": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        // 解析节点域名用 (国内 UDP)
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        
        // 核心 DNS：全用国内 DoH (截图配置)
        nameserver: [
            "https://doh.pub/dns-query",      
            "https://dns.alidns.com/dns-query" 
        ],
        
        // 代理 DNS
        "proxy-server-nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        
        // Fallback 为空或同上
        fallback: [],
        
        // Fake-IP 过滤 (包含豆包修复)
        "fake-ip-filter": [
            "*.lan", "*.local", "time.*.com", "ntp.*.com", 
            "+.market.xiaomi.com", "*.stun.*.*", "*.stun.*.*.*",
            "+.doubao.com", "+.volces.com", "geosite:cn"
        ]
    };
}

const snifferConfig = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, 8080, 8880] }, QUIC: { ports: [443, 8443] } },
    "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.push.apple.com"]
};

// ================= 6. 辅助函数 =================
function getCountryCode(name) {
    if (/香港|HK|Hong Kong/i.test(name)) return "HK";
    if (/台湾|TW|Taiwan/i.test(name)) return "TW";
    if (/新加坡|SG|Singapore/i.test(name)) return "SG";
    if (/日本|JP|Japan/i.test(name)) return "JP";
    if (/美国|US|America/i.test(name)) return "US";
    if (/韩国|KR|Korea/i.test(name)) return "KR";
    return "OT"; // 其他
}

// ================= 7. 策略组生成 (精简6分组 + 前置/落地) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    const proxyNames = proxies.map(p => p.name);

    // 筛选国家节点
    const groupsHK = proxyNames.filter(n => n.startsWith("HK-"));
    const groupsJP = proxyNames.filter(n => n.startsWith("JP-"));
    const groupsUS = proxyNames.filter(n => n.startsWith("US-"));
    const groupsTW = proxyNames.filter(n => n.startsWith("TW-"));
    const groupsSG = proxyNames.filter(n => n.startsWith("SG-"));
    const groupsKR = proxyNames.filter(n => n.startsWith("KR-"));

    // 核心选择器
    // 如果有落地模式，主选择器包含：自动、手动、前置、落地、直连
    const selectList = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 1. 主选择
    groups.push({
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: selectList
    });

    // 2. 自动 & 手动
    groups.push({ name: PROXY_GROUPS.AUTO, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png", type: "url-test", proxies: proxyNames, interval: 300, tolerance: 50 });
    groups.push({ name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", type: "select", proxies: proxyNames });

    // 3. 前置 & 落地 (Landing 模式)
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select",
            proxies: proxyNames.filter(n => !n.includes("-> 前置")) // 排除落地节点
        });
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select",
            proxies: proxyNames.filter(n => n.includes("-> 前置")) // 只选落地节点
        });
    }

    // 4. 六大国家分组 (你的精简要求)
    groups.push({ name: "🇭🇰 香港节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsHK.length ? groupsHK : ["DIRECT"] });
    groups.push({ name: "🇨🇳 台湾节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsTW.length ? groupsTW : ["DIRECT"] });
    groups.push({ name: "🇸🇬 狮城节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsSG.length ? groupsSG : ["DIRECT"] });
    groups.push({ name: "🇯🇵 日本节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsJP.length ? groupsJP : ["DIRECT"] });
    groups.push({ name: "🇺🇲 美国节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsUS.length ? groupsUS : ["DIRECT"] });
    groups.push({ name: "🇰🇷 韩国节点", type: "url-test", interval: 300, tolerance: 50, proxies: groupsKR.length ? groupsKR : ["DIRECT"] });

    // 5. 直连 & 拦截
    groups.push({ name: PROXY_GROUPS.DIRECT, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png", type: "select", proxies: ["DIRECT"] });
    groups.push({ name: PROXY_GROUPS.ADBLOCK, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/AdBlack.png", type: "select", proxies: ["REJECT", "DIRECT"] });

    return groups;
}

// ================= 8. 主程序 =================
function main(e) {
    let rawProxies = e.proxies || [];
    let finalProxies = [];
    const countryCounts = {};
    const excludeKeywords = /套餐|官网|剩余|时间|节点|重置|异常|邮箱|网址|Traffic|Expire|Reset/i;
    const strictLandingKeyword = "落地";

    // 1. 节点处理：重命名 + 落地链式
    rawProxies.forEach(p => {
        if (excludeKeywords.test(p.name)) return;

        if (p.name.includes(strictLandingKeyword)) {
            if (landing) {
                // 落地节点 -> 强制走前置组
                finalProxies.push({
                    ...p,
                    "dialer-proxy": PROXY_GROUPS.FRONT,
                    name: `${p.name} -> 前置`
                });
            } else {
                finalProxies.push(p);
            }
        } else {
            // 普通节点 -> 自动编号 (HK-01)
            const code = getCountryCode(p.name);
            if (!countryCounts[code]) countryCounts[code] = 0;
            countryCounts[code]++;
            finalProxies.push({
                ...p,
                name: `${code}-${countryCounts[code].toString().padStart(2, '0')}`
            });
        }
    });

    // 2. 端口映射 (8000+)
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

    // 3. 构建策略组
    const groups = buildProxyGroups(finalProxies, landing);
    
    // 4. Global 组 (API用)
    const allProxyNames = finalProxies.map(p => p.name);
    groups.push({name: "GLOBAL", type: "select", proxies: allProxyNames});

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
