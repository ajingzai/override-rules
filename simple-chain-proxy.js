/*!
powerfullz 的 Substore 订阅转换脚本 (极简嵌套版)
https://github.com/powerfullz/override-rules

配置说明：
1. [极致精简] 移除了所有国家分组和功能分组，界面极其干净。
2. [嵌套优化] "手动切换" 和 "前置代理" 组内均包含 "自动选择"，方便一键切换。
3. [秒开DNS] 保持全国内 DoH + Fake-IP 配置。
*/

// ================= 1. 基础工具 =================
const NODE_SUFFIX = "节点";
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
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
    MATCH: "🐟 漏网之鱼"
};

// ================= 3. 规则集 (极简) =================
const ruleProviders = {}; // 不再依赖外部文件，全内置

// ================= 4. 规则配置 (硬编码) =================
const baseRules = [
    // 1. 强制直连 (国产 AI + 基础)
    "DOMAIN-SUFFIX,doubao.com,DIRECT",
    "DOMAIN-SUFFIX,volces.com,DIRECT",
    "DOMAIN-SUFFIX,yiyan.baidu.com,DIRECT",
    "DOMAIN-SUFFIX,chatglm.cn,DIRECT",
    "DOMAIN-SUFFIX,kimi.ai,DIRECT",
    
    // 2. 强制代理 (Grok/X)
    "DOMAIN-SUFFIX,grok.com," + PROXY_GROUPS.SELECT,
    "DOMAIN-SUFFIX,x.ai," + PROXY_GROUPS.SELECT,
    "DOMAIN-SUFFIX,x.com," + PROXY_GROUPS.SELECT,
    "DOMAIN-SUFFIX,twitter.com," + PROXY_GROUPS.SELECT,

    // 3. 常用国外
    "GEOSITE,GOOGLE," + PROXY_GROUPS.SELECT,
    "GEOSITE,YOUTUBE," + PROXY_GROUPS.SELECT,
    "GEOSITE,TELEGRAM," + PROXY_GROUPS.SELECT,
    "GEOSITE,NETFLIX," + PROXY_GROUPS.SELECT,
    "GEOSITE,GITHUB," + PROXY_GROUPS.SELECT,
    "GEOSITE,TIKTOK," + PROXY_GROUPS.SELECT, // 这里的 TIKTOK 走 Select

    // 4. 国内直连
    "GEOSITE,CN,DIRECT",
    "GEOIP,CN,DIRECT",
    "GEOIP,PRIVATE,DIRECT",

    // 5. 兜底
    "MATCH," + PROXY_GROUPS.MATCH
];

// ================= 5. DNS 配置 (秒开同款) =================
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
        nameserver: ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        "proxy-server-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        fallback: [],
        "fake-ip-filter": ["*.lan", "*.local", "+.market.xiaomi.com", "*.stun.*.*", "+.doubao.com", "+.volces.com"]
    };
}

const snifferConfig = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, 8080, 8880] }, QUIC: { ports: [443, 8443] } }
};

// ================= 6. 辅助函数 =================
function getCountryCode(name) {
    if (/香港|HK|Hong Kong/i.test(name)) return "HK";
    if (/台湾|TW|Taiwan/i.test(name)) return "TW";
    if (/新加坡|SG|Singapore/i.test(name)) return "SG";
    if (/日本|JP|Japan/i.test(name)) return "JP";
    if (/美国|US|America/i.test(name)) return "US";
    if (/韩国|KR|Korea/i.test(name)) return "KR";
    return "OT";
}

// ================= 7. 策略组生成 (极简核心) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    const proxyNames = proxies.map(p => p.name);
    
    // 筛选前置节点 (非落地节点)
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    // 筛选落地节点
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    // 核心代理列表
    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 1. 🚀 节点选择 (主入口)
    groups.push({
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: mainProxies
    });

    // 2. ♻️ 自动选择
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png", 
        type: "url-test", 
        proxies: proxyNames, 
        interval: 300, 
        tolerance: 50 
    });

    // 3. 🔄 手动切换 (包含自动选择)
    groups.push({ 
        name: PROXY_GROUPS.MANUAL, 
        icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", 
        type: "select", 
        proxies: [PROXY_GROUPS.AUTO, ...proxyNames] // 这里加了自动选择
    });

    // 4. 前置与落地 (按需开启)
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, ...frontProxies] // 这里也加了自动选择
        });
        
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    // 5. 🎯 全球直连 (唯一保留的其他分组)
    groups.push({
        name: PROXY_GROUPS.DIRECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
        type: "select",
        proxies: ["DIRECT", PROXY_GROUPS.SELECT] // 允许切回代理
    });

    // 6. 漏网之鱼
    groups.push({
        name: PROXY_GROUPS.MATCH,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Fish.png",
        type: "select",
        proxies: [PROXY_GROUPS.SELECT, "DIRECT"]
    });

    return groups;
}

// ================= 8. 主程序 =================
function main(e) {
    let rawProxies = e.proxies || [];
    let finalProxies = [];
    const countryCounts = {};
    const excludeKeywords = /套餐|官网|剩余|时间|节点|重置|异常|邮箱|网址|Traffic|Expire|Reset/i;
    const strictLandingKeyword = "落地";

    rawProxies.forEach(p => {
        if (excludeKeywords.test(p.name)) return;

        if (p.name.includes(strictLandingKeyword)) {
            if (landing) {
                finalProxies.push({
                    ...p,
                    "dialer-proxy": PROXY_GROUPS.FRONT,
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

    // 端口映射
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

    const u = buildProxyGroups(finalProxies, landing);
    
    // Global 组
    const allProxyNames = finalProxies.map(p => p.name);
    u.push({name: "GLOBAL", type: "select", proxies: allProxyNames});

    return { 
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
}
