/*!
powerfullz 的 Substore 订阅转换脚本 (图标源修复版)
https://github.com/powerfullz/override-rules

配置说明：
1. [图标修复] 彻底更换图标源为更稳定的 MetaCubeX 库，解决图标加载失败/空白问题。
2. [界面整洁] 保持无 Emoji 纯净风格。
3. [功能保持] 秒开 DNS + 极简分组 + 自动重命名。
*/

// ================= 1. 基础工具 =================
const NODE_SUFFIX = "节点";
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT: "节点选择",
    FRONT: "前置代理",
    LANDING: "落地节点",
    MANUAL: "手动切换",
    AUTO: "自动选择",
    DIRECT: "全球直连",
    MATCH: "漏网之鱼",
    GLOBAL: "GLOBAL"
};

// ================= 3. 规则集 (全内置) =================
const ruleProviders = {}; 

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
    "GEOSITE,TIKTOK," + PROXY_GROUPS.SELECT,

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

// ================= 7. 策略组生成 (更换图标源) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    const proxyNames = proxies.map(p => p.name);
    
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 1. 节点选择 (火箭) - 使用 fastly.jsdelivr 源，通常更稳
    groups.push({
        name: PROXY_GROUPS.SELECT,
        icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/rocket.svg", 
        type: "select",
        proxies: mainProxies
    });

    // 2. 自动选择 (闪电/WiFi)
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/speed.svg", 
        type: "url-test", 
        proxies: proxyNames, 
        interval: 300, 
        tolerance: 50 
    });

    // 3. 手动切换 (列表)
    groups.push({ 
        name: PROXY_GROUPS.MANUAL, 
        icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/adjust.svg", 
        type: "select", 
        proxies: [PROXY_GROUPS.AUTO, ...proxyNames] 
    });

    // 4. 前置与落地
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/link.svg", // 链接图标
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, ...frontProxies] 
        });
        
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/airplane.svg", // 飞机图标
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    // 5. 全球直连 (圆圈)
    groups.push({
        name: PROXY_GROUPS.DIRECT,
        icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/check.svg",
        type: "select",
        proxies: ["DIRECT", PROXY_GROUPS.SELECT] 
    });

    // 6. 漏网之鱼 (鱼/网)
    groups.push({
        name: PROXY_GROUPS.MATCH,
        icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/bug.svg", // 用个Bug图标代表漏网
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
    
    // 7. GLOBAL 组 (地球)
    const allProxyNames = finalProxies.map(p => p.name);
    u.push({
        name: "GLOBAL", 
        icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/globe.svg",
        type: "select", 
        proxies: allProxyNames
    });

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
