// ==============================================
// 1. 基础工具函数 (展开写，防止报错)
// ==============================================
const NODE_SUFFIX = "节点";

function parseBool(val) {
    if (typeof val === "boolean") return val;
    if (typeof val === "string") {
        return val.toLowerCase() === "true" || val === "1";
    }
    return false;
}

function parseNumber(val, defaultVal = 0) {
    if (val == null) return defaultVal;
    const num = parseInt(val, 10);
    return isNaN(num) ? defaultVal : num;
}

// 获取脚本参数
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const loadBalance = parseBool(rawArgs.loadBalance);
const landing = parseBool(rawArgs.landing); // 只有开启 landing=true，才会处理落地节点
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ==============================================
// 2. 组名定义
// ==============================================
const PROXY_GROUPS = {
    SELECT: "选择代理",
    FRONT: "前置代理",
    LANDING: "落地节点",
    MANUAL: "手动选择",
    DIRECT: "直连"
};

// ==============================================
// 3. 规则集定义
// ==============================================
const ruleProviders = {
    TikTok: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml", path: "./ruleset/TikTok.yaml" },
    ADBlock: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://adrules.top/adrules-mihomo.mrs", path: "./ruleset/ADBlock.mrs" },
    SogouInput: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt", path: "./ruleset/SogouInput.txt" },
    StaticResources: { type: "http", behavior: "domain", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/domainset/cdn.txt", path: "./ruleset/StaticResources.txt" },
    CDNResources: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/cdn.txt", path: "./ruleset/CDNResources.txt" },
    Crypto: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list", path: "./ruleset/Crypto.list" }
};

// ==============================================
// 4. 规则配置 (全能修复)
// ==============================================
const baseRules = [
    // 阻断 QUIC (解决 Gemini/Sora 转圈)
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
    
    // DNS 防泄露 (Google DNS 走代理)
    `DOMAIN,dns.google,${PROXY_GROUPS.SELECT}`,
    `IP-CIDR,8.8.8.8/32,${PROXY_GROUPS.SELECT},no-resolve`,
    
    // GitHub 加速
    `GEOSITE,GITHUB,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`,
    
    // Google & Gemini & Sora 全家桶修复
    `GEOSITE,GOOGLE,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,generativelanguage.googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,${PROXY_GROUPS.SELECT}`, // 手机端Gemini关键
    `DOMAIN-SUFFIX,sora.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.SELECT}`,
    
    // YouTube 图片修复
    `DOMAIN-SUFFIX,ggpht.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,

    // TikTok 修复 (优先匹配)
    `RULE-SET,TikTok,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,TIKTOK,${PROXY_GROUPS.SELECT}`,

    // 基础规则
    "RULE-SET,ADBlock,REJECT",
    `RULE-SET,SogouInput,${PROXY_GROUPS.DIRECT}`, 
    `RULE-SET,StaticResources,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.SELECT}`
];

// ==============================================
// 5. DNS 配置 (非TUN防泄露)
// ==============================================
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: false, // 强关 IPv6
        "prefer-h3": false,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
        nameserver: ["https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query"],
        "nameserver-policy": {
            "geosite:cn,private,apple,huawei,xiaomi": ["223.5.5.5", "119.29.29.29"]
        },
        fallback: [],
        "fallback-filter": { "geoip": true, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"] }
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

// ==============================================
// 6. 策略组生成器
// ==============================================
function buildProxyGroups(params) {
    const isLanding = params.landing;
    const groups = [];

    // 1. 选择代理 (总入口)
    const selectProxies = isLanding ? [PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"] : [];
    const selectGroup = {
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: selectProxies
    };
    if (!isLanding) selectGroup["include-all"] = true;
    groups.push(selectGroup);

    // 2. 落地 & 前置 (仅 landing=true 时生成)
    if (isLanding) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select", 
            "include-all": true, 
            "exclude-filter": " -> 前置" // 前置组：排除掉已经是链式的节点
        });
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select", 
            "include-all": true, 
            filter: " -> 前置" // 落地组：只包含链式节点
        });
    }

    groups.push({name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", "include-all": true, type: "select"});
    groups.push({name: PROXY_GROUPS.DIRECT, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png", type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT]});
    return groups;
}

// 辅助函数：根据名字判断国家代码
function getCountryCode(name) {
    if (/香港|HK|Hong Kong/i.test(name)) return "HK";
    if (/台湾|TW|Taiwan/i.test(name)) return "TW";
    if (/新加坡|SG|Singapore/i.test(name)) return "SG";
    if (/日本|JP|Japan/i.test(name)) return "JP";
    if (/美国|US|America/i.test(name)) return "US";
    if (/韩国|KR|Korea/i.test(name)) return "KR";
    if (/英国|UK|United Kingdom/i.test(name)) return "UK";
    if (/德国|DE|Germany/i.test(name)) return "DE";
    if (/法国|FR|France/i.test(name)) return "FR";
    if (/俄罗斯|RU|Russia/i.test(name)) return "RU";
    if (/土耳其|TR|Turkey/i.test(name)) return "TR";
    if (/阿根廷|AR|Argentina/i.test(name)) return "AR";
    return "OT"; // Other
}

// ==============================================
// 7. 主程序 (Main)
// ==============================================
function main(e) {
    let rawProxies = e.proxies || [];
    let finalProxies = [];
    const countryCounts = {};
    
    // 垃圾词过滤正则
    const excludeKeywords = /套餐|官网|剩余|时间|节点|重置|异常|邮箱|网址|Traffic|Expire|Reset/i;
    // 落地关键词
    const strictLandingKeyword = "落地";

    // --- 步骤 1: 节点清洗、重命名与链式处理 ---
    rawProxies.forEach(p => {
        // A. 剔除无效节点
        if (excludeKeywords.test(p.name)) {
            return;
        }

        // B. 处理“落地”节点
        if (p.name.includes(strictLandingKeyword)) {
            if (landing) {
                // 如果开启了 landing，则注入链式代理参数
                finalProxies.push({
                    ...p,
                    "dialer-proxy": PROXY_GROUPS.FRONT,
                    name: `${p.name} -> 前置` // 改个名，方便确认
                });
            } else {
                // 没开参数就原样保留
                finalProxies.push(p);
            }
        } 
        // C. 处理普通节点 (重命名)
        else {
            const code = getCountryCode(p.name);
            if (!countryCounts[code]) countryCounts[code] = 0;
            countryCounts[code]++;
            // 格式化为 HK-01, US-05
            const newName = `${code}-${countryCounts[code].toString().padStart(2, '0')}`;
            
            finalProxies.push({
                ...p,
                name: newName
            });
        }
    });

    // 此时 finalProxies 已经是处理好的干净列表
    const t = { proxies: finalProxies };

    // --- 步骤 2: 生成端口映射 (Listeners) ---
    const autoListeners = [];
    let startPort = 8000;

    finalProxies.forEach(proxy => {
        autoListeners.push({
            name: `mixed-${startPort}`,
            type: "mixed",
            address: "0.0.0.0", // 允许局域网连接
            port: startPort, 
            proxy: proxy.name   // 绑定到(可能已重命名过的)节点名
        });
        startPort++;
    });

    // --- 步骤 3: 组装配置 ---
    const u = buildProxyGroups({ landing: landing });
    const d = u.map(e => e.name);
    u.push({name:"GLOBAL", icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png", "include-all":true, type:"select", proxies:d});

    const dnsFake = buildDnsConfig();

    Object.assign(t, {
        "mixed-port": 7890,
        "allow-lan": true,
        ipv6: false, 
        mode: "rule",
        "unified-delay": true,
        "tcp-concurrent": true,
        "global-client-fingerprint": "chrome",
        "listeners": autoListeners, // 注入自动生成的端口
        "proxy-groups": u,
        "rule-providers": ruleProviders,
        rules: baseRules,
        sniffer: snifferConfig,
        dns: dnsFake,
        "geodata-mode": true,
        "geox-url": {
            geoip: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
            geosite: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
            mmdb: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"
        }
    });

    return t;
}
