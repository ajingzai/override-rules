/*!
powerfullz 的 Substore 订阅转换脚本 (严格防泄露版)
https://github.com/powerfullz/override-rules

修复重点：
1. [DNS重构] 彻底抛弃原文件的“国内优先”策略，改为“严格分流”。
   - 国外域名只走 https://1.1.1.1，绝不向国内 DNS 发送请求，彻底杜绝 China Mobile 泄露。
   - 国内域名通过 nameserver-policy 走国内 DNS，保证速度。
2. [X/TikTok] 保持规则修复，解决加载失败。
3. [功能] 保持自动重命名、链式代理、端口映射。
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

// ================= 2. 组名定义 =================
const PROXY_GROUPS = { SELECT: "选择代理", FRONT: "前置代理", LANDING: "落地节点", MANUAL: "手动选择", DIRECT: "直连" };

// ================= 3. 规则集 =================
const ruleProviders = {
    TikTok: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml", path: "./ruleset/TikTok.yaml" },
    ADBlock: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://adrules.top/adrules-mihomo.mrs", path: "./ruleset/ADBlock.mrs" },
    SogouInput: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt", path: "./ruleset/SogouInput.txt" },
    StaticResources: { type: "http", behavior: "domain", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/domainset/cdn.txt", path: "./ruleset/StaticResources.txt" },
    CDNResources: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/cdn.txt", path: "./ruleset/CDNResources.txt" },
    Crypto: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list", path: "./ruleset/Crypto.list" }
};

// ================= 4. 规则配置 =================
const baseRules = [
    // 1. 阻断 QUIC (解决转圈)
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
    
    // 2. 强制 DNS 流量走代理
    `IP-CIDR,8.8.8.8/32,${PROXY_GROUPS.SELECT},no-resolve`,
    `IP-CIDR,1.1.1.1/32,${PROXY_GROUPS.SELECT},no-resolve`,
    `DOMAIN,dns.google,${PROXY_GROUPS.SELECT}`,
    `DOMAIN,cloudflare-dns.com,${PROXY_GROUPS.SELECT}`,

    // 3. X (Twitter) 修复
    `GEOSITE,TWITTER,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`,

    // 4. TikTok 修复
    `RULE-SET,TikTok,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokv.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,byteoversea.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ibytedtos.com,${PROXY_GROUPS.SELECT}`,
    
    // 5. Google / YouTube / AI
    `DOMAIN-SUFFIX,googleapis.cn,${PROXY_GROUPS.SELECT}`, 
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ggpht.com,${PROXY_GROUPS.SELECT}`, 
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,sora.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,GOOGLE,${PROXY_GROUPS.SELECT}`, 
    `GEOSITE,YOUTUBE,${PROXY_GROUPS.SELECT}`,

    // 6. 其他
    `GEOSITE,GITHUB,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,NETFLIX,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,TELEGRAM,${PROXY_GROUPS.SELECT}`,
    
    // 基础
    "RULE-SET,ADBlock,REJECT",
    `RULE-SET,SogouInput,${PROXY_GROUPS.DIRECT}`, 
    `RULE-SET,StaticResources,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.SELECT}`
];

// ================= 5. DNS 配置 (严格防泄露) =================
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: ipv6Enabled,
        "prefer-h3": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        // 1. 仅用于解析节点域名的国内 DNS (Bootstrap)
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
        
        // 2. 【核心修改】主 Nameserver 只填国外的 DoH！
        // 绝不填国内 IP，防止 Clash 拿国内 DNS 去解析国外域名
        nameserver: [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query"
        ],
        
        // 3. 【核心修改】国内域名单独走国内 DNS
        "nameserver-policy": {
            "geosite:cn,private,apple,huawei,xiaomi": [
                "223.5.5.5",
                "119.29.29.29"
            ]
        },
        
        // 4. Fallback 留空，避免逻辑混乱
        fallback: [],
        "fallback-filter": { "geoip": true, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"] },

        "fake-ip-filter": [
            "geosite:private",
            "geosite:connectivity-check",
            "geosite:cn",
            "Mijia Cloud",
            "dig.io.mi.com",
            "localhost.ptlogin2.qq.com",
            "*.icloud.com",
            "*.stun.*.*",
            "*.stun.*.*.*"
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

// ================= 6. 策略组生成 =================
function buildProxyGroups(params) {
    const isLanding = params.landing;
    const groups = [];

    const selectProxies = isLanding ? [PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"] : [];
    const selectGroup = {
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: selectProxies
    };
    if (!isLanding) selectGroup["include-all"] = true;
    groups.push(selectGroup);

    if (isLanding) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select", "include-all": true, "exclude-filter": " -> 前置"
        });
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select", "include-all": true, filter: " -> 前置"
        });
    }

    groups.push({name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", "include-all": true, type: "select"});
    groups.push({name: PROXY_GROUPS.DIRECT, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png", type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT]});
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
    if (/英国|UK|United Kingdom/i.test(name)) return "UK";
    if (/德国|DE|Germany/i.test(name)) return "DE";
    if (/法国|FR|France/i.test(name)) return "FR";
    if (/俄罗斯|RU|Russia/i.test(name)) return "RU";
    if (/土耳其|TR|Turkey/i.test(name)) return "TR";
    if (/阿根廷|AR|Argentina/i.test(name)) return "AR";
    return "OT";
}

// ================= 7. 主程序 =================
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

    const t = { proxies: finalProxies };

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

    const dnsConfig = buildDnsConfig();

    Object.assign(t, {
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
        dns: dnsConfig,
        "geodata-mode": true,
        "geox-url": {
            geoip: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
            geosite: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
            mmdb: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"
        }
    });

    return t;
}
