/*!
powerfullz 的 Substore 订阅转换脚本 (完美平衡版)
https://github.com/powerfullz/override-rules

核心策略：
1. [国内恢复] 恢复 GEOSITE:CN 和 nameserver-policy，国内网站秒开，不再绕路。
2. [防报错] 只引用 standard 列表 (CN, GOOGLE, GITHUB)，避开 GCM/TikTok 等易报错列表。
3. [国外加固] TikTok/AI/X 继续使用硬编码规则，确保 100% 走代理。
4. [功能] 链式代理、端口映射、重命名全部保留。
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
    // 仅保留基础去广告，其他规则全部内置
    ADBlock: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://adrules.top/adrules-mihomo.mrs", path: "./ruleset/ADBlock.mrs" }
};

// ================= 4. 规则配置 (混合模式) =================
const baseRules = [
    // 1. 阻断 QUIC
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
    
    // 2. DNS 防泄露
    `IP-CIDR,8.8.8.8/32,${PROXY_GROUPS.SELECT},no-resolve`,
    `IP-CIDR,1.1.1.1/32,${PROXY_GROUPS.SELECT},no-resolve`,
    `DOMAIN,dns.google,${PROXY_GROUPS.SELECT}`,

    // ================= 国外重点 (硬编码 + 标准Geosite) =================
    // GitHub (Geosite很稳，但也加硬编码双保险)
    `DOMAIN-KEYWORD,github,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,GITHUB,${PROXY_GROUPS.SELECT}`,
    
    // Twitter / X (硬编码)
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`,
    
    // Telegram (硬编码 + 标准Geosite)
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.SELECT}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.SELECT},no-resolve`,
    `GEOSITE,TELEGRAM,${PROXY_GROUPS.SELECT}`,

    // TikTok (必须硬编码，Geosite容易缺失)
    `DOMAIN-KEYWORD,tiktok,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,byteoversea.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ibytedtos.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokv.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokcdn.com,${PROXY_GROUPS.SELECT}`,

    // Google / YouTube (标准Geosite + 补漏)
    `GEOSITE,GOOGLE,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,YOUTUBE,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    
    // AI (OpenAI/Gemini/Claude)
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,sora.com,${PROXY_GROUPS.SELECT}`,

    // 常见国外流媒体
    `GEOSITE,NETFLIX,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,spotify.com,${PROXY_GROUPS.SELECT}`,
    
    // ================= 国内直连 (恢复 GEOSITE:CN) =================
    "RULE-SET,ADBlock,REJECT",
    
    // 1. 标准 CN 列表 (这里恢复了！)
    // 这行能覆盖 99% 的国内网站，解决变慢问题
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    
    // 2. 常见国内域名补漏 (防止 Geosite 抽风)
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,163.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alipay.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,jd.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bilibili.com,${PROXY_GROUPS.DIRECT}`,
    
    // 3. 中国 IP 直连
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    
    // ================= 万能兜底 =================
    // 既不是国内 Geosite，又不是中国 IP 的，全部走代理
    `MATCH,${PROXY_GROUPS.SELECT}`
];

// ================= 5. DNS 配置 (恢复 CN 分流) =================
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: ipv6Enabled,
        "prefer-h3": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
        
        // 1. 默认 Nameserver：只填国外，防止污染
        nameserver: [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query"
        ],
        
        // 2. 分流策略：恢复了 geosite:cn ！
        // 这会让国内网站直接问阿里 DNS，速度飞快
        "nameserver-policy": {
            "geosite:cn,private,apple,huawei,xiaomi": [
                "223.5.5.5",
                "119.29.29.29"
            ]
        },
        
        fallback: [],
        "fallback-filter": { "geoip": true, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"] },

        "fake-ip-filter": [
            "geosite:cn", // 恢复
            "geosite:private",
            "Mijia Cloud",
            "dig.io.mi.com",
            "*.icloud.com",
            "*.stun.*.*"
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

        // B. 处理“落地”节点
        if (p.name.includes(strictLandingKeyword)) {
            if (landing) {
                // 【强制链式】
                finalProxies.push({
                    ...p,
                    "dialer-proxy": PROXY_GROUPS.FRONT,
                    name: `${p.name} -> 前置`
                });
            } else {
                finalProxies.push(p);
            }
        } 
        // C. 处理普通节点 (重命名)
        else {
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
