/*!
powerfullz 的 Substore 订阅转换脚本 (香港高速/IEPL 严格定制版)
https://github.com/powerfullz/override-rules

配置变更：
1. [负载均衡] 极度严格筛选：仅允许名称包含 "香港高速" 或 "香港IEPL" 的节点。
2. [保底机制] 如果找不到上述节点，强制直连，防止配置报错。
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT:   "01. 节点选择",
    AUTO:     "02. 自动选择",
    LB:       "03. 负载均衡",
    FRONT:    "04. 前置代理",
    LANDING:  "05. 落地节点",
    MANUAL:   "06. 手动切换",
    TELEGRAM: "07. 电报消息",
    MATCH:    "08. 漏网之鱼",
    DIRECT:   "09. 全球直连",
    GLOBAL:   "GLOBAL" 
};

// ================= 3. 规则配置 =================
const baseRules = [
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT", 
    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,deepseek.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,t.me,${PROXY_GROUPS.TELEGRAM}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 =================
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
        fallback: []
    };
}

// ================= 5. 策略组生成 (定制筛选版) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    if (!proxies || proxies.length === 0) return [];
    
    const proxyNames = proxies.map(p => p.name);
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    // 【关键修改】严格匹配 "香港高速" 或 "香港IEPL"
    const specificRegex = /香港高速|香港IEPL/i;
    
    // 筛选
    let fastProxies = frontProxies.filter(n => specificRegex.test(n));

    // 【严格保底】
    // 只有匹配到了才放进去，匹配不到就给个直连占位，绝不放杂七杂八的节点
    let lbProxies = [];
    if (fastProxies.length > 0) {
        lbProxies = fastProxies; 
    } else {
        lbProxies = ["DIRECT"]; 
    }

    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 01. 节点选择
    groups.push({ name: PROXY_GROUPS.SELECT, type: "select", proxies: mainProxies });

    // 02. 自动选择
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies.length ? frontProxies : ["DIRECT"],
        interval: 300, 
        tolerance: 50 
    });

    // 03. 负载均衡 (定制版)
    groups.push({
        name: PROXY_GROUPS.LB,
        type: "load-balance",
        strategy: "consistent-hashing",
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
        proxies: lbProxies 
    });

    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, ...frontProxies] 
        });
        groups.push({
            name: PROXY_GROUPS.LANDING,
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, ...frontProxies] });
    groups.push({ name: PROXY_GROUPS.TELEGRAM, type: "select", proxies: mainProxies });
    groups.push({ name: PROXY_GROUPS.MATCH, type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });
    groups.push({ name: PROXY_GROUPS.DIRECT, type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });

    return groups;
}

// ================= 6. 主程序 =================
function main(e) {
    try {
        let rawProxies = e.proxies || [];
        let finalProxies = [];
        const excludeKeywords = /套餐|官网|剩余|时间|重置|异常|邮箱|网址/i;
        const strictLandingKeyword = "落地"; 

        rawProxies.forEach(p => {
            if (excludeKeywords.test(p.name)) return;
            if (p.name.includes(strictLandingKeyword)) {
                if (landing) {
                    finalProxies.push({ ...p, "dialer-proxy": PROXY_GROUPS.FRONT, name: `${p.name} -> 前置` });
                } else {
                    finalProxies.push(p);
                }
            } else {
                finalProxies.push(p);
            }
        });

        if (finalProxies.length === 0) return e; 

        const autoListeners = [];
        let startPort = 8000;
        finalProxies.forEach(proxy => {
            autoListeners.push({ name: `mixed-${startPort}`, type: "mixed", address: "0.0.0.0", port: startPort, proxy: proxy.name });
            startPort++;
        });

        const u = buildProxyGroups(finalProxies, landing);
        const allProxyNames = finalProxies.map(p => p.name);
        u.push({ name: "GLOBAL", type: "select", proxies: allProxyNames });

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
            rules: baseRules,
            dns: buildDnsConfig()
        };
    } catch (error) {
        console.log("Script Error: " + error);
        return e;
    }
}
