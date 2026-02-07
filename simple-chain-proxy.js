/*!
powerfullz 的 Substore 订阅转换脚本 (绝对稳定·零干扰版)
https://github.com/powerfullz/override-rules

核心逻辑：
1. [零干扰] 绝对不修改任何节点的内部参数 (TFO/证书/SNI)，原汁原味，兼容所有机场。
2. [DNS] 集成你截图中的完美 DNS 设置 (Fake-IP + Fallback)。
3. [修复] 仅做唯一修改：移除全局冲突的 global-client-fingerprint (Hy2 必须)。
4. [规则] 内置 TikTok/YouTube/Netflix 等分流规则。
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT:   "01. 节点选择",
    FRONT:    "02. 前置代理",
    LANDING:  "03. 落地节点",
    MANUAL:   "04. 手动切换",
    AUTO:     "05. 自动选择",
    NETFLIX:  "06. Netflix",
    TELEGRAM: "07. Telegram",
    MATCH:    "08. 漏网之鱼",
    DIRECT:   "09. 全球直连",
    GLOBAL:   "GLOBAL" 
};

// ================= 3. 规则配置 (Geosite 集合版) =================
const baseRules = [
    // 0. 特殊直连 (Steam/微软更新)
    `DOMAIN-SUFFIX,steamcontent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,steampipe.akamaized.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,dl.steam.clngaa.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,dl.steam.ksyna.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,windowsupdate.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,microsoft.com,${PROXY_GROUPS.DIRECT}`,

    // 1. 阻断 UDP 443 (仿照你提供的脚本，优化 TikTok 体验)
    `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT`,

    // 2. 国际 AI
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,openai,${PROXY_GROUPS.SELECT}`,

    // 3. TikTok
    `GEOSITE,tiktok,${PROXY_GROUPS.SELECT}`, 

    // 4. 国际巨头
    `GEOSITE,youtube,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,google,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,twitter,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,facebook,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,telegram,${PROXY_GROUPS.TELEGRAM}`,
    `GEOSITE,netflix,${PROXY_GROUPS.NETFLIX}`,
    `GEOSITE,disney,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,spotify,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,github,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,onedrive.com,${PROXY_GROUPS.SELECT}`,

    // 5. GFW 列表
    `GEOSITE,gfw,${PROXY_GROUPS.SELECT}`,

    // 6. 国内直连
    `GEOSITE,cn,${PROXY_GROUPS.DIRECT}`,

    // 7. 兜底
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 (你的完美截图版) =================
function buildDnsConfig() {
    return {
        "enable": true,
        "listen": ":1053",
        "ipv6": false,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": [
            "*.lan",
            "*.local",
            "time.*.com",
            "ntp.*.com",
            "*.market.xiaomi.com",
            "+.msftncsi.com",
            "+.msftconnecttest.com"
        ],
        "default-nameserver": ["tls://223.5.5.5", "119.29.29.29"],
        "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        "fallback": [
            "https://dns.google/dns-query",
            "https://1.1.1.1/dns-query",
            "tls://8.8.4.4",
            "tls://1.0.0.1"
        ],
        "fallback-filter": {
            "geoip": true,
            "geoip-code": "CN",
            "ipcidr": ["240.0.0.0/4", "0.0.0.0/32"],
            "domain": ["+.google.com", "+.facebook.com", "+.youtube.com"]
        }
    };
}

// ================= 5. 策略组生成 =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    if (!proxies || proxies.length === 0) return [];
    
    const proxyNames = proxies.map(p => p.name);
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));
    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];
    
    groups.push({ name: PROXY_GROUPS.SELECT, type: "select", proxies: mainProxies });
    if (landing) {
        groups.push({ name: PROXY_GROUPS.FRONT, type: "select", proxies: [PROXY_GROUPS.AUTO, ...frontProxies] });
        groups.push({ name: PROXY_GROUPS.LANDING, type: "select", proxies: landingProxies.length ? landingProxies : ["DIRECT"] });
    }
    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: [PROXY_GROUPS.AUTO, ...frontProxies] });
    groups.push({ name: PROXY_GROUPS.AUTO, type: "url-test", proxies: frontProxies.length ? frontProxies : ["DIRECT"], interval: 300, tolerance: 50 });
    
    [PROXY_GROUPS.NETFLIX, PROXY_GROUPS.TELEGRAM].forEach(groupName => {
        const subProxies = [PROXY_GROUPS.AUTO, PROXY_GROUPS.SELECT, ...frontProxies];
        groups.push({ name: groupName, type: "select", proxies: subProxies });
    });

    groups.push({ name: PROXY_GROUPS.MATCH, type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });
    groups.push({ name: PROXY_GROUPS.DIRECT, type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });
    return groups;
}

// ================= 6. 主程序 (零干扰模式) =================
function main(e) {
    try {
        // 🚨 1. 全局清理：这是唯一必须做的“破坏”
        // 因为如果不删这个，你的 Hysteria2 协议一定会被指纹干扰导致断连。
        // 这不影响节点内部参数，只影响全局设置，是安全的。
        if (e['global-client-fingerprint']) delete e['global-client-fingerprint'];

        let rawProxies = e.proxies || [];
        let finalProxies = [];
        const excludeKeywords = /套餐|官网|剩余|时间|重置|异常|邮箱|网址/i;
        const strictLandingKeyword = "落地"; 

        rawProxies.forEach(p => {
            if (excludeKeywords.test(p.name)) return;

            // ================== ✅ 零干扰原则 ==================
            // 我移除了所有修改 p.udp, p.tfo, p.servername, p.skip-cert-verify 的代码。
            // 节点参数将保持和你订阅里的一模一样。
            // 这样就能确保那个敏感的机场不会因为参数变动而连接失败。
            // ==================================================

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

        const config = { 
            proxies: finalProxies,
            "mixed-port": 7890,
            "allow-lan": true,
            ipv6: ipv6Enabled, 
            mode: "rule",
            "unified-delay": true,
            "tcp-concurrent": true,
            "listeners": autoListeners,
            "proxy-groups": u,
            rules: baseRules,
            dns: buildDnsConfig(), // 你的定制 DNS
            sniffer: { // 补充 Sniffer 设置，确保域名嗅探正常
                enable: true,
                "force-dns-mapping": true,
                "parse-pure-ip": true,
                "override-destination": true,
                sniff: {
                    TLS: { ports: [443, 8443] },
                    HTTP: { ports: [80, 8080, 8880] },
                    QUIC: { ports: [443, 8443] }
                }
            }
        };

        return config;
    } catch (error) {
        console.log("Script Error: " + error);
        return e;
    }
}
