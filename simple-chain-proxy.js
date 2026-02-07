/*!
powerfullz 的 Substore 订阅转换脚本 (SNI 补全 + TFO 禁用修复版)
https://github.com/powerfullz/override-rules

配置变更：
1. [关键修复] 自动补全缺失的 servername (SNI)，解决 Vless/Trojan 全红。
2. [回滚] 撤销强制 skip-cert-verify，防止误杀 Reality 节点。
3. [网络] 强制关闭 TCP Fast Open (TFO)，防止握手堵塞。
4. [保留] Hy2 指纹移除、DNS 完美配置、TikTok 规则。
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

// ================= 3. 规则配置 =================
const baseRules = [
    // 0. 精细策略
    `DOMAIN-SUFFIX,steamcontent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,steampipe.akamaized.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,dl.steam.clngaa.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,dl.steam.ksyna.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,windowsupdate.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,microsoft.com,${PROXY_GROUPS.DIRECT}`,

    // 1. AI
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,openai,${PROXY_GROUPS.SELECT}`,

    // 2. TikTok
    `GEOSITE,tiktok,${PROXY_GROUPS.SELECT}`, 

    // 3. 国际巨头
    `GEOSITE,youtube,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,google,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,twitter,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,facebook,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,instagram,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,telegram,${PROXY_GROUPS.TELEGRAM}`,
    `GEOSITE,netflix,${PROXY_GROUPS.NETFLIX}`,
    `GEOSITE,disney,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,spotify,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,github,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,docker,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,onedrive.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,sharepoint.com,${PROXY_GROUPS.SELECT}`,

    // 4. 被墙列表
    `GEOSITE,gfw,${PROXY_GROUPS.SELECT}`,

    // 5. 国内直连
    `GEOSITE,apple,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,bilibili,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,steam,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,cn,${PROXY_GROUPS.DIRECT}`,

    // 6. 兜底
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 (保持复刻) =================
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
    const subProxies = [PROXY_GROUPS.AUTO, PROXY_GROUPS.SELECT, ...frontProxies];

    groups.push({ name: PROXY_GROUPS.SELECT, type: "select", proxies: mainProxies });
    if (landing) {
        groups.push({ name: PROXY_GROUPS.FRONT, type: "select", proxies: [PROXY_GROUPS.AUTO, ...frontProxies] });
        groups.push({ name: PROXY_GROUPS.LANDING, type: "select", proxies: landingProxies.length ? landingProxies : ["DIRECT"] });
    }
    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: [PROXY_GROUPS.AUTO, ...frontProxies] });
    groups.push({ name: PROXY_GROUPS.AUTO, type: "url-test", proxies: frontProxies.length ? frontProxies : ["DIRECT"], interval: 300, tolerance: 50 });
    
    [PROXY_GROUPS.NETFLIX, PROXY_GROUPS.TELEGRAM].forEach(groupName => {
        groups.push({ name: groupName, type: "select", proxies: subProxies });
    });

    groups.push({ name: PROXY_GROUPS.MATCH, type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });
    groups.push({ name: PROXY_GROUPS.DIRECT, type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });
    return groups;
}

// ================= 6. 主程序 (急救修复逻辑) =================
function main(e) {
    try {
        // 1. 强力清除全局指纹
        if (e['global-client-fingerprint']) delete e['global-client-fingerprint'];

        let rawProxies = e.proxies || [];
        let finalProxies = [];
        const excludeKeywords = /套餐|官网|剩余|时间|重置|异常|邮箱|网址/i;
        const strictLandingKeyword = "落地"; 

        rawProxies.forEach(p => {
            if (excludeKeywords.test(p.name)) return;

            // ================== 🚑 节点深度修复 START ==================
            
            // A. 基础属性修复
            if (p.udp === undefined) p.udp = true; // 开启UDP
            if (p.tfo !== undefined) p.tfo = false; // 🚫 强制关闭 TFO (防止握手超时)

            // B. SNI (ServerName) 补全 - 解决 Vless/Trojan 全红的核心
            // 如果没有 servername，但有 host 或 sni，则复制过来
            if (!p.servername) {
                if (p.sni) p.servername = p.sni;
                else if (p.host) p.servername = p.host;
                else if (p['ws-opts'] && p['ws-opts'].headers && p['ws-opts'].headers.Host) {
                    p.servername = p['ws-opts'].headers.Host;
                }
            }

            // C. Hy2 保护
            if (p.type === 'hysteria2' && p['client-fingerprint']) {
                delete p['client-fingerprint'];
            }
            
            // D. Reality 保护 (不要强制 skip-cert-verify，除非它本来就没有)
            // 如果不是 Reality 且使用了 TLS，尝试开启跳过验证（救活自签名）
            // 如果是 Reality (通常有 publicKey)，则绝对不要动 skip-cert-verify
            const isReality = (p['reality-opts'] || p.realityOpts);
            if (!isReality && p.tls && p['skip-cert-verify'] === undefined) {
                p['skip-cert-verify'] = true;
            }

            // ================== 🚑 节点深度修复 END ==================

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
            dns: buildDnsConfig() 
        };

        return config;
    } catch (error) {
        console.log("Script Error: " + error);
        return e;
    }
}
