/*!
powerfullz 的 Substore 订阅转换脚本 (多机场兼容修复版)
https://github.com/powerfullz/override-rules

配置变更：
1. [兼容] 新增 "节点体检" 模块，自动修复 Vless/Reality 缺失指纹的问题。
2. [兼容] 强制所有 TLS 节点跳过证书验证 (skip-cert-verify)，救活自签名机场。
3. [修复] 依然保持 Hy2 无指纹逻辑，确保 Hy2 和 Vless Reality 共存。
4. [DNS] 保持完美复刻的 DNS 配置。
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
    // ------------------------------------------------
    // ➤ 0. 必须手动指定的精细策略
    // ------------------------------------------------
    `DOMAIN-SUFFIX,steamcontent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,steampipe.akamaized.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,dl.steam.clngaa.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,dl.steam.ksyna.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,windowsupdate.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,microsoft.com,${PROXY_GROUPS.DIRECT}`,

    // ------------------------------------------------
    // ➤ 1. 国际 AI
    // ------------------------------------------------
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,openai,${PROXY_GROUPS.SELECT}`,

    // ------------------------------------------------
    // ➤ 2. TikTok
    // ------------------------------------------------
    `GEOSITE,tiktok,${PROXY_GROUPS.SELECT}`, 

    // ------------------------------------------------
    // ➤ 3. 国际巨头集合
    // ------------------------------------------------
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

    // ------------------------------------------------
    // ➤ 4. 常见的被墙列表
    // ------------------------------------------------
    `GEOSITE,gfw,${PROXY_GROUPS.SELECT}`,

    // ------------------------------------------------
    // ➤ 5. 国内直连集合
    // ------------------------------------------------
    `GEOSITE,apple,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,bilibili,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,steam,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,cn,${PROXY_GROUPS.DIRECT}`,

    // ------------------------------------------------
    // ➤ 6. 兜底策略
    // ------------------------------------------------
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 (完美复刻所有截图) =================
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
        "default-nameserver": [
            "tls://223.5.5.5",
            "119.29.29.29" 
        ],
        "nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        "fallback": [
            "https://dns.google/dns-query",
            "https://1.1.1.1/dns-query",
            "tls://8.8.4.4",
            "tls://1.0.0.1"
        ],
        "fallback-filter": {
            "geoip": true,
            "geoip-code": "CN",
            "ipcidr": [
                "240.0.0.0/4",
                "0.0.0.0/32"
            ],
            "domain": [
                "+.google.com",
                "+.facebook.com",
                "+.youtube.com"
            ]
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
    
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies.length ? frontProxies : ["DIRECT"],
        interval: 300, 
        tolerance: 50 
    });

    const customGroups = [PROXY_GROUPS.NETFLIX, PROXY_GROUPS.TELEGRAM];
    customGroups.forEach(groupName => {
        groups.push({ name: groupName, type: "select", proxies: subProxies });
    });

    groups.push({ name: PROXY_GROUPS.MATCH, type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });
    groups.push({ name: PROXY_GROUPS.DIRECT, type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });

    return groups;
}

// ================= 6. 主程序 (含多机场修复模块) =================
function main(e) {
    try {
        // 🚨 1. 全局清理：删除可能会干扰 Hy2 的全局指纹
        if (e['global-client-fingerprint']) {
            delete e['global-client-fingerprint'];
        }

        let rawProxies = e.proxies || [];
        let finalProxies = [];
        const excludeKeywords = /套餐|官网|剩余|时间|重置|异常|邮箱|网址/i;
        const strictLandingKeyword = "落地"; 

        rawProxies.forEach(p => {
            if (excludeKeywords.test(p.name)) return;
            
            // ================== 🚑 节点急救包 START ==================
            // 2. 通用修复：确保 UDP 开启，跳过证书验证 (解决自签名机场超时)
            if (p.udp === undefined) p.udp = true;
            if (p.tls || p['client-fingerprint']) {
                p['skip-cert-verify'] = true; 
            }

            // 3. Vless/Reality 修复：如果缺失指纹，补全为 chrome
            // (注意：仅针对 Vless，不碰 Hy2)
            if (p.type === 'vless' && !p['client-fingerprint']) {
                p['client-fingerprint'] = 'chrome';
            }

            // 4. Hysteria2 修复：确保没有指纹干扰
            if (p.type === 'hysteria2' && p['client-fingerprint']) {
                delete p['client-fingerprint'];
            }
            // ================== 🚑 节点急救包 END ==================

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
