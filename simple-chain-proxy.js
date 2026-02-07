/*!
powerfullz 的 Substore 订阅转换脚本 (零干扰兼容版)
https://github.com/powerfullz/override-rules

配置变更：
1. [回滚] 停止对单个节点指纹 (fingerprint) 的增删改，尊重机场原始配置。
2. [回滚] 停止强制 skip-cert-verify，防止 Reality 节点验证失败。
3. [保留] 仅删除 "全局" 指纹，解决 Hy2/Tuic 协议冲突。
4. [保留] 完美 DNS 配置 + TikTok/YouTube 规则 + 分组策略。
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

// ================= 4. DNS 配置 (完美复刻版) =================
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

// ================= 6. 主程序 (零干扰兼容版) =================
function main(e) {
    try {
        // 🚨 1. 全局清理：这是唯一必须删除的全局设置
        // 删掉它解决了 Hy2/Tuic 的大面积冲突
        if (e['global-client-fingerprint']) delete e['global-client-fingerprint'];

        let rawProxies = e.proxies || [];
        let finalProxies = [];
        const excludeKeywords = /套餐|官网|剩余|时间|重置|异常|邮箱|网址/i;
        const strictLandingKeyword = "落地"; 

        rawProxies.forEach(p => {
            if (excludeKeywords.test(p.name)) return;

            // ================== 🛡️ 保守修复策略 START ==================
            // 2. 基础补全：只做最安全的修改
            if (p.udp === undefined) p.udp = true; 
            if (p.tfo !== undefined) p.tfo = false; // 关闭 TFO 通常更稳定

            // 3. SNI 补全：这步很关键，防止 Clash Meta 读不出 host
            // 如果只有 host 没有 servername，就复制一份
            if (!p.servername) {
                if (p.sni) p.servername = p.sni;
                else if (p.host) p.servername = p.host;
                else if (p['ws-opts'] && p['ws-opts'].headers && p['ws-opts'].headers.Host) {
                    p.servername = p['ws-opts'].headers.Host;
                }
            }
            
            // 🛑 4. 关键：彻底停止对指纹 (client-fingerprint) 和证书 (skip-cert-verify) 的干预！
            // 之前的脚本在这里做了太多的 "自作聪明" 的修改，导致部分机场节点验证失败。
            // 现在完全保留订阅原样的设置。
            // ================== 🛡️ 保守修复策略 END ==================

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
