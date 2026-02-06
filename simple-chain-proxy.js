/*!
powerfullz 的 Substore 订阅转换脚本 (分组排序优化版)
https://github.com/powerfullz/override-rules

配置变更：
1. [排序] 将 "前置代理"、"落地节点"、"手动切换" 提权至顶部，紧跟在 "节点选择" 之后。
2. [重构] 移除负载均衡，采用精细化 App 策略组。
3. [保底] UDP/QUIC 默认放行。
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 (序号重排) =================
const PROXY_GROUPS = {
    SELECT:   "01. 节点选择",
    FRONT:    "02. 前置代理", // ⬆️ 提权
    LANDING:  "03. 落地节点", // ⬆️ 提权
    MANUAL:   "04. 手动切换", // ⬆️ 提权
    AUTO:     "05. 自动选择",
    OPENAI:   "06. OpenAI",
    YOUTUBE:  "07. YouTube",
    NETFLIX:  "08. Netflix",
    TIKTOK:   "09. TikTok",
    TELEGRAM: "10. Telegram",
    TWITTER:  "11. Twitter",
    GAMES:    "12. 游戏平台",
    MATCH:    "13. 漏网之鱼",
    DIRECT:   "14. 全球直连",
    GLOBAL:   "GLOBAL" 
};

// ================= 3. 规则配置 =================
const baseRules = [
    // --- 0. 特殊直连 ---
    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,deepseek.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,

    // --- 1. OpenAI / AI ---
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,oaiusercontent.com,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,anthropic.com,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,grok.com,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,x.ai,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,perplexity.ai,${PROXY_GROUPS.OPENAI}`,
    `DOMAIN-SUFFIX,poe.com,${PROXY_GROUPS.OPENAI}`,

    // --- 2. YouTube ---
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.YOUTUBE}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.YOUTUBE}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.YOUTUBE}`,
    `DOMAIN-SUFFIX,gvt1.com,${PROXY_GROUPS.YOUTUBE}`,

    // --- 3. Netflix / 流媒体 ---
    `DOMAIN-SUFFIX,netflix.com,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,netflix.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflximg.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflxvideo.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,disneyplus.com,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,bamgrid.com,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,hbo.com,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,hulu.com,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,primevideo.com,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,iq.com,${PROXY_GROUPS.NETFLIX}`,

    // --- 4. TikTok ---
    `DOMAIN-SUFFIX,tiktok.com,${PROXY_GROUPS.TIKTOK}`,
    `DOMAIN-SUFFIX,tiktokcdn.com,${PROXY_GROUPS.TIKTOK}`,
    `DOMAIN-SUFFIX,musically.com,${PROXY_GROUPS.TIKTOK}`,
    `DOMAIN-KEYWORD,tiktok,${PROXY_GROUPS.TIKTOK}`,

    // --- 5. Telegram ---
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,t.me,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,tdesktop.com,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,tx.me,${PROXY_GROUPS.TELEGRAM}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    `IP-CIDR,149.154.160.0/20,${PROXY_GROUPS.TELEGRAM},no-resolve`,

    // --- 6. Twitter ---
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.TWITTER}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.TWITTER}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.TWITTER}`,

    // --- 7. 游戏 ---
    `DOMAIN-SUFFIX,steamcommunity.com,${PROXY_GROUPS.GAMES}`,
    `DOMAIN-SUFFIX,discord.com,${PROXY_GROUPS.GAMES}`,
    `DOMAIN-SUFFIX,discord.gg,${PROXY_GROUPS.GAMES}`,
    `DOMAIN-SUFFIX,twitch.tv,${PROXY_GROUPS.GAMES}`,
    `DOMAIN-SUFFIX,epicgames.com,${PROXY_GROUPS.GAMES}`,

    // --- 8. Google / 其他常用 ---
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,instagram.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,facebook.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,whatsapp.com,${PROXY_GROUPS.SELECT}`,

    // --- 9. 强制直连 ---
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,jd.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,12306.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,apple.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,microsoft.com,${PROXY_GROUPS.DIRECT}`,

    // --- 10. 兜底 ---
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

// ================= 5. 策略组生成 (新排序版) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    if (!proxies || proxies.length === 0) return [];
    
    const proxyNames = proxies.map(p => p.name);
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    // 主选择列表 (含所有分组)
    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];
    
    // 子功能列表 (用于 OpenAI, Netflix 等)
    const subProxies = [PROXY_GROUPS.AUTO, PROXY_GROUPS.SELECT, ...frontProxies];

    // --- 01. 节点选择 (主入口) ---
    groups.push({ name: PROXY_GROUPS.SELECT, type: "select", proxies: mainProxies });

    // --- 02. 前置代理 (Landing模式) ---
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, ...frontProxies] 
        });
    }

    // --- 03. 落地节点 (Landing模式) ---
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.LANDING,
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    // --- 04. 手动切换 ---
    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: [PROXY_GROUPS.AUTO, ...frontProxies] });

    // --- 05. 自动选择 ---
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies.length ? frontProxies : ["DIRECT"],
        interval: 300, 
        tolerance: 50 
    });

    // --- 06+. App 独立分组 ---
    const customGroups = [
        PROXY_GROUPS.OPENAI,
        PROXY_GROUPS.YOUTUBE,
        PROXY_GROUPS.NETFLIX,
        PROXY_GROUPS.TIKTOK,
        PROXY_GROUPS.TELEGRAM,
        PROXY_GROUPS.TWITTER,
        PROXY_GROUPS.GAMES
    ];

    customGroups.forEach(groupName => {
        groups.push({
            name: groupName,
            type: "select",
            proxies: subProxies
        });
    });

    // --- 末尾分组 ---
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
