/*!
powerfullz 的 Substore 订阅转换脚本 (Geosite 集合懒人版)
https://github.com/powerfullz/override-rules

核心逻辑：
1. 使用 GEOSITE 集合 (google/twitter/apple等) 代替手动域名，脚本更短更全。
2. 依然保留 TikTok 修复、Steam 下载直连等精细化策略。
3. "漏网之鱼" 建议设为 代理 (Select)，这就是你想要的 "国外全集"。
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
    // ➤ 0. 必须手动指定的精细策略 (直连优先)
    // ------------------------------------------------
    // 如下域名 Geosite 可能会误判走代理，所以手动强制直连
    `DOMAIN-SUFFIX,steamcontent.com,${PROXY_GROUPS.DIRECT}`, // Steam下载
    `DOMAIN-SUFFIX,steampipe.akamaized.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,dl.steam.clngaa.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,dl.steam.ksyna.com,${PROXY_GROUPS.DIRECT}`,
    
    // 微软部分服务直连 (Geosite microsoft 包含太广，容易把下载也代理了)
    `DOMAIN-SUFFIX,windowsupdate.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,microsoft.com,${PROXY_GROUPS.DIRECT}`,

    // ------------------------------------------------
    // ➤ 1. 国际 AI (手动指定，防止 Geosite 更新不及时)
    // ------------------------------------------------
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,openai,${PROXY_GROUPS.SELECT}`, // 兜底

    // ------------------------------------------------
    // ➤ 2. TikTok (核心修复：必须手动写)
    // ------------------------------------------------
    // 阻断 UDP/QUIC (解决视频转圈)
    `AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-KEYWORD,tiktok)),REJECT`, 
    // 强制流量策略
    `GEOSITE,tiktok,${PROXY_GROUPS.SELECT}`, // 这一行代替了 tiktok.com, muscdn 等几十个域名

    // ------------------------------------------------
    // ➤ 3. 国际巨头集合 (这就是你要的“国外规则集”)
    // ------------------------------------------------
    // Google 全家桶 (含 YouTube, Gdrive, Gmail, Ggpht 头像)
    `GEOSITE,youtube,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,google,${PROXY_GROUPS.SELECT}`,
    
    // 社交网络 (含 Twitter, FB, Ins, Whatsapp)
    `GEOSITE,twitter,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,facebook,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,instagram,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,telegram,${PROXY_GROUPS.TELEGRAM}`,

    // 流媒体
    `GEOSITE,netflix,${PROXY_GROUPS.NETFLIX}`,
    `GEOSITE,disney,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,spotify,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,hbo,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,primevideo,${PROXY_GROUPS.SELECT}`,

    // 开发者与工具
    `GEOSITE,github,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,docker,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,onedrive.com,${PROXY_GROUPS.SELECT}`, // OneDrive 建议手动指定代理
    `DOMAIN-SUFFIX,sharepoint.com,${PROXY_GROUPS.SELECT}`,

    // ------------------------------------------------
    // ➤ 4. 常见的被墙列表 (补充 Geosite 没覆盖到的)
    // ------------------------------------------------
    `GEOSITE,gfw,${PROXY_GROUPS.SELECT}`, // 🚨 这一行包含了绝大多数已知的被墙域名

    // ------------------------------------------------
    // ➤ 5. 国内直连集合 (使用 GEOSITE,CN)
    // ------------------------------------------------
    `GEOSITE,apple,${PROXY_GROUPS.DIRECT}`, // Apple 国内直连通常更快
    `GEOSITE,bilibili,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,steam,${PROXY_GROUPS.DIRECT}`, // Steam 商店/社区视地区而定，这里默认直连，连不上会走漏网之鱼
    `GEOSITE,cn,${PROXY_GROUPS.DIRECT}`,   // 🚨 包含 阿里/腾讯/百度/网易/字节 等所有国内巨头

    // ------------------------------------------------
    // ➤ 6. 兜底策略 (最关键的一步)
    // ------------------------------------------------
    // 先判断是不是国内 IP
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    
    // 🔴 剩下的全是国外 -> 走节点选择
    // 这就是你理解的 "国外规则集"
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 =================
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: false,
        "prefer-h3": false, // 保持 false 修复 TikTok
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        nameserver: ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        fallback: [] // fake-ip 模式下通常不需要 fallback，依赖规则分流
    };
}

// ================= 5. 策略组生成 (保持不变) =================
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

    // 01. 节点选择
    groups.push({ name: PROXY_GROUPS.SELECT, type: "select", proxies: mainProxies });

    // 02. 前置代理
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, ...frontProxies] 
        });
    }

    // 03. 落地节点
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.LANDING,
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    // 04. 手动切换
    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: [PROXY_GROUPS.AUTO, ...frontProxies] });

    // 05. 自动选择
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies.length ? frontProxies : ["DIRECT"],
        interval: 300, 
        tolerance: 50 
    });

    // 06+. 独立 App
    const customGroups = [PROXY_GROUPS.NETFLIX, PROXY_GROUPS.TELEGRAM];
    customGroups.forEach(groupName => {
        groups.push({ name: groupName, type: "select", proxies: subProxies });
    });

    // 末尾
    // ⚠️ 注意：这里建议将 MATCH 指向 SELECT，实现“所有未知国外域名自动代理”
    groups.push({ name: PROXY_GROUPS.MATCH, type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });
    groups.push({ name: PROXY_GROUPS.DIRECT, type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });

    return groups;
}

// ================= 6. 主程序 (保持 Hy2 修复) =================
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
            // global-client-fingerprint 已移除
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
