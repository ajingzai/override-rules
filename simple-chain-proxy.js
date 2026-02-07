/*!
powerfullz 的 Substore 订阅转换脚本 (电报分组增强版)
https://github.com/powerfullz/override-rules

配置变更：
1. [新增分组] 增加 "06. 电报消息"，规则指向 Telegram 相关流量。
2. [同步选项] 电报分组的可选节点与 "01. 节点选择" 保持一致。
3. [排序调整] 
   - 01-05 保持不变
   - 06. 电报消息 (新增)
   - 07. 漏网之鱼 (原06)
   - 08. 全球直连 (原07)
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 (排序顺延) =================
const PROXY_GROUPS = {
    SELECT:   "01. 节点选择",
    AUTO:     "02. 自动选择",
    FRONT:    "03. 前置代理",
    LANDING:  "04. 落地节点",
    MANUAL:   "05. 手动切换",
    TELEGRAM: "06. 电报消息", // <--- 新增
    MATCH:    "07. 漏网之鱼", // 06 -> 07
    DIRECT:   "08. 全球直连", // 07 -> 08
    GLOBAL:   "GLOBAL" 
};

// ================= 3. 规则配置 (硬编码) =================
const baseRules = [
    // --- 0. 核心阻断 ---
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",

    // --- 1. 国产 AI & 直连白名单 (强制直连) ---
    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,yiyan.baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,chatglm.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,kimi.ai,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,moonshot.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,hunyuan.tencent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,deepseek.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,sensetime.com,${PROXY_GROUPS.DIRECT}`,
    
    // --- 2. 电报专属 (Telegram) ---
    // 将 TG 流量全部指派给新分组
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,t.me,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,tdesktop.com,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,tx.me,${PROXY_GROUPS.TELEGRAM}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    `IP-CIDR,149.154.160.0/20,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    `IP-CIDR,5.28.192.0/18,${PROXY_GROUPS.TELEGRAM},no-resolve`, // 补充常用 TG IP 段

    // --- 3. 国外 AI (强制代理) ---
    `DOMAIN-SUFFIX,grok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaiusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,anthropic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,perplexity.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,poe.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,midjourney.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discord.gg,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,stability.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,huggingface.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,civitai.com,${PROXY_GROUPS.SELECT}`,

    // --- 4. 国际社交 (代理) ---
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,facebook.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,instagram.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,whatsapp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,reddit.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discord.com,${PROXY_GROUPS.SELECT}`,

    // --- 5. 国际流媒体 (代理) ---
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,netflix.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,disneyplus.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,spotify.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktok.com,${PROXY_GROUPS.SELECT}`,

    // --- 6. 开发/技术 (代理) ---
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,docker.com,${PROXY_GROUPS.SELECT}`,

    // --- 7. 国际搜索 (代理) ---
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bing.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,wikipedia.org,${PROXY_GROUPS.SELECT}`,

    // --- 8. 国内直连 (Direct) ---
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,aliyun.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alipay.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bilibili.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,12306.cn,${PROXY_GROUPS.DIRECT}`,
    
    // --- 9. 兜底 ---
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 (秒开) =================
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
        "proxy-server-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        fallback: [],
        "fake-ip-filter": ["*.lan", "*.local", "+.market.xiaomi.com", "*.stun.*.*", "+.doubao.com", "+.volces.com"]
    };
}

const snifferConfig = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, 8080, 8880] }, QUIC: { ports: [443, 8443] } }
};

// ================= 5. 策略组生成 =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    const proxyNames = proxies.map(p => p.name);
    
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 01. 节点选择
    groups.push({
        name: PROXY_GROUPS.SELECT,
        type: "select",
        proxies: mainProxies
    });

    // 02. 自动选择
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies,
        interval: 300, 
        tolerance: 50 
    });

    // 03. 前置代理
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, ...frontProxies] 
        });
    }

    // 04. 落地节点
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.LANDING,
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    // 05. 手动切换
    groups.push({ 
        name: PROXY_GROUPS.MANUAL, 
        type: "select", 
        proxies: [PROXY_GROUPS.AUTO, ...frontProxies]
    });

    // 06. 电报消息 (新增，节点选项与 01 保持一致)
    groups.push({
        name: PROXY_GROUPS.TELEGRAM,
        type: "select",
        proxies: mainProxies 
    });

    // 07. 漏网之鱼
    groups.push({
        name: PROXY_GROUPS.MATCH,
        type: "select",
        proxies: [PROXY_GROUPS.SELECT, "DIRECT"]
    });

    // 08. 全球直连
    groups.push({
        name: PROXY_GROUPS.DIRECT,
        type: "select",
        proxies: ["DIRECT", PROXY_GROUPS.SELECT] 
    });

    return groups;
}

// ================= 6. 主程序 =================
function main(e) {
    let rawProxies = e.proxies || [];
    let finalProxies = [];
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
            finalProxies.push(p);
        }
    });

    // 端口映射
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

    const u = buildProxyGroups(finalProxies, landing);
    
    // GLOBAL 组
    const allProxyNames = finalProxies.map(p => p.name);
    u.push({
        name: "GLOBAL", 
        type: "select", 
        proxies: allProxyNames
    });

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
        "rule-providers": {},
        rules: baseRules,
        sniffer: snifferConfig,
        dns: buildDnsConfig(),
        "geodata-mode": true,
        "geox-url": {
            geoip: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
            geosite: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
            mmdb: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"
        }
    };
}


这是完整文件，你在上面加，
