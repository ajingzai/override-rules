/*!
powerfullz 的 Substore 订阅转换脚本 (最终回归版)
https://github.com/powerfullz/override-rules

配置说明：
1. [分组回归] 只有“前置代理”和“落地节点”，简单粗暴。
2. [DNS复刻] 按照你的截图，使用腾讯/阿里 DoH 作为主力，追求国内秒开。
3. [规则硬编码] 不再引用 ACL4SSR，所有规则手动写死，包含 Grok/豆包/TikTok 修复。
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 组名定义 (经典结构) =================
const PROXY_GROUPS = {
    SELECT: "🚀 节点选择",
    FRONT: "⚡ 前置代理",
    LANDING: "🛫 落地节点",
    MANUAL: "🔄 手动切换",
    DIRECT: "🎯 全球直连",
    AUTO: "♻️ 自动选择"
};

// ================= 3. 规则集 (无在线引用，全内置) =================
// 既然不要 ACL4SSR，这里留空即可，只保留最基础的去广告
const ruleProviders = {
    ADBlock: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://adrules.top/adrules-mihomo.mrs", path: "./ruleset/ADBlock.mrs" }
};

// ================= 4. 规则配置 (硬编码 + 截图DNS配合) =================
const baseRules = [
    // 1. 阻断 QUIC (UDP 443) - 防止 YouTube/TikTok 转圈
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",

    // ================= 🚀 国产 AI 加速 (直连) =================
    // 必须放在最前面！解决豆包/文心一言转圈问题
    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`, // 豆包后端
    `DOMAIN-SUFFIX,yiyan.baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,chatglm.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,kimi.ai,${PROXY_GROUPS.DIRECT}`,

    // ================= 🌍 国外重点 (代理) =================
    // Grok / xAI / Twitter
    `DOMAIN-SUFFIX,grok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twimg.com,${PROXY_GROUPS.SELECT}`,
    
    // GitHub
    `DOMAIN-KEYWORD,github,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`,

    // Telegram
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.SELECT}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.SELECT},no-resolve`,

    // TikTok (暴力全覆盖)
    `DOMAIN-KEYWORD,tiktok,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,byteoversea.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ibytedtos.com,${PROXY_GROUPS.SELECT}`,

    // Google / YouTube / OpenAI
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,

    // ================= 🏠 国内常用 (直连) =================
    "RULE-SET,ADBlock,REJECT",
    
    // 强制直连常见国内大厂，防止误伤
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,163.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alipay.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,jd.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bilibili.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weibo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,zhihu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xiaomi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,huawei.com,${PROXY_GROUPS.DIRECT}`,

    // 如果是国内 IP，走直连
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    
    // ================= 🐟 漏网之鱼 =================
    // 剩下的全部走代理
    `MATCH,${PROXY_GROUPS.SELECT}`
];

// ================= 5. DNS 配置 (截图复刻 + 优化) =================
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: false, // 截图关闭了 IPv6
        "prefer-h3": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        // 1. 引导 DNS：使用 IP 格式，防止死循环
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        
        // 2. 主 DNS：按照你的截图，全用国内 DoH
        // 这样解析国内网站极快，国外网站靠 Fake-IP 也不慢
        nameserver: [
            "https://doh.pub/dns-query",      
            "https://dns.alidns.com/dns-query" 
        ],
        
        // 3. 代理 DNS
        "proxy-server-nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        
        // 4. Fallback (截图里你设置了 AliDNS，这里加上)
        fallback: [
            "https://dns.alidns.com/dns-query"
        ],
        
        // 5. 【优化点】Fake-IP 过滤
        // 把豆包等国产 AI 加入过滤，强制它们解析真实 IP 走直连
        "fake-ip-filter": [
            "*.lan", "*.local", "time.*.com", "ntp.*.com", 
            "+.market.xiaomi.com", "*.stun.*.*", "*.stun.*.*.*",
            "+.doubao.com", "+.volces.com", "+.chatglm.cn"
        ]
    };
}

const snifferConfig = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, 8080, 8880] }, QUIC: { ports: [443, 8443] } }
};

// ================= 6. 策略组生成 (前置/落地) =================
function buildProxyGroups(params) {
    const isLanding = params.landing;
    const groups = [];

    // 核心代理列表
    const mainProxies = isLanding 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, "DIRECT"] 
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 1. 🚀 节点选择 (主入口)
    groups.push({
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: mainProxies
    });

    // 2. ⚡ 前置代理 (Landing 模式)
    if (isLanding) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select",
            "include-all": true,
            "exclude-filter": " -> 前置"
        });
        
        // 3. 🛫 落地节点 (Landing 模式)
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select",
            "include-all": true,
            filter: " -> 前置"
        });
    }

    // 4. ♻️ 自动 & 🔄 手动
    groups.push({ name: PROXY_GROUPS.AUTO, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png", type: "url-test", interval: 300, tolerance: 50, "include-all": true });
    groups.push({ name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", type: "select", "include-all": true });

    // 5. 🎯 全球直连 (修复 Loop 问题，只含 DIRECT)
    groups.push({
        name: PROXY_GROUPS.DIRECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
        type: "select",
        proxies: ["DIRECT"]
    });

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

    const u = buildProxyGroups({ landing: landing });
    const d = u.map(e => e.name);
    u.push({name: "GLOBAL", type: "select", proxies: d});

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
        "rule-providers": ruleProviders,
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
