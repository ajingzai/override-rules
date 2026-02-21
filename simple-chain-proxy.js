/*!
powerfullz 的 Substore 订阅转换脚本 (监听端口增强 + 截图 DNS 版 + 4地区分组 + 前置代理严格限制 + 落地节点前置 + 奈飞分组)
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
    HK:       "04. 香港节点",
    JP:       "05. 日本节点",
    US:       "06. 美国节点",
    TW:       "07. 台湾节点",
    MANUAL:   "08. 手动切换",
    TELEGRAM: "09. 电报消息",
    NETFLIX:  "12. 奈飞视频", // 新增奈飞组
    MATCH:    "10. 漏网之鱼",
    DIRECT:   "11. 全球直连",
    GLOBAL:   "GLOBAL" 
};

// ================= 3. 规则配置 =================
const baseRules = [
    "AND,(DST-PORT,443),(NETWORK,udp),REJECT", 
    
    `DOMAIN-SUFFIX,gvt1.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gvt2.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gvt3.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.cn,${PROXY_GROUPS.SELECT}`, 
    `DOMAIN-KEYWORD,xn--ngstr-lra8j,${PROXY_GROUPS.SELECT}`,

    // 奈飞规则
    `DOMAIN-SUFFIX,netflix.com,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,netflix.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflximg.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflxvideo.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflxso.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflxext.com,${PROXY_GROUPS.NETFLIX}`,

    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,yiyan.baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,chatglm.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,kimi.ai,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,moonshot.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,hunyuan.tencent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,deepseek.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,t.me,${PROXY_GROUPS.TELEGRAM}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    `IP-CIDR,149.154.160.0/20,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    
    `DOMAIN-SUFFIX,bing.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bingapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,copilot.microsoft.com,${PROXY_GROUPS.SELECT}`,

    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,anthropic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,binance.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,okx.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,jd.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alipay.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weixin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bilibili.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,apple.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,microsoft.com,${PROXY_GROUPS.DIRECT}`,
    
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 =================
function buildDnsConfig() {
    return {
        "enable": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "ipv6": false,
        "prefer-h3": true,
        "direct-nameserver-follow-matching": false,
        "nameserver-policy": {
            "+.lan": "223.5.5.5",
            "+.local": "223.5.5.5",
            "time.*.com": "223.5.5.5",
            "ntp.*.com": "223.5.5.5",
            "+.market.xiaomi.com": "223.5.5.5"
        },
        "default-nameserver": ["tls://223.5.5.5"],
        "proxy-server-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        "fallback-filter": {
            "geoip": true,
            "geoip-code": "CN",
            "ip-cidr": ["240.0.0.0/4", "0.0.0.0/32"],
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

    const hkProxies = proxyNames.filter(n => /港|HK|Hong/i.test(n) && !n.includes("落地"));
    const jpProxies = proxyNames.filter(n => /日|JP|Japan/i.test(n) && !n.includes("落地"));
    const usProxies = proxyNames.filter(n => /美|US|United States|America/i.test(n) && !n.includes("落地"));
    const twProxies = proxyNames.filter(n => /台|TW|Taiwan/i.test(n) && !n.includes("落地"));

    const regionGroups = [PROXY_GROUPS.HK, PROXY_GROUPS.JP, PROXY_GROUPS.US, PROXY_GROUPS.TW];
    const mainProxies = landing 
        ? [PROXY_GROUPS.MANUAL, ...regionGroups, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, "DIRECT"]
        : [PROXY_GROUPS.MANUAL, ...regionGroups, "DIRECT"];

    // 组合 手动切换/奈飞 的选项（排除落地节点）
    const cleanOptions = [...regionGroups, ...(frontProxies.length ? frontProxies : ["DIRECT"])];

    // 01. 节点选择
    groups.push({ name: PROXY_GROUPS.SELECT, type: "select", proxies: mainProxies });

    if (landing) {
        groups.push({ name: PROXY_GROUPS.FRONT, type: "select", proxies: regionGroups.length ? regionGroups : ["DIRECT"] });
        groups.push({ name: PROXY_GROUPS.LANDING, type: "select", proxies: landingProxies.length ? landingProxies : ["DIRECT"] });
    }

    // 04-07 地区分组
    groups.push({ name: PROXY_GROUPS.HK, type: "select", proxies: hkProxies.length ? hkProxies : ["DIRECT"] });
    groups.push({ name: PROXY_GROUPS.JP, type: "select", proxies: jpProxies.length ? jpProxies : ["DIRECT"] });
    groups.push({ name: PROXY_GROUPS.US, type: "select", proxies: usProxies.length ? usProxies : ["DIRECT"] });
    groups.push({ name: PROXY_GROUPS.TW, type: "select", proxies: twProxies.length ? twProxies : ["DIRECT"] });

    // 08. 手动切换
    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: cleanOptions });
    
    // 09. 电报消息
    groups.push({ name: PROXY_GROUPS.TELEGRAM, type: "select", proxies: mainProxies });

    // 12. 奈飞视频 (放在电报下面，排除落地节点)
    groups.push({ name: PROXY_GROUPS.NETFLIX, type: "select", proxies: cleanOptions });

    // 10. 漏网之鱼 & 11. 全球直连
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
