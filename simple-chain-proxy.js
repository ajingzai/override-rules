/*!
Substore 订阅转换脚本 - 融合版 v3
基于 powerfullz 原版规则集 + ajingzai 定制功能
特性: 在线规则集 + DNS双模式 + Sniffer嗅探 + GeoData + 自动多端口监听 + 链式代理 + 防断流

支持参数:
- landing: 启用落地节点链式代理 (默认 false)
- ipv6Enabled: 启用 IPv6 (默认 false)
- fakeip: DNS 使用 FakeIP 模式 (默认 true, false 为 RedirHost)
- quic: 允许 QUIC 流量 (默认 true)
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing);
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;
const fakeIPEnabled = rawArgs.fakeip !== undefined ? parseBool(rawArgs.fakeip) : true;
const quicEnabled = rawArgs.quic !== undefined ? parseBool(rawArgs.quic) : true;

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
    MATCH:    "10. 漏网之鱼",
    DIRECT:   "11. 全球直连",
    NETFLIX:  "12. 奈飞视频",
    TIKTOK:   "13. TikTok",
    ADBLOCK:  "14. 广告拦截",
    GLOBAL:   "GLOBAL"
};

// ================= 3. 在线规则集 (来自 powerfullz) =================
const ruleProviders = {
    ADBlock: {
        type: "http", behavior: "domain", format: "mrs", interval: 86400,
        url: "https://adrules.top/adrules-mihomo.mrs",
        path: "./ruleset/ADBlock.mrs"
    },
    SogouInput: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt",
        path: "./ruleset/SogouInput.txt"
    },
    StaticResources: {
        type: "http", behavior: "domain", format: "text", interval: 86400,
        url: "https://ruleset.skk.moe/Clash/domainset/cdn.txt",
        path: "./ruleset/StaticResources.txt"
    },
    CDNResources: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://ruleset.skk.moe/Clash/non_ip/cdn.txt",
        path: "./ruleset/CDNResources.txt"
    },
    TikTok: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list",
        path: "./ruleset/TikTok.list"
    },
    EHentai: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list",
        path: "./ruleset/EHentai.list"
    },
    SteamFix: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list",
        path: "./ruleset/SteamFix.list"
    },
    GoogleFCM: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list",
        path: "./ruleset/FirebaseCloudMessaging.list"
    },
    AdditionalFilter: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list",
        path: "./ruleset/AdditionalFilter.list"
    },
    AdditionalCDNResources: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list",
        path: "./ruleset/AdditionalCDNResources.list"
    },
    Crypto: {
        type: "http", behavior: "classical", format: "text", interval: 86400,
        url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list",
        path: "./ruleset/Crypto.list"
    }
};

// ================= 4. 规则配置 (融合版) =================
function buildRules() {
    const rules = [];

    // QUIC 控制 (参数可配)
    if (!quicEnabled) {
        rules.push("AND,((DST-PORT,443),(NETWORK,UDP)),REJECT");
    }

    rules.push(
        // 广告拦截
        `RULE-SET,ADBlock,${PROXY_GROUPS.ADBLOCK}`,
        `RULE-SET,AdditionalFilter,${PROXY_GROUPS.ADBLOCK}`,
        `RULE-SET,SogouInput,${PROXY_GROUPS.DIRECT}`,

        // 静态资源 & CDN
        `RULE-SET,StaticResources,${PROXY_GROUPS.SELECT}`,
        `RULE-SET,CDNResources,${PROXY_GROUPS.SELECT}`,
        `RULE-SET,AdditionalCDNResources,${PROXY_GROUPS.SELECT}`,

        // 特殊服务
        `RULE-SET,Crypto,${PROXY_GROUPS.SELECT}`,
        `RULE-SET,EHentai,${PROXY_GROUPS.SELECT}`,
        `RULE-SET,TikTok,${PROXY_GROUPS.TIKTOK}`,
        `RULE-SET,SteamFix,${PROXY_GROUPS.DIRECT}`,
        `RULE-SET,GoogleFCM,${PROXY_GROUPS.DIRECT}`,

        // Google 服务
        `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`,
        `GEOSITE,GOOGLE-PLAY@CN,${PROXY_GROUPS.DIRECT}`,
        `GEOSITE,YOUTUBE,${PROXY_GROUPS.SELECT}`,
        `GEOSITE,GOOGLE,${PROXY_GROUPS.SELECT}`,

        // AI 服务
        `GEOSITE,CATEGORY-AI-!CN,${PROXY_GROUPS.SELECT}`,

        // Microsoft
        `GEOSITE,MICROSOFT@CN,${PROXY_GROUPS.DIRECT}`,
        `GEOSITE,ONEDRIVE,${PROXY_GROUPS.SELECT}`,
        `GEOSITE,MICROSOFT,${PROXY_GROUPS.SELECT}`,

        // 通讯 & 社交
        `GEOSITE,TELEGRAM,${PROXY_GROUPS.TELEGRAM}`,

        // 流媒体
        `GEOSITE,NETFLIX,${PROXY_GROUPS.NETFLIX}`,
        `GEOSITE,SPOTIFY,${PROXY_GROUPS.SELECT}`,
        `GEOSITE,BAHAMUT,${PROXY_GROUPS.SELECT}`,
        `GEOSITE,BILIBILI,${PROXY_GROUPS.DIRECT}`,
        `GEOSITE,PIKPAK,${PROXY_GROUPS.SELECT}`,

        // 国内 AI 直连
        `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
        `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
        `DOMAIN-SUFFIX,deepseek.com,${PROXY_GROUPS.DIRECT}`,
        `DOMAIN-SUFFIX,kimi.ai,${PROXY_GROUPS.DIRECT}`,
        `DOMAIN-SUFFIX,moonshot.cn,${PROXY_GROUPS.DIRECT}`,
        `DOMAIN-SUFFIX,chatglm.cn,${PROXY_GROUPS.DIRECT}`,

        // GFW & 国内
        `GEOSITE,GFW,${PROXY_GROUPS.SELECT}`,
        `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
        `GEOSITE,PRIVATE,${PROXY_GROUPS.DIRECT}`,

        // GeoIP 规则
        `GEOIP,NETFLIX,${PROXY_GROUPS.NETFLIX},no-resolve`,
        `GEOIP,TELEGRAM,${PROXY_GROUPS.TELEGRAM},no-resolve`,
        `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
        `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,

        // 兜底
        `MATCH,${PROXY_GROUPS.MATCH}`
    );

    return rules;
}

// ================= 5. Sniffer 嗅探 (来自 powerfullz) =================
const snifferConfig = {
    sniff: {
        TLS: { ports: [443, 8443] },
        HTTP: { ports: [80, 8080, 8880] },
        QUIC: { ports: [443, 8443] }
    },
    "override-destination": false,
    enable: true,
    "force-dns-mapping": true,
    "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.push.apple.com"]
};

// ================= 6. DNS 配置 (来自 powerfullz, 支持双模式) =================
function buildDnsConfig() {
    const mode = fakeIPEnabled ? "fake-ip" : "redir-host";
    const config = {
        "enable": true,
        "ipv6": ipv6Enabled,
        "prefer-h3": true,
        "enhanced-mode": mode,
        "default-nameserver": ["119.29.29.29", "223.5.5.5"],
        "nameserver": ["system", "223.5.5.5", "119.29.29.29", "180.184.1.1"],
        "fallback": [
            "quic://dns0.eu",
            "https://dns.cloudflare.com/dns-query",
            "https://dns.sb/dns-query",
            "tcp://208.67.222.222",
            "tcp://8.26.56.2"
        ],
        "proxy-server-nameserver": ["https://dns.alidns.com/dns-query", "tls://dot.pub"],
        "fallback-filter": {
            "geoip": true, "geoip-code": "CN",
            "ip-cidr": ["240.0.0.0/4", "0.0.0.0/32"],
            "domain": ["+.google.com", "+.facebook.com", "+.youtube.com"]
        }
    };

    if (fakeIPEnabled) {
        config["fake-ip-range"] = "198.18.0.1/16";
        config["fake-ip-filter"] = [
            "geosite:private",
            "geosite:connectivity-check",
            "geosite:cn",
            "Mijia Cloud",
            "dig.io.mi.com",
            "localhost.ptlogin2.qq.com",
            "*.icloud.com",
            "*.stun.*.*",
            "*.stun.*.*.*"
        ];
    }

    return config;
}

// ================= 7. GeoData URL (来自 powerfullz) =================
const geoxURL = {
    geoip: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
    geosite: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
    mmdb: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",
    asn: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb"
};

// ================= 8. 策略组生成 =================
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

    // 01. 节点选择
    const mainProxies = landing
        ? [PROXY_GROUPS.MANUAL, ...regionGroups, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, "DIRECT"]
        : [PROXY_GROUPS.MANUAL, ...regionGroups, "DIRECT"];
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
    const manualOptions = [...regionGroups, ...(frontProxies.length ? frontProxies : ["DIRECT"])];
    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: manualOptions });

    // 含落地节点的完整列表
    const allOptionsWithLanding = [...regionGroups, ...proxyNames];

    // 09. 电报消息
    groups.push({ name: PROXY_GROUPS.TELEGRAM, type: "select", proxies: allOptionsWithLanding });

    // 12. 奈飞视频
    groups.push({ name: PROXY_GROUPS.NETFLIX, type: "select", proxies: allOptionsWithLanding });

    // 13. TikTok
    groups.push({ name: PROXY_GROUPS.TIKTOK, type: "select", proxies: allOptionsWithLanding });

    // 10. 漏网之鱼 & 11. 全球直连
    groups.push({ name: PROXY_GROUPS.MATCH, type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });
    groups.push({ name: PROXY_GROUPS.DIRECT, type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });

    // 14. 广告拦截
    groups.push({ name: PROXY_GROUPS.ADBLOCK, type: "select", proxies: ["REJECT", "REJECT-DROP", "DIRECT"] });

    return groups;
}

// ================= 9. 主程序 =================
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

        // 自动多端口监听
        const autoListeners = [];
        let startPort = 8000;
        finalProxies.forEach(proxy => {
            autoListeners.push({
                name: `mixed-${startPort}`, type: "mixed", address: "0.0.0.0", port: startPort, proxy: proxy.name
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
            "keep-alive-idle": 15,
            "keep-alive-interval": 15,
            "global-client-fingerprint": "chrome",
            "geodata-mode": true,
            "geox-url": geoxURL,
            "profile": {
                "store-selected": true,
                "store-fake-ip": true
            },
            "listeners": autoListeners,
            "proxy-groups": u,
            "rule-providers": ruleProviders,
            rules: buildRules(),
            sniffer: snifferConfig,
            dns: buildDnsConfig()
        };
    } catch (error) {
        console.log("Script Error: " + error);
        return e;
    }
}
