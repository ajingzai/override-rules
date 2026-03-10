/*!
Substore 订阅转换脚本 - 融合版 v3
基于 powerfullz 原版规则集 + ajingzai 定制功能
特性: 在线规则集 + DNS双模式 + Sniffer嗅探 + GeoData + 自动多端口监听 + 链式代理 + 防断流

所有功能默认全开:
- landing: 链式代理 (默认 true)
- ipv6Enabled: IPv6 (默认 true)
- fakeip: FakeIP 模式 (默认 true)
- quic: QUIC 流量 (默认 true)
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = rawArgs.landing !== undefined ? parseBool(rawArgs.landing) : true;
const ipv6Enabled = rawArgs.ipv6Enabled !== undefined ? parseBool(rawArgs.ipv6Enabled) : true;
const fakeIPEnabled = rawArgs.fakeip !== undefined ? parseBool(rawArgs.fakeip) : true;
const quicEnabled = rawArgs.quic !== undefined ? parseBool(rawArgs.quic) : true;

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT:   "节点选择",
    FRONT:    "前置代理",
    LANDING:  "落地节点",
    HK:       "香港节点",
    JP:       "日本节点",
    US:       "美国节点",
    TW:       "台湾节点",
    MANUAL:   "手动切换",
    TELEGRAM: "电报消息",
    MATCH:    "漏网之鱼",
    DIRECT:   "全球直连",
    NETFLIX:  "奈飞视频",
    TIKTOK:   "TikTok",
    ADBLOCK:  "广告拦截",
    GLOBAL:   "GLOBAL"
};

function unique(items) {
    return [...new Set(items)];
}

function createGroupIcon(label, background, foreground = "#ffffff") {
    const safeLabel = String(label)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="${background}"/><text x="50%" y="53%" text-anchor="middle" dominant-baseline="middle" font-family="Segoe UI, Arial, sans-serif" font-size="24" font-weight="700" fill="${foreground}">${safeLabel}</text></svg>`;
    return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

const GROUP_ICONS = {
    SELECT: "https://api.iconify.design/material-symbols/hub-rounded.svg?color=%232563eb",
    FRONT: "https://api.iconify.design/material-symbols/route-rounded.svg?color=%237c3aed",
    LANDING: "https://api.iconify.design/material-symbols/flight-land-rounded.svg?color=%23ea580c",
    HK: "https://api.iconify.design/circle-flags/hk.svg",
    JP: "https://api.iconify.design/circle-flags/jp.svg",
    US: "https://api.iconify.design/circle-flags/us.svg",
    TW: "https://api.iconify.design/circle-flags/tw.svg",
    MANUAL: "https://api.iconify.design/material-symbols/tune-rounded.svg?color=%234f46e5",
    TELEGRAM: "https://api.iconify.design/logos/telegram.svg",
    TIKTOK: "https://api.iconify.design/logos/tiktok-icon.svg",
    NETFLIX: "https://api.iconify.design/logos/netflix-icon.svg",
    MATCH: "https://api.iconify.design/material-symbols/travel-explore-rounded.svg?color=%23475569",
    DIRECT: "https://api.iconify.design/material-symbols/language-rounded.svg?color=%2316a34a",
    ADBLOCK: "https://api.iconify.design/material-symbols/block-rounded.svg?color=%23334155",
    GLOBAL: "https://api.iconify.design/material-symbols/public-rounded.svg?color=%230f766e"
};

function createGroup(name, proxies, iconKey) {
    return { name, type: "select", proxies, icon: GROUP_ICONS[iconKey] };
}

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
    groups.push(createGroup(PROXY_GROUPS.SELECT, mainProxies, "SELECT"));

    if (landing) {
        groups.push(createGroup(PROXY_GROUPS.FRONT, regionGroups.length ? regionGroups : ["DIRECT"], "FRONT"));
        groups.push(createGroup(PROXY_GROUPS.LANDING, landingProxies.length ? landingProxies : ["DIRECT"], "LANDING"));
    }

    // 04-07 地区分组
    groups.push(createGroup(PROXY_GROUPS.HK, hkProxies.length ? hkProxies : ["DIRECT"], "HK"));
    groups.push(createGroup(PROXY_GROUPS.JP, jpProxies.length ? jpProxies : ["DIRECT"], "JP"));
    groups.push(createGroup(PROXY_GROUPS.US, usProxies.length ? usProxies : ["DIRECT"], "US"));
    groups.push(createGroup(PROXY_GROUPS.TW, twProxies.length ? twProxies : ["DIRECT"], "TW"));

    // 08. 手动切换
    const manualOptions = unique([...regionGroups, ...(frontProxies.length ? frontProxies : ["DIRECT"])]);
    groups.push(createGroup(PROXY_GROUPS.MANUAL, manualOptions, "MANUAL"));

    // 含落地节点的完整列表
    const allOptionsWithLanding = unique([...regionGroups, ...proxyNames]);

    // 功能分组，按 Clash Verge 更顺眼的展示顺序输出
    groups.push(createGroup(PROXY_GROUPS.TELEGRAM, allOptionsWithLanding, "TELEGRAM"));
    groups.push(createGroup(PROXY_GROUPS.TIKTOK, allOptionsWithLanding, "TIKTOK"));
    groups.push(createGroup(PROXY_GROUPS.NETFLIX, allOptionsWithLanding, "NETFLIX"));
    groups.push(createGroup(PROXY_GROUPS.MATCH, [PROXY_GROUPS.SELECT, "DIRECT"], "MATCH"));
    groups.push(createGroup(PROXY_GROUPS.DIRECT, ["DIRECT", PROXY_GROUPS.SELECT], "DIRECT"));
    groups.push(createGroup(PROXY_GROUPS.ADBLOCK, ["REJECT", "REJECT-DROP", "DIRECT"], "ADBLOCK"));

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
        u.push(createGroup(PROXY_GROUPS.GLOBAL, allProxyNames, "GLOBAL"));

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
