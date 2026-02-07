/*!
Modified Substore Script based on user request
Changes: Default landing=true, specific landing keyword filter, chain proxy injection, custom DNS, auto-listeners.
*/
const NODE_SUFFIX = "节点";

function parseBool(e, defaultVal = false) {
    if (e === undefined || e === null) return defaultVal;
    return "boolean" == typeof e ? e : "string" == typeof e && ("true" === e.toLowerCase() || "1" === e)
}

function parseNumber(e, t = 0) {
    if (null == e) return t;
    const o = parseInt(e, 10);
    return isNaN(o) ? t : o
}

function buildFeatureFlags(e) {
    // 1. 修改：landing 默认为 true
    const defaults = {
        loadbalance: false,
        landing: true, // 默认开启
        ipv6: false,
        full: false,
        keepalive: false,
        fakeip: false,
        quic: false
    };
    
    const t = {};
    t.loadBalance = parseBool(e.loadbalance, defaults.loadbalance);
    t.landing = parseBool(e.landing, defaults.landing);
    t.ipv6Enabled = parseBool(e.ipv6, defaults.ipv6);
    t.fullConfig = parseBool(e.full, defaults.full);
    t.keepAliveEnabled = parseBool(e.keepalive, defaults.keepalive);
    t.fakeIPEnabled = parseBool(e.fakeip, defaults.fakeip);
    t.quicEnabled = parseBool(e.quic, defaults.quic);
    t.countryThreshold = parseNumber(e.threshold, 0);
    return t;
}

const rawArgs = "undefined" != typeof $arguments ? $arguments : {};
const {
    loadBalance,
    landing,
    ipv6Enabled,
    fullConfig,
    keepAliveEnabled,
    fakeIPEnabled,
    quicEnabled,
    countryThreshold
} = buildFeatureFlags(rawArgs);

// 2. 修改：严格限制落地关键字为“落地”
const LANDING_KEYWORD_REGEX = /落地/; 

function getCountryGroupNames(e, t) {
    return e.filter(e => e.count >= t).map(e => e.country + "节点")
}

function stripNodeSuffix(e) {
    const t = new RegExp("节点$");
    return e.map(e => e.replace(t, ""))
}

const PROXY_GROUPS = {
    SELECT: "选择代理",
    MANUAL: "手动选择",
    FALLBACK: "故障转移",
    DIRECT: "直连",
    LANDING: "落地节点",
    LOW_COST: "低倍率节点"
};
const buildList = (...e) => e.flat().filter(Boolean);

function buildBaseLists({
    landing: e,
    lowCost: t,
    countryGroupNames: o
}) {
    const r = buildList(PROXY_GROUPS.FALLBACK, e && PROXY_GROUPS.LANDING, o, t && PROXY_GROUPS.LOW_COST, PROXY_GROUPS.MANUAL, "DIRECT");
    return {
        defaultProxies: buildList(PROXY_GROUPS.SELECT, o, t && PROXY_GROUPS.LOW_COST, PROXY_GROUPS.MANUAL, PROXY_GROUPS.DIRECT),
        defaultProxiesDirect: buildList(PROXY_GROUPS.DIRECT, o, t && PROXY_GROUPS.LOW_COST, PROXY_GROUPS.SELECT, PROXY_GROUPS.MANUAL),
        defaultSelector: r,
        defaultFallback: buildList(e && PROXY_GROUPS.LANDING, o, t && PROXY_GROUPS.LOW_COST, PROXY_GROUPS.MANUAL, "DIRECT")
    }
}
const ruleProviders = {
    ADBlock: { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://adrules.top/adrules-mihomo.mrs", path: "./ruleset/ADBlock.mrs" },
    SogouInput: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt", path: "./ruleset/SogouInput.txt" },
    StaticResources: { type: "http", behavior: "domain", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/domainset/cdn.txt", path: "./ruleset/StaticResources.txt" },
    CDNResources: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://ruleset.skk.moe/Clash/non_ip/cdn.txt", path: "./ruleset/CDNResources.txt" },
    TikTok: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list", path: "./ruleset/TikTok.list" },
    EHentai: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list", path: "./ruleset/EHentai.list" },
    SteamFix: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list", path: "./ruleset/SteamFix.list" },
    GoogleFCM: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list", path: "./ruleset/FirebaseCloudMessaging.list" },
    AdditionalFilter: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list", path: "./ruleset/AdditionalFilter.list" },
    AdditionalCDNResources: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list", path: "./ruleset/AdditionalCDNResources.list" },
    Crypto: { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list", path: "./ruleset/Crypto.list" }
};
const baseRules = ["RULE-SET,ADBlock,广告拦截", "RULE-SET,AdditionalFilter,广告拦截", "RULE-SET,SogouInput,搜狗输入法", "DOMAIN-SUFFIX,truthsocial.com,Truth Social", "RULE-SET,StaticResources,静态资源", "RULE-SET,CDNResources,静态资源", "RULE-SET,AdditionalCDNResources,静态资源", "RULE-SET,Crypto,Crypto", "RULE-SET,EHentai,E-Hentai", "RULE-SET,TikTok,TikTok", `RULE-SET,SteamFix,${PROXY_GROUPS.DIRECT}`, `RULE-SET,GoogleFCM,${PROXY_GROUPS.DIRECT}`, `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`, "GEOSITE,CATEGORY-AI-!CN,AI", `GEOSITE,GOOGLE-PLAY@CN,${PROXY_GROUPS.DIRECT}`, `GEOSITE,MICROSOFT@CN,${PROXY_GROUPS.DIRECT}`, "GEOSITE,ONEDRIVE,OneDrive", "GEOSITE,MICROSOFT,Microsoft", "GEOSITE,TELEGRAM,Telegram", "GEOSITE,YOUTUBE,YouTube", "GEOSITE,GOOGLE,Google", "GEOSITE,NETFLIX,Netflix", "GEOSITE,SPOTIFY,Spotify", "GEOSITE,BAHAMUT,Bahamut", "GEOSITE,BILIBILI,Bilibili", "GEOSITE,PIKPAK,PikPak", `GEOSITE,GFW,${PROXY_GROUPS.SELECT}`, `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`, `GEOSITE,PRIVATE,${PROXY_GROUPS.DIRECT}`, "GEOIP,NETFLIX,Netflix,no-resolve", "GEOIP,TELEGRAM,Telegram,no-resolve", `GEOIP,CN,${PROXY_GROUPS.DIRECT}`, `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`, "DST-PORT,22,SSH(22端口)", `MATCH,${PROXY_GROUPS.SELECT}`];

function buildRules({
    quicEnabled: e
}) {
    const t = [...baseRules];
    return e || t.unshift("AND,((DST-PORT,443),(NETWORK,UDP)),REJECT"), t
}
const snifferConfig = {
    sniff: {
        TLS: { ports: [443, 8443] },
        HTTP: { ports: [80, 8080, 8880] },
        QUIC: { ports: [443, 8443] }
    },
    "override-destination": !1,
    enable: !0,
    "force-dns-mapping": !0,
    "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.push.apple.com"]
};

// 3. 修改：完全重写 DNS 配置以匹配图片
function buildDnsConfig({
    mode: e,
    fakeIpFilter: t
}) {
    const o = {
        enable: true,
        ipv6: ipv6Enabled,
        "prefer-h3": true,
        "enhanced-mode": "fake-ip", // 强制 FakeIP
        "fake-ip-range": "198.18.0.1/16",
        "default-nameserver": ["tls://223.5.5.5"], // DNS服务器域名解析
        "proxy-server-nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"], // 代理服务器域名解析
        nameserver: ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"], // 默认解析服务器
        "fake-ip-filter": [ // 真实IP回应
            "*.lan",
            "+.local",
            "time.*.com",
            "ntp.*.com",
            "+.market.xiaomi.com"
        ],
        fallback: [], // 回退服务器置空
        "fallback-filter": { // 回退过滤设置
            geoip: true,
            "geoip-code": "CN",
            ipcidr: ["240.0.0.0/4", "0.0.0.0/32"],
            domain: ["+.google.com", "+.facebook.com", "+.youtube.com"]
        }
    };
    return o
}

const dnsConfigFakeIp = buildDnsConfig({ mode: "fake-ip" }); 
const dnsConfig = dnsConfigFakeIp; // 默认使用该配置

const geoxURL = {
    geoip: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
    geosite: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
    mmdb: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",
    asn: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb"
};
const countriesMeta = {
    "香港": { pattern: "香港|港|HK|hk|Hong Kong|HongKong|hongkong|🇭🇰", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hong_Kong.png" },
    "澳门": { pattern: "澳门|MO|Macau|🇲🇴", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Macao.png" },
    "台湾": { pattern: "台|新北|彰化|TW|Taiwan|🇹🇼", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Taiwan.png" },
    "新加坡": { pattern: "新加坡|坡|狮城|SG|Singapore|🇸🇬", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Singapore.png" },
    "日本": { pattern: "日本|川日|东京|大阪|泉日|埼玉|沪日|深日|JP|Japan|🇯🇵", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Japan.png" },
    "韩国": { pattern: "KR|Korea|KOR|首尔|韩|韓|🇰🇷", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Korea.png" },
    "美国": { pattern: "美国|美|US|United States|🇺🇸", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_States.png" },
    "加拿大": { pattern: "加拿大|Canada|CA|🇨🇦", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Canada.png" },
    "英国": { pattern: "英国|United Kingdom|UK|伦敦|London|🇬🇧", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_Kingdom.png" },
    "澳大利亚": { pattern: "澳洲|澳大利亚|AU|Australia|🇦🇺", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Australia.png" },
    "德国": { pattern: "德国|德|DE|Germany|🇩🇪", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Germany.png" },
    "法国": { pattern: "法国|法|FR|France|🇫🇷", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/France.png" },
    "俄罗斯": { pattern: "俄罗斯|俄|RU|Russia|🇷🇺", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Russia.png" },
    "泰国": { pattern: "泰国|泰|TH|Thailand|🇹🇭", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Thailand.png" },
    "印度": { pattern: "印度|IN|India|🇮🇳", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/India.png" },
    "马来西亚": { pattern: "马来西亚|马来|MY|Malaysia|🇲🇾", icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Malaysia.png" }
};

function hasLowCost(e) {
    const t = /0\.[0-5]|低倍率|省流|大流量|实验性/i;
    return (e.proxies || []).some(e => t.test(e.name))
}

function parseCountries(e) {
    const t = e.proxies || [],
        // 此处只做统计，不影响 Landing 逻辑
        o = LANDING_KEYWORD_REGEX, 
        r = Object.create(null),
        n = {};
    for (const [e, t] of Object.entries(countriesMeta)) n[e] = new RegExp(t.pattern.replace(/^\(\?i\)/, ""));
    for (const e of t) {
        const t = e.name || "";
        if (!o.test(t))
            for (const [e, o] of Object.entries(n))
                if (o.test(t)) {
                    r[e] = (r[e] || 0) + 1;
                    break
                }
    }
    const s = [];
    for (const [e, t] of Object.entries(r)) s.push({
        country: e,
        count: t
    });
    return s
}

function buildCountryProxyGroups({
    countries: e,
    landing: t,
    loadBalance: o
}) {
    const r = [],
        n = "0\\.[0-5]|低倍率|省流|大流量|实验性",
        s = o ? "load-balance" : "url-test";
    
    // Landing 排除逻辑
    const excludeFilter = t ? `(?i)${LANDING_KEYWORD_REGEX.source}|${n}` : n;

    for (const l of e) {
        const e = countriesMeta[l];
        if (!e) continue;
        const i = {
            name: `${l}节点`,
            icon: e.icon,
            "include-all": !0,
            filter: e.pattern,
            "exclude-filter": excludeFilter,
            type: s
        };
        o || Object.assign(i, {
            url: "https://cp.cloudflare.com/generate_204",
            interval: 60,
            tolerance: 20,
            lazy: !1
        }), r.push(i)
    }
    return r
}

function buildProxyGroups({
    landing: e,
    countries: t,
    countryProxyGroups: o,
    lowCost: r,
    defaultProxies: n,
    defaultProxiesDirect: s,
    defaultSelector: l,
    defaultFallback: i
}) {
    const a = t.includes("台湾"),
        c = t.includes("香港"),
        p = t.includes("美国"),
        // 前置代理组：排除落地节点
        u = e ? l.filter(e => e !== PROXY_GROUPS.LANDING && e !== PROXY_GROUPS.FALLBACK) : [];
        
    return [{
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: l
    }, {
        name: PROXY_GROUPS.MANUAL,
        icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png",
        "include-all": !0,
        type: "select"
    }, 
    // 前置代理策略组
    e ? {
        name: "前置代理",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
        type: "select",
        "include-all": !0,
        "exclude-filter": "(?i)落地", // 排除自己，避免循环
        proxies: u
    } : null, 
    // 落地节点策略组
    e ? {
        name: PROXY_GROUPS.LANDING,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
        type: "select",
        "include-all": !0,
        filter: "(?i)落地" // 严格筛选“落地”
    } : null, {
        name: PROXY_GROUPS.FALLBACK,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bypass.png",
        type: "fallback",
        url: "https://cp.cloudflare.com/generate_204",
        proxies: i,
        interval: 180,
        tolerance: 20,
        lazy: !1
    }, {
        name: "静态资源",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Cloudflare.png",
        type: "select",
        proxies: n
    }, {
        name: "AI",
        icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/chatgpt.png",
        type: "select",
        proxies: n
    }, {
        name: "Crypto",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Cryptocurrency_3.png",
        type: "select",
        proxies: n
    }, {
        name: "Google",
        icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Google.png",
        type: "select",
        proxies: n
    }, {
        name: "Microsoft",
        icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Microsoft_Copilot.png",
        type: "select",
        proxies: n
    }, {
        name: "YouTube",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png",
        type: "select",
        proxies: n
    }, {
        name: "Bilibili",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/bilibili.png",
        type: "select",
        proxies: a && c ? [PROXY_GROUPS.DIRECT, "台湾节点", "香港节点"] : s
    }, {
        name: "Bahamut",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bahamut.png",
        type: "select",
        proxies: a ? ["台湾节点", PROXY_GROUPS.SELECT, PROXY_GROUPS.MANUAL, PROXY_GROUPS.DIRECT] : n
    }, {
        name: "Netflix",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png",
        type: "select",
        proxies: n
    }, {
        name: "TikTok",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/TikTok.png",
        type: "select",
        proxies: n
    }, {
        name: "Spotify",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Spotify.png",
        type: "select",
        proxies: n
    }, {
        name: "E-Hentai",
        icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Ehentai.png",
        type: "select",
        proxies: n
    }, {
        name: "Telegram",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png",
        type: "select",
        proxies: n
    }, {
        name: "Truth Social",
        icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/TruthSocial.png",
        type: "select",
        proxies: p ? ["美国节点", PROXY_GROUPS.SELECT, PROXY_GROUPS.MANUAL] : n
    }, {
        name: "OneDrive",
        icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Onedrive.png",
        type: "select",
        proxies: n
    }, {
        name: "PikPak",
        icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/PikPak.png",
        type: "select",
        proxies: n
    }, {
        name: "SSH(22端口)",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Server.png",
        type: "select",
        proxies: n
    }, {
        name: "搜狗输入法",
        icon: "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Sougou.png",
        type: "select",
        proxies: [PROXY_GROUPS.DIRECT, "REJECT"]
    }, {
        name: PROXY_GROUPS.DIRECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
        type: "select",
        proxies: ["DIRECT", PROXY_GROUPS.SELECT]
    }, {
        name: "广告拦截",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/AdBlack.png",
        type: "select",
        proxies: ["REJECT", "REJECT-DROP", PROXY_GROUPS.DIRECT]
    }, r ? {
        name: PROXY_GROUPS.LOW_COST,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Lab.png",
        type: "url-test",
        url: "https://cp.cloudflare.com/generate_204",
        "include-all": !0,
        filter: "(?i)0.[0-5]|低倍率|省流|大流量|实验性"
    } : null, ...o].filter(Boolean)
}

function main(e) {
    const t = {
        proxies: e.proxies
    };

    // 2. 修改：预处理节点，给"落地"节点添加前置代理
    if (landing) {
        t.proxies.forEach(p => {
            if (LANDING_KEYWORD_REGEX.test(p.name)) {
                p['dialer-proxy'] = "前置代理";
            }
        });
    }

    // 4. 修改：为所有节点生成 listeners，起始端口 8000
    const listeners = t.proxies.map((p, idx) => ({
        name: `mixed-${8000 + idx}`,
        type: "mixed",
        address: "0.0.0.0",
        port: 8000 + idx,
        proxy: p.name
    }));

    const o = parseCountries(t),
        r = hasLowCost(t),
        n = getCountryGroupNames(o, countryThreshold),
        s = stripNodeSuffix(n),
        {
            defaultProxies: l,
            defaultProxiesDirect: i,
            defaultSelector: a,
            defaultFallback: c
        } = buildBaseLists({
            landing: landing,
            lowCost: r,
            countryGroupNames: n
        }),
        p = buildCountryProxyGroups({
            countries: s,
            landing: landing,
            loadBalance: loadBalance
        }),
        u = buildProxyGroups({
            landing: landing,
            countries: s,
            countryProxyGroups: p,
            lowCost: r,
            defaultProxies: l,
            defaultProxiesDirect: i,
            defaultSelector: a,
            defaultFallback: c
        }),
        d = u.map(e => e.name);
    u.push({
        name: "GLOBAL",
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png",
        "include-all": !0,
        type: "select",
        proxies: d
    });
    const g = buildRules({
        quicEnabled: quicEnabled
    });
    return fullConfig && Object.assign(t, {
        "mixed-port": 7890,
        "redir-port": 7892,
        "tproxy-port": 7893,
        "routing-mark": 7894,
        "allow-lan": !0,
        ipv6: ipv6Enabled,
        mode: "rule",
        "unified-delay": !0,
        "tcp-concurrent": !0,
        "find-process-mode": "off",
        "log-level": "info",
        "geodata-loader": "standard",
        "external-controller": ":9999",
        "disable-keep-alive": !keepAliveEnabled,
        profile: {
            "store-selected": !0
        }
    }), Object.assign(t, {
        "proxy-groups": u,
        "rule-providers": ruleProviders,
        rules: g,
        sniffer: snifferConfig,
        dns: dnsConfig, // 使用新的 DNS
        "geodata-mode": !0,
        "geox-url": geoxURL,
        listeners: listeners // 添加 listeners
    }), t
}
