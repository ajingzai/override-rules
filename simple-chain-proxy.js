/*!
powerfullz 的 Substore 订阅转换脚本 (极简二分法修复版)
https://github.com/powerfullz/override-rules

配置变更：
1. [修复报错] 移除了直连组中的代理引用，彻底解决 "loop detected" 死循环。
2. [极简分组] 删除了所有 APP 细分分组，只保留【🌍 国外流量】和【🌏 国内流量】。
3. [规则映射] 将 ACL4SSR 的几十个规则集智能归类到“国内”和“国外”两个组。
4. [秒开DNS] 保持腾讯/阿里 DoH + Fake-IP 配置。
*/

// ================= 1. 基础工具 =================
const NODE_SUFFIX = "节点";
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT: "🚀 节点选择",   // 主开关
    FOREIGN: "🌍 国外流量",  // 所有的墙外规则都走这个
    DOMESTIC: "🌏 国内流量", // 所有的墙内规则都走这个
    FRONT: "⚡ 前置代理",    // 落地专用
    LANDING: "🛫 落地节点",  // 落地专用
    MANUAL: "🔄 手动切换",
    AUTO: "♻️ 自动选择",
    DIRECT: "🎯 全球直连",
    MATCH: "🐟 漏网之鱼"
};

// ================= 3. 规则集 (ACL4SSR) =================
const ruleProviders = {
    // 国内/直连类
    LocalAreaNetwork: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/LocalAreaNetwork.list", path: "./ruleset/LocalAreaNetwork.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    UnBan: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/UnBan.list", path: "./ruleset/UnBan.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    GoogleCN: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/GoogleCN.list", path: "./ruleset/GoogleCN.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    SteamCN: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/SteamCN.list", path: "./ruleset/SteamCN.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    ChinaMedia: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaMedia.list", path: "./ruleset/ChinaMedia.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    ChinaDomain: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaDomain.list", path: "./ruleset/ChinaDomain.list", behavior: "domain", interval: 86400, format: "text", type: "http" },
    ChinaCompanyIp: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaCompanyIp.list", path: "./ruleset/ChinaCompanyIp.list", behavior: "ipcidr", interval: 86400, format: "text", type: "http" },
    Download: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Download.list", path: "./ruleset/Download.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    
    // 广告类
    BanAD: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/BanAD.list", path: "./ruleset/BanAD.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    BanProgramAD: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/BanProgramAD.list", path: "./ruleset/BanProgramAD.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    
    // 国外/代理类 (全部归入国外流量)
    GoogleFCM: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/GoogleFCM.list", path: "./ruleset/GoogleFCM.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Bing: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Bing.list", path: "./ruleset/Bing.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    OneDrive: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/OneDrive.list", path: "./ruleset/OneDrive.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Microsoft: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Microsoft.list", path: "./ruleset/Microsoft.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Apple: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Apple.list", path: "./ruleset/Apple.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Telegram: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Telegram.list", path: "./ruleset/Telegram.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    OpenAi: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/OpenAi.list", path: "./ruleset/OpenAi.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    NetEaseMusic: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/NetEaseMusic.list", path: "./ruleset/NetEaseMusic.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Epic: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Epic.list", path: "./ruleset/Epic.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Origin: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Origin.list", path: "./ruleset/Origin.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Sony: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Sony.list", path: "./ruleset/Sony.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Steam: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Steam.list", path: "./ruleset/Steam.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Nintendo: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Nintendo.list", path: "./ruleset/Nintendo.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    YouTube: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/YouTube.list", path: "./ruleset/YouTube.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Netflix: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Netflix.list", path: "./ruleset/Netflix.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Bahamut: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Bahamut.list", path: "./ruleset/Bahamut.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    BilibiliHMT: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/BilibiliHMT.list", path: "./ruleset/BilibiliHMT.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    Bilibili: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Bilibili.list", path: "./ruleset/Bilibili.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    ProxyMedia: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ProxyMedia.list", path: "./ruleset/ProxyMedia.list", behavior: "classical", interval: 86400, format: "text", type: "http" },
    ProxyGFWlist: { url: "https://testingcf.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ProxyGFWlist.list", path: "./ruleset/ProxyGFWlist.list", behavior: "classical", interval: 86400, format: "text", type: "http" }
};

// ================= 4. 规则配置 (极简二分法) =================
const baseRules = [
    // 1. 强制直连 (国产 AI + 基础)
    "DOMAIN-SUFFIX,doubao.com," + PROXY_GROUPS.DOMESTIC,
    "DOMAIN-SUFFIX,volces.com," + PROXY_GROUPS.DOMESTIC,
    "RULE-SET,LocalAreaNetwork," + PROXY_GROUPS.DOMESTIC,
    "RULE-SET,UnBan," + PROXY_GROUPS.DOMESTIC,
    "RULE-SET,GoogleCN," + PROXY_GROUPS.DOMESTIC,
    "RULE-SET,SteamCN," + PROXY_GROUPS.DOMESTIC,
    "RULE-SET,ChinaDomain," + PROXY_GROUPS.DOMESTIC,
    "RULE-SET,ChinaCompanyIp," + PROXY_GROUPS.DOMESTIC,
    "RULE-SET,Download," + PROXY_GROUPS.DOMESTIC,
    "GEOIP,CN," + PROXY_GROUPS.DOMESTIC,

    // 2. 广告拦截
    "RULE-SET,BanAD,REJECT",
    "RULE-SET,BanProgramAD,REJECT",

    // 3. 强制代理 (特例 + 国外列表)
    // 所有的特殊应用全部指向 【🌍 国外流量】
    "DOMAIN-SUFFIX,grok.com," + PROXY_GROUPS.FOREIGN,
    "DOMAIN-SUFFIX,x.ai," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,GoogleFCM," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Bing," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,OneDrive," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Microsoft," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Apple," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Telegram," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,OpenAi," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,NetEaseMusic," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Epic," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Origin," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Sony," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Steam," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Nintendo," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,YouTube," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Netflix," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Bahamut," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,BilibiliHMT," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,Bilibili," + PROXY_GROUPS.DOMESTIC, // B站主站通常直连
    "RULE-SET,ChinaMedia," + PROXY_GROUPS.DOMESTIC,
    "RULE-SET,ProxyMedia," + PROXY_GROUPS.FOREIGN,
    "RULE-SET,ProxyGFWlist," + PROXY_GROUPS.FOREIGN,

    // 4. 兜底
    "MATCH," + PROXY_GROUPS.MATCH
];

// ================= 5. DNS 配置 (秒开不泄露) =================
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
        "fake-ip-filter": ["*.lan", "*.local", "time.*.com", "ntp.*.com", "+.market.xiaomi.com", "*.stun.*.*", "*.stun.*.*.*", "+.doubao.com", "+.volces.com"]
    };
}

const snifferConfig = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, 8080, 8880] }, QUIC: { ports: [443, 8443] } }
};

// ================= 6. 策略组生成 (极简版) =================
function buildProxyGroups(params) {
    const isLanding = params.landing;
    const groups = [];

    // 1. 核心选择器
    // 如果有落地，包含落地和前置；否则只包含自动、手动、直连
    const mainProxies = isLanding 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];

    groups.push({
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: mainProxies
    });

    // 2. 自动与手动
    groups.push({ name: PROXY_GROUPS.AUTO, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png", type: "url-test", interval: 300, tolerance: 50, "include-all": true });
    groups.push({ name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", type: "select", "include-all": true });

    // 3. 前置与落地 (按需开启)
    if (isLanding) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select",
            "include-all": true,
            "exclude-filter": " -> 前置"
        });
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select",
            "include-all": true,
            filter: " -> 前置"
        });
    }

    // 4. 【关键修复】直连组 (纯净版)
    // 以前这里包含了 SELECT 导致死循环，现在只放 DIRECT
    groups.push({
        name: PROXY_GROUPS.DIRECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
        type: "select",
        proxies: ["DIRECT"]
    });

    // 5. 极简二分法组
    // 🌍 国外流量 -> 走主选择器
    groups.push({
        name: PROXY_GROUPS.FOREIGN,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png",
        type: "select",
        proxies: [PROXY_GROUPS.SELECT, PROXY_GROUPS.AUTO]
    });

    // 🌏 国内流量 -> 走直连组
    groups.push({
        name: PROXY_GROUPS.DOMESTIC,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/China.png",
        type: "select",
        proxies: [PROXY_GROUPS.DIRECT] // 强制直连，不回环
    });

    // 6. 漏网之鱼
    groups.push({
        name: PROXY_GROUPS.MATCH,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Fish.png",
        type: "select",
        proxies: [PROXY_GROUPS.SELECT, "DIRECT"]
    });

    return groups;
}

// ================= 7. 主程序 =================
function main(e) {
    let rawProxies = e.proxies || [];
    let finalProxies = [];
    const excludeKeywords = /套餐|官网|剩余|时间|节点|重置|异常|邮箱|网址|Traffic|Expire|Reset/i;
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

    // 端口映射
    const autoListeners = [];
    let startPort = 8000;
    finalProxies.forEach(proxy => {
        autoListeners.push({ name: `mixed-${startPort}`, type: "mixed", address: "0.0.0.0", port: startPort, proxy: proxy.name });
        startPort++;
    });

    const u = buildProxyGroups({ landing: landing });
    const d = u.map(e => e.name);
    // GLOBAL 组是 Clash 必须的，用于 API 交互，但UI上不一定显示
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
