/*!
powerfullz 的 Substore 订阅转换脚本 (在线规则托管版)
https://github.com/powerfullz/override-rules

配置变更：
1. [自动更新] 引入 blackmatrix7 的在线规则集 (China/Proxy/TikTok)，每天自动更新，无需手动维护。
2. [Grok加速] 手动置顶 Grok/xAI/Twitter 规则，确保其绝对走代理，解决加载慢/打不开。
3. [DNS策略] 保持“去毒+分流”策略，国内域名走阿里DNS，国外域名走 1.1.1.1。
4. [功能保留] 链式代理、端口映射、重命名全部保留。
*/

// ================= 1. 基础工具 =================
const NODE_SUFFIX = "节点";
function parseBool(val) {
    if (typeof val === "boolean") return val;
    if (typeof val === "string") return val.toLowerCase() === "true" || val === "1";
    return false;
}
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing);
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 组名定义 =================
const PROXY_GROUPS = { SELECT: "选择代理", FRONT: "前置代理", LANDING: "落地节点", MANUAL: "手动选择", DIRECT: "直连" };

// ================= 3. 在线规则集 (Rule Providers) =================
// 这里配置了自动更新的订阅源，每天(86400秒)更新一次
const ruleProviders = {
    // 🇨🇳 国内域名列表 (包含数万个国内网站)
    China: {
        type: "http", behavior: "domain", format: "yaml", interval: 86400,
        url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/China/China.yaml",
        path: "./ruleset/China.yaml"
    },
    // 🌍 国外/代理域名列表 (包含 Google/Github/Netflix 等)
    Proxy: {
        type: "http", behavior: "domain", format: "yaml", interval: 86400,
        url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Proxy/Proxy.yaml",
        path: "./ruleset/Proxy.yaml"
    },
    // 🎵 TikTok 专属列表
    TikTok: {
        type: "http", behavior: "domain", format: "yaml", interval: 86400,
        url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml",
        path: "./ruleset/TikTok.yaml"
    },
    // 📺 YouTube
    YouTube: {
        type: "http", behavior: "domain", format: "yaml", interval: 86400,
        url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml",
        path: "./ruleset/YouTube.yaml"
    },
    // 🤖 OpenAI / ChatGPT
    OpenAI: {
        type: "http", behavior: "domain", format: "yaml", interval: 86400,
        url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml",
        path: "./ruleset/OpenAI.yaml"
    },
    // 🛑 广告拦截
    ADBlock: { 
        type: "http", behavior: "domain", format: "mrs", interval: 86400, 
        url: "https://adrules.top/adrules-mihomo.mrs", 
        path: "./ruleset/ADBlock.mrs" 
    }
};

// ================= 4. 规则配置 (Grok置顶 + 在线列表) =================
const baseRules = [
    // 1. 阻断 QUIC
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
    
    // 2. DNS 防泄露
    `IP-CIDR,8.8.8.8/32,${PROXY_GROUPS.SELECT},no-resolve`,
    `IP-CIDR,1.1.1.1/32,${PROXY_GROUPS.SELECT},no-resolve`,
    `DOMAIN,dns.google,${PROXY_GROUPS.SELECT}`,

    // ================= ⚡ Grok / xAI / Twitter 极速置顶 =================
    // 这些是我们手动强加的，优先级最高，确保 Grok 秒开！
    `DOMAIN-SUFFIX,grok.com,${PROXY_GROUPS.SELECT}`,  // Grok 官网
    `DOMAIN-SUFFIX,x.ai,${PROXY_GROUPS.SELECT}`,      // xAI 官网
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`,
    
    // ================= 引用在线规则集 =================
    "RULE-SET,ADBlock,REJECT",
    
    // 优先匹配特定 APP
    `RULE-SET,TikTok,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,YouTube,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,OpenAI,${PROXY_GROUPS.SELECT}`,
    
    // 🇨🇳 国内列表 -> 直连
    `RULE-SET,China,${PROXY_GROUPS.DIRECT}`,
    
    // 🌍 国外列表 -> 代理
    `RULE-SET,Proxy,${PROXY_GROUPS.SELECT}`,
    
    // ================= 兜底规则 =================
    // 中国 IP 直连
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    // 剩下的全部走代理
    `MATCH,${PROXY_GROUPS.SELECT}`
];

// ================= 5. DNS 配置 (手动分流保平安) =================
// 依然保持手动列表，因为 nameserver-policy 不支持 rule-provider
// 这能确保你绝不会遇到 "GeoSite error" 报错
const CN_DNS_DOMAINS = [
    "+.cn", "+.baidu.com", "+.qq.com", "+.tencent.com", "+.aliyun.com", 
    "+.taobao.com", "+.tmall.com", "+.jd.com", "+.bilibili.com", 
    "+.163.com", "+.xiaomi.com", "+.huawei.com", "+.meituan.com",
    "+.douyin.com", "+.kuaishou.com", "+.zhihu.com", "+.weibo.com"
];

function buildDnsConfig() {
    const cnPolicy = {};
    cnPolicy[CN_DNS_DOMAINS.join(",")] = ["223.5.5.5", "119.29.29.29"];

    return {
        enable: true,
        ipv6: ipv6Enabled,
        "prefer-h3": true,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
        
        // 国外走 DoH
        nameserver: [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query"
        ],
        
        // 国内走 UDP
        "nameserver-policy": cnPolicy,
        
        fallback: [],
        "fallback-filter": { "geoip": true, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"] },

        "fake-ip-filter": [
            "+.cn",
            "+.baidu.com",
            "+.qq.com",
            "Mijia Cloud",
            "dig.io.mi.com",
            "localhost.ptlogin2.qq.com",
            "*.icloud.com",
            "*.stun.*.*"
        ]
    };
}

const snifferConfig = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, 8080, 8880] }, QUIC: { ports: [443, 8443] } },
    "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.push.apple.com"]
};

// ================= 6. 策略组生成 =================
function buildProxyGroups(params) {
    const isLanding = params.landing;
    const groups = [];

    const selectProxies = isLanding ? [PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"] : [];
    const selectGroup = {
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: selectProxies
    };
    if (!isLanding) selectGroup["include-all"] = true;
    groups.push(selectGroup);

    if (isLanding) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select", "include-all": true, "exclude-filter": " -> 前置"
        });
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select", "include-all": true, filter: " -> 前置"
        });
    }

    groups.push({name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", "include-all": true, type: "select"});
    groups.push({name: PROXY_GROUPS.DIRECT, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png", type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT]});
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
    if (/法国|FR|France/i.test(name)) return "FR";
    if (/俄罗斯|RU|Russia/i.test(name)) return "RU";
    if (/土耳其|TR|Turkey/i.test(name)) return "TR";
    if (/阿根廷|AR|Argentina/i.test(name)) return "AR";
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
        } 
        else {
            const code = getCountryCode(p.name);
            if (!countryCounts[code]) countryCounts[code] = 0;
            countryCounts[code]++;
            finalProxies.push({
                ...p,
                name: `${code}-${countryCounts[code].toString().padStart(2, '0')}`
            });
        }
    });

    const t = { proxies: finalProxies };

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
    u.push({name:"GLOBAL", icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png", "include-all":true, type:"select", proxies:d});

    const dnsConfig = buildDnsConfig();

    Object.assign(t, {
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
        dns: dnsConfig,
        "geodata-mode": true,
        "geox-url": {
            geoip: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
            geosite: "https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
            mmdb: "https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"
        }
    });

    return t;
}
