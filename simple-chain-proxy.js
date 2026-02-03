/*!
powerfullz 的 Substore 订阅转换脚本 (全能修复终极版)
https://github.com/powerfullz/override-rules

集大成功能：
1. [TikTok修复] 引入完整 TikTok 规则集，解决黑屏/加载不出。
2. [图片修复] 强制 Google/Youtube 所有静态资源走代理，解决 Gemini/YT 灰块。
3. [防泄露] 强制 DNS 流量代理解析，解决 "China Mobile" 泄露问题。
4. [链式代理] "落地" 节点自动走前置代理。
5. [重命名] 自动清洗并按国家重命名节点。
6. [端口映射] 自动生成 8000+ 端口。
*/

// ================= 1. 核心底层 =================
const NODE_SUFFIX="节点";function parseBool(e){return"boolean"==typeof e?e:"string"==typeof e&&("true"===e.toLowerCase()||"1"===e)}function parseNumber(e,t=0){if(null==e)return t;const o=parseInt(e,10);return isNaN(o)?t:o}function buildFeatureFlags(e){const t=Object.entries({loadbalance:"loadBalance",landing:"landing",ipv6:"ipv6Enabled",full:"fullConfig",keepalive:"keepAliveEnabled",fakeip:"fakeIPEnabled",quic:"quicEnabled"}).reduce((t,[o,r])=>(t[r]=parseBool(e[o])||!1,t),{});return t.countryThreshold=parseNumber(e.threshold,0),t}const rawArgs="undefined"!=typeof $arguments?$arguments:{},{loadBalance:loadBalance,landing:landing,ipv6Enabled:ipv6Enabled,fullConfig:fullConfig,keepAliveEnabled:keepAliveEnabled,fakeIPEnabled:fakeIPEnabled,quicEnabled:quicEnabled,countryThreshold:countryThreshold}=buildFeatureFlags(rawArgs);function stripNodeSuffix(e){const t=new RegExp("节点$");return e.map(e=>e.replace(t,""))}const buildList=(...e)=>e.flat().filter(Boolean);

// ================= 2. 组名定义 =================
const PROXY_GROUPS={SELECT:"选择代理",FRONT:"前置代理",LANDING:"落地节点",MANUAL:"手动选择",DIRECT:"直连"};

// ================= 3. 规则集 (增强版) =================
const ruleProviders={
    // 强制引入 TikTok 规则集
    TikTok:{type:"http",behavior:"domain",format:"mrs",interval:86400,url:"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml",path:"./ruleset/TikTok.yaml"},
    ADBlock:{type:"http",behavior:"domain",format:"mrs",interval:86400,url:"https://adrules.top/adrules-mihomo.mrs",path:"./ruleset/ADBlock.mrs"},
    SogouInput:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt",path:"./ruleset/SogouInput.txt"},
    StaticResources:{type:"http",behavior:"domain",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/domainset/cdn.txt",path:"./ruleset/StaticResources.txt"},
    CDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/cdn.txt",path:"./ruleset/CDNResources.txt"},
    Crypto:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list",path:"./ruleset/Crypto.list"}
};

// ================= 4. 规则配置 (优先级非常重要) =================
const baseRules=[
    // 1. 阻断 QUIC (UDP 443) - 解决所有 App 转圈/断流的根源
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT", 
    
    // 2. DNS 防泄露 - 强制 DNS 流量走代理
    `IP-CIDR,8.8.8.8/32,${PROXY_GROUPS.SELECT},no-resolve`,
    `IP-CIDR,1.1.1.1/32,${PROXY_GROUPS.SELECT},no-resolve`,
    `DOMAIN,dns.google,${PROXY_GROUPS.SELECT}`,
    `DOMAIN,cloudflare-dns.com,${PROXY_GROUPS.SELECT}`,

    // 3. TikTok 专属修复 (优先匹配)
    // 必须放在 GEOSITE 之前，防止漏网
    `RULE-SET,TikTok,${PROXY_GROUPS.SELECT}`, 
    `GEOSITE,TIKTOK,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokv.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,byteoversea.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ibytedtos.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ipstatp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,muscdn.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,musical.ly,${PROXY_GROUPS.SELECT}`,
    
    // 4. Google 全家桶 & 图片修复
    `GEOSITE,GOOGLE,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,GCM,${PROXY_GROUPS.SELECT}`, // 安卓推送服务
    `DOMAIN-SUFFIX,ggpht.com,${PROXY_GROUPS.SELECT}`, // 图片CDN核心
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.SELECT}`,
    
    // 5. AI 服务 (Gemini/Sora)
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,generativelanguage.googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,sora.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.SELECT}`,

    // 6. 其他常用
    `GEOSITE,GITHUB,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,NETFLIX,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,TELEGRAM,${PROXY_GROUPS.SELECT}`,
    
    // 基础规则
    "RULE-SET,ADBlock,REJECT",
    `RULE-SET,SogouInput,${PROXY_GROUPS.DIRECT}`, 
    `RULE-SET,StaticResources,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`, // 安卓手机特有
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.SELECT}`
];

// ================= 5. DNS 配置 (手机防泄露专用) =================
function buildDnsConfig({mode:e, fakeIpFilter:t}) {
    return {
        enable: true,
        ipv6: false, 
        "prefer-h3": false,
        "enhanced-mode": "fake-ip", 
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        // 国内 DNS 用于解析节点域名
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
        // 国外 DNS (DoH) 用于代理流量
        nameserver: ["https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query"],
        // 国内分流
        "nameserver-policy": {
            "geosite:cn,private,apple,huawei,xiaomi": ["223.5.5.5", "119.29.29.29"]
        },
        fallback: [],
        "fallback-filter": { "geoip": true, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"] },
        "fake-ip-filter": t
    };
}

const snifferConfig={sniff:{TLS:{ports:[443,8443]},HTTP:{ports:[80,8080,8880]},QUIC:{ports:[443,8443]}},"override-destination":!1,enable:!0,"force-dns-mapping":!0,"skip-domain":["Mijia Cloud","dlg.io.mi.com","+.push.apple.com"]};

// ================= 6. 策略组生成 =================
function buildProxyGroups(params){
    const { landing, defaultProxies: l } = params;
    const groups = [];

    const selectProxies = landing ? [PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"] : [];
    const selectGroup = {
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: selectProxies
    };
    if (!landing) selectGroup["include-all"] = true;
    groups.push(selectGroup);

    if (landing) {
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
    return "OT";
}

// ================= 7. 主程序 =================
function main(e){
    let rawProxies = e.proxies;
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

    const t = {proxies:e.proxies};
    t.proxies = finalProxies;

    const u = buildProxyGroups({ landing: landing, defaultProxies: finalProxies.map(p=>p.name) });
    const d = u.map(e => e.name);
    u.push({name:"GLOBAL",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png","include-all":!0,type:"select",proxies:d});

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

    const dnsFake = buildDnsConfig({
        mode: "fake-ip",
        fakeIpFilter: ["geosite:private", "geosite:cn", "Mijia Cloud", "*.stun.*.*"]
    });

    Object.assign(t,{
        "mixed-port":7890,
        "allow-lan": true,
        ipv6: false, 
        mode: "rule",
        "unified-delay": true,
        "tcp-concurrent": true,
        "global-client-fingerprint": "chrome",
        "listeners": autoListeners, 
        "proxy-groups":u,
        "rule-providers":ruleProviders,
        rules: baseRules,
        sniffer:snifferConfig,
        dns: dnsFake,
        "geodata-mode":true,
        "geox-url":{geoip:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",geosite:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",mmdb:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"}
    });
    return t;
}
