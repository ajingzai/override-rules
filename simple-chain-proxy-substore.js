/*!
powerfullz 的 Substore 订阅转换脚本 (修复报错版)
https://github.com/powerfullz/override-rules

修改内容：
1. 完整保留原版底层逻辑，修复报错。
2. 强行移除了：所有国家分组、故障转移、静态资源、广告拦截、低倍率节点。
3. 只保留：选择代理、手动选择、直连。
4. 广告规则 -> REJECT，其他规则 -> 统一并入主代理或直连。
*/

// ================= 核心逻辑保留区 (防止报错) =================
const NODE_SUFFIX="节点";function parseBool(e){return"boolean"==typeof e?e:"string"==typeof e&&("true"===e.toLowerCase()||"1"===e)}function parseNumber(e,t=0){if(null==e)return t;const o=parseInt(e,10);return isNaN(o)?t:o}function buildFeatureFlags(e){const t=Object.entries({loadbalance:"loadBalance",landing:"landing",ipv6:"ipv6Enabled",full:"fullConfig",keepalive:"keepAliveEnabled",fakeip:"fakeIPEnabled",quic:"quicEnabled"}).reduce((t,[o,r])=>(t[r]=parseBool(e[o])||!1,t),{});return t.countryThreshold=parseNumber(e.threshold,0),t}const rawArgs="undefined"!=typeof $arguments?$arguments:{},{loadBalance:loadBalance,landing:landing,ipv6Enabled:ipv6Enabled,fullConfig:fullConfig,keepAliveEnabled:keepAliveEnabled,fakeIPEnabled:fakeIPEnabled,quicEnabled:quicEnabled,countryThreshold:countryThreshold}=buildFeatureFlags(rawArgs);function getCountryGroupNames(e,t){return e.filter(e=>e.count>=t).map(e=>e.country+"节点")}function stripNodeSuffix(e){const t=new RegExp("节点$");return e.map(e=>e.replace(t,""))}
// ==========================================================

// 定义我们想要保留的核心组名
const PROXY_GROUPS={SELECT:"选择代理",MANUAL:"手动选择",DIRECT:"直连"};

// 规则源地址 (保持不变)
const ruleProviders={ADBlock:{type:"http",behavior:"domain",format:"mrs",interval:86400,url:"https://adrules.top/adrules-mihomo.mrs",path:"./ruleset/ADBlock.mrs"},SogouInput:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt",path:"./ruleset/SogouInput.txt"},StaticResources:{type:"http",behavior:"domain",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/domainset/cdn.txt",path:"./ruleset/StaticResources.txt"},CDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/cdn.txt",path:"./ruleset/CDNResources.txt"},TikTok:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list",path:"./ruleset/TikTok.list"},EHentai:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list",path:"./ruleset/EHentai.list"},SteamFix:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list",path:"./ruleset/SteamFix.list"},GoogleFCM:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list",path:"./ruleset/FirebaseCloudMessaging.list"},AdditionalFilter:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list",path:"./ruleset/AdditionalFilter.list"},AdditionalCDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list",path:"./ruleset/AdditionalCDNResources.list"},Crypto:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list",path:"./ruleset/Crypto.list"}};

// 修改后的规则列表：将原本指向“广告”、“静态”的规则，重定向到 REJECT 或 DIRECT
const baseRules=[
    "RULE-SET,ADBlock,REJECT",                 // 广告拦截 -> 直接拒绝
    "RULE-SET,AdditionalFilter,REJECT",        // 额外过滤 -> 直接拒绝
    `RULE-SET,SogouInput,${PROXY_GROUPS.DIRECT}`, // 搜狗输入 -> 直连
    `DOMAIN-SUFFIX,truthsocial.com,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,StaticResources,${PROXY_GROUPS.DIRECT}`, // 静态资源 -> 直连
    `RULE-SET,CDNResources,${PROXY_GROUPS.DIRECT}`,    // CDN -> 直连
    `RULE-SET,AdditionalCDNResources,${PROXY_GROUPS.DIRECT}`,
    `RULE-SET,Crypto,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,EHentai,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,TikTok,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,SteamFix,${PROXY_GROUPS.DIRECT}`,
    `RULE-SET,GoogleFCM,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,CATEGORY-AI-!CN,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,GOOGLE-PLAY@CN,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,MICROSOFT@CN,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,ONEDRIVE,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,MICROSOFT,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,TELEGRAM,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,YOUTUBE,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,GOOGLE,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,NETFLIX,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,SPOTIFY,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,BAHAMUT,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,BILIBILI,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,PIKPAK,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,GFW,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,PRIVATE,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,NETFLIX,${PROXY_GROUPS.SELECT},no-resolve`,
    `GEOIP,TELEGRAM,${PROXY_GROUPS.SELECT},no-resolve`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,
    `DST-PORT,22,${PROXY_GROUPS.SELECT}`,
    `MATCH,${PROXY_GROUPS.SELECT}`
];

// 构建规则函数
function buildRules({quicEnabled:e}){const t=[...baseRules];return e||t.unshift("AND,((DST-PORT,443),(NETWORK,UDP)),REJECT"),t}

// 嗅探配置 (保持不变)
const snifferConfig={sniff:{TLS:{ports:[443,8443]},HTTP:{ports:[80,8080,8880]},QUIC:{ports:[443,8443]}},"override-destination":!1,enable:!0,"force-dns-mapping":!0,"skip-domain":["Mijia Cloud","dlg.io.mi.com","+.push.apple.com"]};

// DNS 配置 (保持不变)
function buildDnsConfig({mode:e,fakeIpFilter:t}){const o={enable:!0,ipv6:ipv6Enabled,"prefer-h3":!0,"enhanced-mode":e,"default-nameserver":["119.29.29.29","223.5.5.5"],nameserver:["system","223.5.5.5","119.29.29.29","180.184.1.1"],fallback:["quic://dns0.eu","https://dns.cloudflare.com/dns-query","https://dns.sb/dns-query","tcp://208.67.222.222","tcp://8.26.56.2"],"proxy-server-nameserver":["https://dns.alidns.com/dns-query","tls://dot.pub"]};return t&&(o["fake-ip-filter"]=t),o}const dnsConfig=buildDnsConfig({mode:"redir-host"}),dnsConfigFakeIp=buildDnsConfig({mode:"fake-ip",fakeIpFilter:["geosite:private","geosite:connectivity-check","geosite:cn","Mijia Cloud","dig.io.mi.com","localhost.ptlogin2.qq.com","*.icloud.com","*.stun.*.*","*.stun.*.*.*"]});

// GeoX 资源地址 (保持不变)
const geoxURL={geoip:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",geosite:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",mmdb:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",asn:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb"};

// ================= 主逻辑修改区 =================

// 【重点修改】手动构建极简策略组，不依赖原脚本的复杂分组逻辑
function buildSimpleProxyGroups(allProxies) {
    const allNames = allProxies.map(p => p.name);
    return [
        {
            name: PROXY_GROUPS.SELECT, // 1. 选择代理 (包含所有节点)
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
            type: "select",
            proxies: allNames // 自动填入所有节点
        },
        {
            name: PROXY_GROUPS.MANUAL, // 2. 手动选择 (备用)
            icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png",
            "include-all": true,
            type: "select"
        },
        {
            name: PROXY_GROUPS.DIRECT, // 3. 直连
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
            type: "select",
            proxies: ["DIRECT", PROXY_GROUPS.SELECT]
        }
    ];
}

function main(e){
    const proxies = e.proxies;
    
    // 使用新的极简分组构建函数
    const proxyGroups = buildSimpleProxyGroups(proxies);
    
    // 添加必需的 GLOBAL 组
    const groupNames = proxyGroups.map(g => g.name);
    proxyGroups.push({name:"GLOBAL",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png","include-all":!0,type:"select",proxies:groupNames});

    const rules = buildRules({quicEnabled:quicEnabled});
    
    // 基础配置对象
    const config = { proxies: proxies };

    // 完整配置参数 (Full Config)
    if(fullConfig){
        Object.assign(config, {
            "mixed-port":7890,"redir-port":7892,"tproxy-port":7893,"routing-mark":7894,"allow-lan":!0,
            ipv6:ipv6Enabled,mode:"rule","unified-delay":!0,"tcp-concurrent":!0,
            "find-process-mode":"off","log-level":"info","geodata-loader":"standard",
            "external-controller":":9999","disable-keep-alive":!keepAliveEnabled,
            profile:{"store-selected":!0}
        });
    }

    // 注入最终结果
    Object.assign(config, {
        "proxy-groups": proxyGroups,
        "rule-providers": ruleProviders,
        rules: rules,
        sniffer: snifferConfig,
        dns: fakeIPEnabled ? dnsConfigFakeIp : dnsConfig,
        "geodata-mode": !0,
        "geox-url": geoxURL
    });

    return config;
}
