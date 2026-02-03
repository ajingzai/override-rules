/*!
powerfullz 的 Substore 订阅转换脚本 (极简纯净版)
https://github.com/powerfullz/override-rules

修改内容：
1. 移除所有国家/地区分组。
2. 移除“故障转移”、“静态资源”、“广告拦截”、“低倍率”分组。
3. 只有“选择代理”、“手动选择”、“直连”三个核心组。
4. 广告直接拒绝，静态资源直接直连。
*/

// 核心参数解析（保留部分基础功能开关）
const NODE_SUFFIX="节点";function parseBool(e){return"boolean"==typeof e?e:"string"==typeof e&&("true"===e.toLowerCase()||"1"===e)}function buildFeatureFlags(e){const t=Object.entries({ipv6:"ipv6Enabled",full:"fullConfig",keepalive:"keepAliveEnabled",fakeip:"fakeIPEnabled",quic:"quicEnabled"}).reduce((t,[o,r])=>(t[r]=parseBool(e[o])||!1,t),{});return t}const rawArgs="undefined"!=typeof $arguments?$arguments:{},{ipv6Enabled:ipv6Enabled,fullConfig:fullConfig,keepAliveEnabled:keepAliveEnabled,fakeIPEnabled:fakeIPEnabled,quicEnabled:quicEnabled}=buildFeatureFlags(rawArgs);

// 核心策略组名称定义
const PROXY_GROUPS={SELECT:"选择代理",MANUAL:"手动选择",DIRECT:"直连"};

// 规则集定义 (保持源不变)
const ruleProviders={ADBlock:{type:"http",behavior:"domain",format:"mrs",interval:86400,url:"https://adrules.top/adrules-mihomo.mrs",path:"./ruleset/ADBlock.mrs"},SogouInput:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt",path:"./ruleset/SogouInput.txt"},StaticResources:{type:"http",behavior:"domain",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/domainset/cdn.txt",path:"./ruleset/StaticResources.txt"},CDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/cdn.txt",path:"./ruleset/CDNResources.txt"},TikTok:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list",path:"./ruleset/TikTok.list"},EHentai:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list",path:"./ruleset/EHentai.list"},SteamFix:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list",path:"./ruleset/SteamFix.list"},GoogleFCM:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list",path:"./ruleset/FirebaseCloudMessaging.list"},AdditionalFilter:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list",path:"./ruleset/AdditionalFilter.list"},AdditionalCDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list",path:"./ruleset/AdditionalCDNResources.list"},Crypto:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list",path:"./ruleset/Crypto.list"}};

// 规则构建：彻底重构，移除对旧分组的引用
const baseRules=[
    "RULE-SET,ADBlock,REJECT", // 广告 -> 直接拒绝
    "RULE-SET,AdditionalFilter,REJECT", // 广告 -> 直接拒绝
    `RULE-SET,SogouInput,DIRECT`,
    `DOMAIN-SUFFIX,truthsocial.com,${PROXY_GROUPS.SELECT}`,
    "RULE-SET,StaticResources,DIRECT", // 静态资源 -> 直连
    "RULE-SET,CDNResources,DIRECT",   // 静态资源 -> 直连
    "RULE-SET,AdditionalCDNResources,DIRECT",
    `RULE-SET,Crypto,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,EHentai,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,TikTok,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,SteamFix,DIRECT`,
    `RULE-SET,GoogleFCM,DIRECT`,
    `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`,的域名services.googleapis.cn, $ {PROXY_GROUPS.SELECT   选择}”,
    `GEOSITE,CATEGORY-AI-!CN,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,GOOGLE-PLAY@CN,DIRECT`,
    `GEOSITE,MICROSOFT@CN,DIRECT`,
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
    `GEOSITE,GFW,${PROXY_GROUPS.SELECT}`,“GEOSITE, GFW, $ {PROXY_GROUPS。选择}’,
    `GEOSITE,CN,DIRECT`,
    `GEOSITE,PRIVATE,DIRECT`,
    `GEOIP,NETFLIX,${PROXY_GROUPS.SELECT},no-resolve`,$ {PROXY_GROUPS, GEOIP, NETFLIX。选择},no-resolve’,
    `GEOIP,TELEGRAM,${PROXY_GROUPS.SELECT},no-resolve`,
    `GEOIP,CN,DIRECT`,
    `GEOIP,PRIVATE,DIRECT`,
    `DST-PORT,22,${PROXY_GROUPS.SELECT}`,
    `MATCH,${PROXY_GROUPS.SELECT}`$ {PROXY_GROUPS,匹配。选择}’
];

function buildRules({quicEnabled:e}){const t=[...baseRules];return e||t.unshift("AND,((DST-PORT,443),(NETWORK,UDP)),REJECT"),t}const snifferConfig={sniff:{TLS:{ports:[443,8443]},HTTP:{ports:[80,8080,8880]},QUIC:{ports:[443,8443]}},"override-destination":!1,enable:!0,"force-dns-mapping":!0,"skip-domain":["Mijia Cloud","dlg.io.mi.com","+.push.apple.com"]};function buildDnsConfig({mode:e,fakeIpFilter:t}){const o={enable:!0,ipv6:ipv6Enabled,"prefer-h3":!0,"enhanced-mode":e,"default-nameserver":["119.29.29.29","223.5.5.5"],nameserver:["system","223.5.5.5","119.29.29.29","180.184.1.1"],fallback:["quic://dns0.eu","https://dns.cloudflare.com/dns-query","https://dns.sb/dns-query","tcp://208.67.222.222","tcp://8.26.56.2"],"proxy-server-nameserver":["https://dns.alidns.com/dns-query","tls://dot.pub"]};return t&&(o["fake-ip-filter"]=t),o}const dnsConfig=buildDnsConfig({mode:"redir-host"}),dnsConfigFakeIp=buildDnsConfig({mode:"fake-ip",fakeIpFilter:["geosite:private","geosite:connectivity-check","geosite:cn","Mijia Cloud","dig.io.mi.com","localhost.ptlogin2.qq.com","*.icloud.com","*.stun.*.*","*.stun.*.*.*"]}),geoxURL={geoip:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",geosite:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",mmdb:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",asn:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb"};

// 策略组构建：极简模式
function buildProxyGroups(proxies){
    return [
        {
            name: PROXY_GROUPS.SELECT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
            type: "select",
            proxies: [...proxies, "DIRECT"] // 包含所有节点 + 直连
        },
        {
            name: PROXY_GROUPS.MANUAL,
            icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png",
            "include-all": true,
            type: "select" // 备用的全节点选择
        },
        {
            name: PROXY_GROUPS.DIRECT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
            type: "select",
            proxies: ["DIRECT", PROXY_GROUPS.SELECT]
        }
    ];
}

function main(e){
    // 获取纯节点列表（不含任何分组逻辑）
    const proxies = e.proxies.map(p => p.name); 
    
    // 构建极简策略组
    const proxyGroups = buildProxyGroups(proxies);
    const rules = buildRules({quicEnabled:quicEnabled});

    // 完整的 GLOBAL 组（Clash 默认需要）
    const allGroupNames = proxyGroups.map(e=>e.name);
    proxyGroups.push({name:"GLOBAL",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png","include-all":!0,type:"select",proxies:allGroupNames});

    const config = {proxies: e.proxies};

    // 完整配置参数注入
    if (fullConfig) {
        Object.assign(config, {
            "mixed-port":7890,
            "redir-port":7892,
            "tproxy-port":7893,
            "routing-mark":7894,
            "allow-lan":!0,
            ipv6:ipv6Enabled,
            mode:"rule",
            "unified-delay":!0,
            "tcp-concurrent":!0,
            "find-process-mode":"off",
            "log-level":"info",
            "geodata-loader":"standard",
            "external-controller":":9999",
            "disable-keep-alive":!keepAliveEnabled,
            profile:{"store-selected":!0}
        });
    }

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
