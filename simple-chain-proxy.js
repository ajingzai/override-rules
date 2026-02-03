/*!
powerfullz 的 Substore 订阅转换脚本 (前置代理+落地节点版)
https://github.com/powerfullz/override-rules

修改内容：
1. 必须开启参数 landing=true 才能看到效果。
2. 分组结构：
   - 前置代理 (排除落地节点)
   - 落地节点 (只含落地节点)
   - 选择代理 (包含所有，备用)
   - 手动选择 (包含所有，备用)
   - 直连
3. 移除了所有国家、广告、静态等杂项分组。
*/

// ================= 1. 核心底层函数 (完全保留，勿动) =================
const NODE_SUFFIX="节点";function parseBool(e){return"boolean"==typeof e?e:"string"==typeof e&&("true"===e.toLowerCase()||"1"===e)}function parseNumber(e,t=0){if(null==e)return t;const o=parseInt(e,10);return isNaN(o)?t:o}function buildFeatureFlags(e){const t=Object.entries({loadbalance:"loadBalance",landing:"landing",ipv6:"ipv6Enabled",full:"fullConfig",keepalive:"keepAliveEnabled",fakeip:"fakeIPEnabled",quic:"quicEnabled"}).reduce((t,[o,r])=>(t[r]=parseBool(e[o])||!1,t),{});return t.countryThreshold=parseNumber(e.threshold,0),t}const rawArgs="undefined"!=typeof $arguments?$arguments:{},{loadBalance:loadBalance,landing:landing,ipv6Enabled:ipv6Enabled,fullConfig:fullConfig,keepAliveEnabled:keepAliveEnabled,fakeIPEnabled:fakeIPEnabled,quicEnabled:quicEnabled,countryThreshold:countryThreshold}=buildFeatureFlags(rawArgs);function getCountryGroupNames(e,t){return e.filter(e=>e.count>=t).map(e=>e.country+"节点")}function stripNodeSuffix(e){const t=new RegExp("节点$");return e.map(e=>e.replace(t,""))}const PROXY_GROUPS={SELECT:"选择代理",MANUAL:"手动选择",FALLBACK:"故障转移",DIRECT:"直连",LANDING:"落地节点",LOW_COST:"低倍率节点"},buildList=(...e)=>e.flat().filter(Boolean);function buildBaseLists({landing:e,lowCost:t,countryGroupNames:o}){const r=buildList(PROXY_GROUPS.FALLBACK,e&&PROXY_GROUPS.LANDING,o,t&&PROXY_GROUPS.LOW_COST,PROXY_GROUPS.MANUAL,"DIRECT");return{defaultProxies:buildList(PROXY_GROUPS.SELECT,o,t&&PROXY_GROUPS.LOW_COST,PROXY_GROUPS.MANUAL,PROXY_GROUPS.DIRECT),defaultProxiesDirect:buildList(PROXY_GROUPS.DIRECT,o,t&&PROXY_GROUPS.LOW_COST,PROXY_GROUPS.SELECT,PROXY_GROUPS.MANUAL),defaultSelector:r,defaultFallback:buildList(e&&PROXY_GROUPS.LANDING,o,t&&PROXY_GROUPS.LOW_COST,PROXY_GROUPS.MANUAL,"DIRECT")}}

// ================= 2. 规则集定义 (完全保留) =================
const ruleProviders={ADBlock:{type:"http",behavior:"domain",format:"mrs",interval:86400,url:"https://adrules.top/adrules-mihomo.mrs",path:"./ruleset/ADBlock.mrs"},SogouInput:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt",path:"./ruleset/SogouInput.txt"},StaticResources:{type:"http",behavior:"domain",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/domainset/cdn.txt",path:"./ruleset/StaticResources.txt"},CDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/cdn.txt",path:"./ruleset/CDNResources.txt"},TikTok:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list",path:"./ruleset/TikTok.list"},EHentai:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list",path:"./ruleset/EHentai.list"},SteamFix:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list",path:"./ruleset/SteamFix.list"},GoogleFCM:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list",path:"./ruleset/FirebaseCloudMessaging.list"},AdditionalFilter:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list",path:"./ruleset/AdditionalFilter.list"},AdditionalCDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list",path:"./ruleset/AdditionalCDNResources.list"},Crypto:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list",path:"./ruleset/Crypto.list"}};

// ================= 3. 规则重定向 =================
const baseRules=[
    "RULE-SET,ADBlock,REJECT",
    "RULE-SET,AdditionalFilter,REJECT",
    `RULE-SET,SogouInput,${PROXY_GROUPS.DIRECT}`, 
    `DOMAIN-SUFFIX,truthsocial.com,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,StaticResources,${PROXY_GROUPS.DIRECT}`,
    `RULE-SET,CDNResources,${PROXY_GROUPS.DIRECT}`,
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

function buildRules({quicEnabled:e}){const t=[...baseRules];return e||t.unshift("AND,((DST-PORT,443),(NETWORK,UDP)),REJECT"),t}

// ================= 4. 基础配置 (完全保留) =================
const snifferConfig={sniff:{TLS:{ports:[443,8443]},HTTP:{ports:[80,8080,8880]},QUIC:{ports:[443,8443]}},"override-destination":!1,enable:!0,"force-dns-mapping":!0,"skip-domain":["Mijia Cloud","dlg.io.mi.com","+.push.apple.com"]};function buildDnsConfig({mode:e,fakeIpFilter:t}){const o={enable:!0,ipv6:ipv6Enabled,"prefer-h3":!0,"enhanced-mode":e,"default-nameserver":["119.29.29.29","223.5.5.5"],nameserver:["system","223.5.5.5","119.29.29.29","180.184.1.1"],fallback:["quic://dns0.eu","https://dns.cloudflare.com/dns-query","https://dns.sb/dns-query","tcp://208.67.222.222","tcp://8.26.56.2"],"proxy-server-nameserver":["https://dns.alidns.com/dns-query","tls://dot.pub"]};return t&&(o["fake-ip-filter"]=t),o}const dnsConfig=buildDnsConfig({mode:"redir-host"}),dnsConfigFakeIp=buildDnsConfig({mode:"fake-ip",fakeIpFilter:["geosite:private","geosite:connectivity-check","geosite:cn","Mijia Cloud","dig.io.mi.com","localhost.ptlogin2.qq.com","*.icloud.com","*.stun.*.*","*.stun.*.*.*"]}),geoxURL={geoip:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",geosite:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",mmdb:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",asn:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb"},countriesMeta={"香港":{pattern:"香港|港|HK|hk|Hong Kong|HongKong|hongkong|🇭🇰",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hong_Kong.png"}};

// 保留函数定义防报错
function hasLowCost(e){return false}
function parseCountries(e){return []}
function buildCountryProxyGroups(e){return []}

// ================= 5. 策略组生成 (核心修改) =================
function buildProxyGroups(params){
    const { landing, defaultProxies: l } = params;
    
    const groups = [];

    // 正则匹配家宽/星链等关键词
    const landingRegex = "(?i)家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地";

    // 1. 生成 [前置代理] (核心需求)
    // 只有当 landing=true 时才生成，且排除掉落地节点
    if (landing) {
        groups.push({
            name: "前置代理", // 你要求的组名
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select",
            "include-all": true,
            "exclude-filter": landingRegex // 排除落地节点
        });
    }

    // 2. 生成 [落地节点]
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select",
            "include-all": true,
            filter: landingRegex // 只包含落地节点
        });
    }

    // 3. 生成 [选择代理]
    // 包含所有节点（作为通用出口）
    groups.push({
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        "include-all": true
    });

    // 4. 生成 [手动选择]
    groups.push({
        name: PROXY_GROUPS.MANUAL,
        icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png",
        "include-all": true,
        type: "select"
    });

    // 5. 生成 [直连]
    groups.push({
        name: PROXY_GROUPS.DIRECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
        type: "select",
        proxies: ["DIRECT", PROXY_GROUPS.SELECT]
    });

    return groups;
}

// ================= 6. 主程序 =================
function main(e){
    const t = {proxies:e.proxies};
    
    // 调用分组生成
    const u = buildProxyGroups({ landing: landing, defaultProxies: e.proxies.map(p=>p.name) });

    const d = u.map(e => e.name);
    u.push({name:"GLOBAL",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png","include-all":!0,type:"select",proxies:d});

    const g = buildRules({quicEnabled:quicEnabled});

    if(fullConfig){
        Object.assign(t,{"mixed-port":7890,"redir-port":7892,"tproxy-port":7893,"routing-mark":7894,"allow-lan":!0,ipv6:ipv6Enabled,mode:"rule","unified-delay":!0,"tcp-concurrent":!0,"find-process-mode":"off","log-level":"info","geodata-loader":"standard","external-controller":":9999","disable-keep-alive":!keepAliveEnabled,profile:{"store-selected":!0}})
    }

    Object.assign(t,{
        "proxy-groups":u,
        "rule-providers":ruleProviders,
        rules:g,
        sniffer:snifferConfig,
        dns:fakeIPEnabled?dnsConfigFakeIp:dnsConfig,
        "geodata-mode":!0,
        "geox-url":geoxURL
    });

    return t;
}
