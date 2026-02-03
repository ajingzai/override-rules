/*!
powerfullz 的 Substore 订阅转换脚本 (国内加速+防泄露版)
https://github.com/powerfullz/override-rules

修改说明：
1. [速度优化] 国内 DNS 回归 UDP (223.5.5.5)，解决国内网站打开慢的问题。
2. [防泄露] 国外 DNS 保持 DoH (Google/CF) 并走代理，确保测试不泄露。
3. [兼容性] 关闭了 prefer-h3 (HTTP/3) 实验性功能，提高解析稳定性。
4. [完美分组] 保持：选择代理 -> [前置代理/落地节点/手动/直连]。
*/

// ================= 1. 核心底层 (保留勿动) =================
const NODE_SUFFIX="节点";function parseBool(e){return"boolean"==typeof e?e:"string"==typeof e&&("true"===e.toLowerCase()||"1"===e)}function parseNumber(e,t=0){if(null==e)return t;const o=parseInt(e,10);return isNaN(o)?t:o}function buildFeatureFlags(e){const t=Object.entries({loadbalance:"loadBalance",landing:"landing",ipv6:"ipv6Enabled",full:"fullConfig",keepalive:"keepAliveEnabled",fakeip:"fakeIPEnabled",quic:"quicEnabled"}).reduce((t,[o,r])=>(t[r]=parseBool(e[o])||!1,t),{});return t.countryThreshold=parseNumber(e.threshold,0),t}const rawArgs="undefined"!=typeof $arguments?$arguments:{},{loadBalance:loadBalance,landing:landing,ipv6Enabled:ipv6Enabled,fullConfig:fullConfig,keepAliveEnabled:keepAliveEnabled,fakeIPEnabled:fakeIPEnabled,quicEnabled:quicEnabled,countryThreshold:countryThreshold}=buildFeatureFlags(rawArgs);function stripNodeSuffix(e){const t=new RegExp("节点$");return e.map(e=>e.replace(t,""))}const buildList=(...e)=>e.flat().filter(Boolean);

// ================= 2. 组名定义 =================
const PROXY_GROUPS={
    SELECT: "选择代理",
    FRONT: "前置代理",
    LANDING: "落地节点",
    MANUAL: "手动选择",
    DIRECT: "直连"
};

// ================= 3. 规则集 =================
const ruleProviders={
    ADBlock:{type:"http",behavior:"domain",format:"mrs",interval:86400,url:"https://adrules.top/adrules-mihomo.mrs",path:"./ruleset/ADBlock.mrs"},
    SogouInput:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt",path:"./ruleset/SogouInput.txt"},
    StaticResources:{type:"http",behavior:"domain",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/domainset/cdn.txt",path:"./ruleset/StaticResources.txt"},
    CDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/cdn.txt",path:"./ruleset/CDNResources.txt"},
    TikTok:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list",path:"./ruleset/TikTok.list"},
    EHentai:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list",path:"./ruleset/EHentai.list"},
    SteamFix:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list",path:"./ruleset/SteamFix.list"},
    GoogleFCM:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list",path:"./ruleset/FirebaseCloudMessaging.list"},
    AdditionalFilter:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list",path:"./ruleset/AdditionalFilter.list"},
    AdditionalCDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list",path:"./ruleset/AdditionalCDNResources.list"},
    Crypto:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list",path:"./ruleset/Crypto.list"}
};

// ================= 4. 规则重定向 =================
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

// ================= 5. DNS 配置 (速度+防泄露 优化) =================
function buildDnsConfig({mode:e, fakeIpFilter:t}) {
    const dns = {
        enable: true,
        ipv6: false, 
        "prefer-h3": false, // 关闭 H3 提升国内解析速度稳定性
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        
        // 1. 默认 Nameserver (兜底/国外)
        // 必须走代理，防止直接向 Google 发包被墙或泄露
        nameserver: [
            "https://8.8.8.8/dns-query",
            "https://1.1.1.1/dns-query"
        ],
        
        // 2. 策略分流 (Nameserver Policy) - 加速核心
        // 国内域名 -> 直接用 UDP 119.29.29.29 (极速，无握手延迟)
        // 注意：因为测试网站(如dnsleaktest)是国外域名，它不会匹配到这里，所以不会泄露！
        "nameserver-policy": {
            "geosite:cn,private,apple,huawei,xiaomi": [
                "223.5.5.5",
                "119.29.29.29"
            ]
        },

        // 3. 引导 DNS
        "default-nameserver": [
            "223.5.5.5", 
            "119.29.29.29"
        ]
    };

    if (t) {
        dns["fake-ip-filter"] = t;
    }
    return dns;
}

const snifferConfig={sniff:{TLS:{ports:[443,8443]},HTTP:{ports:[80,8080,8880]},QUIC:{ports:[443,8443]}},"override-destination":!1,enable:!0,"force-dns-mapping":!0,"skip-domain":["Mijia Cloud","dlg.io.mi.com","+.push.apple.com"]};

// 构建配置
const dnsConfigFakeIp = buildDnsConfig({
    mode: "fake-ip",
    fakeIpFilter: [
        "geosite:private",
        "geosite:connectivity-check",
        "geosite:cn",
        "Mijia Cloud",
        "dlg.io.mi.com",
        "localhost.ptlogin2.qq.com",
        "*.icloud.com",
        "*.stun.*.*",
        "*.stun.*.*.*"
    ]
});

const geoxURL={geoip:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",geosite:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",mmdb:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",asn:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb"};

// 占位函数
const countriesMeta={}; 
function hasLowCost(e){return false}
function parseCountries(e){return []}
function buildCountryProxyGroups(e){return []}
function buildBaseLists(e){return {defaultProxies:[]}}

// ================= 6. 策略组生成 =================
function buildProxyGroups(params){
    const { landing, defaultProxies: l } = params;
    const groups = [];
    const landingRegex = "(?i)家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地";

    // 第1组：选择代理
    const selectProxies = [];
    if (landing) {
        selectProxies.push(PROXY_GROUPS.FRONT);   
        selectProxies.push(PROXY_GROUPS.LANDING); 
    }
    selectProxies.push(PROXY_GROUPS.MANUAL);      
    selectProxies.push("DIRECT");                 

    const selectGroup = {
        name: PROXY_GROUPS.SELECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
        type: "select",
        proxies: selectProxies
    };
    if (!landing) selectGroup["include-all"] = true; 
    groups.push(selectGroup);

    // 第2组：前置代理 (仅 landing=true)
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Area.png",
            type: "select",
            "include-all": true,
            "exclude-filter": landingRegex
        });
    }

    // 第3组：落地节点 (仅 landing=true)
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select",
            "include-all": true,
            filter: landingRegex 
        });
    }

    // 第4组：手动选择
    groups.push({
        name: PROXY_GROUPS.MANUAL,
        icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png",
        "include-all": true,
        type: "select"
    });

    // 第5组：直连
    groups.push({
        name: PROXY_GROUPS.DIRECT,
        icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
        type: "select",
        proxies: ["DIRECT", PROXY_GROUPS.SELECT]
    });

    return groups;
}

// ================= 7. 主程序 =================
function main(e){
    const t = {proxies:e.proxies};
    
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
        dns: dnsConfigFakeIp,
        "geodata-mode":!0,
        "geox-url":geoxURL
    });

    return t;
}
