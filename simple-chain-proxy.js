/*!
powerfullz 的 Substore 订阅转换脚本 (链式代理自动化版)
https://github.com/powerfullz/override-rules

新增功能：
1. [自动化] 自动识别“落地/家宽”节点，并强制注入 dialer-proxy: "前置代理"。
   - 效果：所有家宽节点会自动通过“前置代理”组中转，不再直连。
2. [非TUN优化] 保持 Fake-IP 和 System Proxy 优化。
3. [防泄露] 保持 DoH 防劫持。
*/

// ================= 1. 核心底层 =================
const NODE_SUFFIX="节点";function parseBool(e){return"boolean"==typeof e?e:"string"==typeof e&&("true"===e.toLowerCase()||"1"===e)}function parseNumber(e,t=0){if(null==e)return t;const o=parseInt(e,10);return isNaN(o)?t:o}function buildFeatureFlags(e){const t=Object.entries({loadbalance:"loadBalance",landing:"landing",ipv6:"ipv6Enabled",full:"fullConfig",keepalive:"keepAliveEnabled",fakeip:"fakeIPEnabled",quic:"quicEnabled"}).reduce((t,[o,r])=>(t[r]=parseBool(e[o])||!1,t),{});return t.countryThreshold=parseNumber(e.threshold,0),t}const rawArgs="undefined"!=typeof $arguments?$arguments:{},{loadBalance:loadBalance,landing:landing,ipv6Enabled:ipv6Enabled,fullConfig:fullConfig,keepAliveEnabled:keepAliveEnabled,fakeIPEnabled:fakeIPEnabled,quicEnabled:quicEnabled,countryThreshold:countryThreshold}=buildFeatureFlags(rawArgs);function stripNodeSuffix(e){const t=new RegExp("节点$");return e.map(e=>e.replace(t,""))}const buildList=(...e)=>e.flat().filter(Boolean);

// ================= 2. 组名定义 =================
const PROXY_GROUPS={SELECT:"选择代理",FRONT:"前置代理",LANDING:"落地节点",MANUAL:"手动选择",DIRECT:"直连"};

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

// ================= 4. 规则配置 =================
const baseRules=[
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT", // 阻断 QUIC
    `DOMAIN,dns.google,${PROXY_GROUPS.SELECT}`,
    
    // GitHub 加速
    `GEOSITE,GITHUB,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`,
    
    // Google & Gemini 修复
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,generativelanguage.googleapis.com,${PROXY_GROUPS.SELECT}`,

    // Sora & OpenAI
    `DOMAIN-SUFFIX,sora.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.SELECT}`,

    // YouTube 修复
    `DOMAIN-SUFFIX,ggpht.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,

    // 基础规则
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

// ================= 5. DNS 配置 =================
function buildDnsConfig({mode:e, fakeIpFilter:t}) {
    return {
        enable: true,
        ipv6: false, 
        "prefer-h3": false,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
        nameserver: ["https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query"],
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
    const landingRegex = "(?i)家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地";

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
            type: "select", "include-all": true, "exclude-filter": landingRegex
        });
        groups.push({
            name: PROXY_GROUPS.LANDING,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Airport.png",
            type: "select", "include-all": true, filter: landingRegex
        });
    }

    groups.push({name: PROXY_GROUPS.MANUAL, icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png", "include-all": true, type: "select"});
    groups.push({name: PROXY_GROUPS.DIRECT, icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png", type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT]});
    return groups;
}

// ================= 7. 主程序 =================
function main(e){
    let finalProxies = e.proxies;
    
    // 【核心注入逻辑】
    // 如果开启了 landing，自动遍历所有节点
    // 凡是符合“家宽/落地”正则的，强行加入 dialer-proxy 参数
    if (landing) {
        const landingRegRaw = "家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地";
        const landingRegExp = new RegExp(landingRegRaw, "i");
        
        finalProxies = finalProxies.map(p => {
            if (landingRegExp.test(p.name)) {
                // 这是一个落地节点，我们给它装上“前置代理”
                return {
                    ...p,
                    "dialer-proxy": PROXY_GROUPS.FRONT // "前置代理"
                };
            }
            return p;
        });
    }

    const t = {proxies:e.proxies}; // 注意：Clash 配置里的 proxies 列表通常不需要包含 dialer-proxy 字段，
    // 但是！Clash Meta 的逻辑是，如果节点对象里有 dialer-proxy，它就会生效。
    // 所以我们需要把 finalProxies 赋值回去
    t.proxies = finalProxies;

    const u = buildProxyGroups({ landing: landing, defaultProxies: finalProxies.map(p=>p.name) });
    const d = u.map(e => e.name);
    u.push({name:"GLOBAL",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png","include-all":!0,type:"select",proxies:d});

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
