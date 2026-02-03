/*!
powerfullz 的 Substore 订阅转换脚本 (端口映射/指纹浏览器专用版)
https://github.com/powerfullz/override-rules

新增核心功能：
1. [端口映射] 自动遍历所有节点，从 8000 端口开始，为每个节点创建一个独立端口。
   - 格式：0.0.0.0:8000 -> 节点1
   - 格式：0.0.0.0:8001 -> 节点2 ...
2. [兼容性] 完美兼容之前的“落地前置”链式代理逻辑。
   - 如果节点被标记为 "-> 前置"，端口映射也会指向这个处理后的链式节点。
*/

// ================= 1. 核心底层 =================
const NODE_SUFFIX="节点";function parseBool(e){return"boolean"==typeof e?e:"string"==typeof e&&("true"===e.toLowerCase()||"1"===e)}function parseNumber(e,t=0){if(null==e)return t;const o=parseInt(e,10);return isNaN(o)?t:o}function buildFeatureFlags(e){const t=Object.entries({loadbalance:"loadBalance",landing:"landing",ipv6:"ipv6Enabled",full:"fullConfig",keepalive:"keepAliveEnabled",fakeip:"fakeIPEnabled",quic:"quicEnabled"}).reduce((t,[o,r])=>(t[r]=parseBool(e[o])||!1,t),{});return t.countryThreshold=parseNumber(e.threshold,0),t}const rawArgs="undefined"!=typeof $arguments?$arguments:{},{loadBalance:loadBalance,landing:landing,ipv6Enabled:ipv6Enabled,fullConfig:fullConfig,keepAliveEnabled:keepAliveEnabled,fakeIPEnabled:fakeIPEnabled,quicEnabled:quicEnabled,countryThreshold:countryThreshold}=buildFeatureFlags(rawArgs);function stripNodeSuffix(e){const t=new RegExp("节点$");return e.map(e=>e.replace(t,""))}const buildList=(...e)=>e.flat().filter(Boolean);

// ================= 2. 组名定义 =================
const PROXY_GROUPS={SELECT:"选择代理",FRONT:"前置代理",LANDING:"落地节点",MANUAL:"手动选择",DIRECT:"直连"};

// ================= 3. 规则配置 =================
const baseRules=[
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT", 
    `DOMAIN,dns.google,${PROXY_GROUPS.SELECT}`,
    
    `GEOSITE,GITHUB,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`,
    
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,generativelanguage.googleapis.com,${PROXY_GROUPS.SELECT}`,

    `DOMAIN-SUFFIX,sora.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.SELECT}`,

    `DOMAIN-SUFFIX,ggpht.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,

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

const ruleProviders={ADBlock:{type:"http",behavior:"domain",format:"mrs",interval:86400,url:"https://adrules.top/adrules-mihomo.mrs",path:"./ruleset/ADBlock.mrs"},SogouInput:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt",path:"./ruleset/SogouInput.txt"},StaticResources:{type:"http",behavior:"domain",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/domainset/cdn.txt",path:"./ruleset/StaticResources.txt"},CDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/cdn.txt",path:"./ruleset/CDNResources.txt"},TikTok:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list",path:"./ruleset/TikTok.list"},EHentai:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list",path:"./ruleset/EHentai.list"},SteamFix:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list",path:"./ruleset/SteamFix.list"},GoogleFCM:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list",path:"./ruleset/FirebaseCloudMessaging.list"},AdditionalFilter:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list",path:"./ruleset/AdditionalFilter.list"},AdditionalCDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list",path:"./ruleset/AdditionalCDNResources.list"},Crypto:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list",path:"./ruleset/Crypto.list"}};

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

// ================= 7. 主程序 =================
function main(e){
    let finalProxies = e.proxies;
    
    // 1. 处理节点：筛选落地、链式注入
    if (landing) {
        const strictLandingKeyword = "落地";
        finalProxies = finalProxies.map(p => {
            if (p.name.includes(strictLandingKeyword)) {
                return {
                    ...p,
                    "dialer-proxy": PROXY_GROUPS.FRONT, 
                    name: `${p.name} -> 前置` 
                };
            }
            return p;
        });
    }

    const t = {proxies:e.proxies};
    t.proxies = finalProxies;

    // 2. 生成策略组
    const u = buildProxyGroups({ landing: landing, defaultProxies: finalProxies.map(p=>p.name) });
    const d = u.map(e => e.name);
    u.push({name:"GLOBAL",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png","include-all":!0,type:"select",proxies:d});

    // 3. 【核心新增】自动生成 Listeners (端口映射)
    // 遍历所有节点，从 8000 开始分配端口
    const autoListeners = [];
    let startPort = 8000;

    finalProxies.forEach(proxy => {
        autoListeners.push({
            name: `mixed-${startPort}`, // 唯一标识名
            type: "mixed",              // 支持 HTTP 和 SOCKS5
            address: "0.0.0.0",         // 允许局域网连接 (0.0.0.0)，只允许本机就改 127.0.0.1
            port: startPort,            // 端口号
            proxy: proxy.name           // 绑定到具体节点名
        });
        startPort++; // 端口号 +1
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
        // 注入生成的 listeners 配置
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
