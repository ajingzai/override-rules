/*!
powerfullz 的 Substore 订阅转换脚本 (极简定制版)
https://github.com/powerfullz/override-rules

修改说明：
1. 完整保留了原脚本的变量和函数定义，防止运行报错。
2. 策略组仅保留：选择代理、手动选择、直连。
3. 所有节点（无论国家）都会直接放入“选择代理”和“手动选择”组。
4. 广告规则 -> 直接 REJECT；静态资源 -> 直接 DIRECT。
*/

// ================= 1. 核心参数与辅助函数 (完全保留) =================
const NODE_SUFFIX="节点";function parseBool(e){return"boolean"==typeof e?e:"string"==typeof e&&("true"===e.toLowerCase()||"1"===e)}function parseNumber(e,t=0){if(null==e)return t;const o=parseInt(e,10);return isNaN(o)?t:o}function buildFeatureFlags(e){const t=Object.entries({loadbalance:"loadBalance",landing:"landing",ipv6:"ipv6Enabled",full:"fullConfig",keepalive:"keepAliveEnabled",fakeip:"fakeIPEnabled",quic:"quicEnabled"}).reduce((t,[o,r])=>(t[r]=parseBool(e[o])||!1,t),{});return t.countryThreshold=parseNumber(e.threshold,0),t}const rawArgs="undefined"!=typeof $arguments?$arguments:{},{loadBalance:loadBalance,landing:landing,ipv6Enabled:ipv6Enabled,fullConfig:fullConfig,keepAliveEnabled:keepAliveEnabled,fakeIPEnabled:fakeIPEnabled,quicEnabled:quicEnabled,countryThreshold:countryThreshold}=buildFeatureFlags(rawArgs);function getCountryGroupNames(e,t){return e.filter(e=>e.count>=t).map(e=>e.country+"节点")}function stripNodeSuffix(e){const t=new RegExp("节点$");return e.map(e=>e.replace(t,""))}const PROXY_GROUPS={SELECT:"选择代理",MANUAL:"手动选择",FALLBACK:"故障转移",DIRECT:"直连",LANDING:"落地节点",LOW_COST:"低倍率节点"},buildList=(...e)=>e.flat().filter(Boolean);function buildBaseLists({landing:e,lowCost:t,countryGroupNames:o}){const r=buildList(PROXY_GROUPS.FALLBACK,e&&PROXY_GROUPS.LANDING,o,t&&PROXY_GROUPS.LOW_COST,PROXY_GROUPS.MANUAL,"DIRECT");return{defaultProxies:buildList(PROXY_GROUPS.SELECT,o,t&&PROXY_GROUPS.LOW_COST,PROXY_GROUPS.MANUAL,PROXY_GROUPS.DIRECT),defaultProxiesDirect:buildList(PROXY_GROUPS.DIRECT,o,t&&PROXY_GROUPS.LOW_COST,PROXY_GROUPS.SELECT,PROXY_GROUPS.MANUAL),defaultSelector:r,defaultFallback:buildList(e&&PROXY_GROUPS.LANDING,o,t&&PROXY_GROUPS.LOW_COST,PROXY_GROUPS.MANUAL,"DIRECT")}}

// ================= 2. 规则集定义 (完全保留) =================
const ruleProviders={ADBlock:{type:"http",behavior:"domain",format:"mrs",interval:86400,url:"https://adrules.top/adrules-mihomo.mrs",path:"./ruleset/ADBlock.mrs"},SogouInput:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt",path:"./ruleset/SogouInput.txt"},StaticResources:{type:"http",behavior:"domain",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/domainset/cdn.txt",path:"./ruleset/StaticResources.txt"},CDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://ruleset.skk.moe/Clash/non_ip/cdn.txt",path:"./ruleset/CDNResources.txt"},TikTok:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list",path:"./ruleset/TikTok.list"},EHentai:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list",path:"./ruleset/EHentai.list"},SteamFix:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list",path:"./ruleset/SteamFix.list"},GoogleFCM:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list",path:"./ruleset/FirebaseCloudMessaging.list"},AdditionalFilter:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list",path:"./ruleset/AdditionalFilter.list"},AdditionalCDNResources:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list",path:"./ruleset/AdditionalCDNResources.list"},Crypto:{type:"http",behavior:"classical",format:"text",interval:86400,url:"https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list",path:"./ruleset/Crypto.list"}};

// ================= 3. 规则重定向 (重点修改) =================
// 修改说明：将所有原本指向特定分组的规则，改为指向 REJECT, DIRECT 或 SELECT
const baseRules=[
    "RULE-SET,ADBlock,REJECT",                 // 广告 -> 拒绝
    "RULE-SET,AdditionalFilter,REJECT",        // 广告 -> 拒绝
    `RULE-SET,SogouInput,${PROXY_GROUPS.DIRECT}`, 
    `DOMAIN-SUFFIX,truthsocial.com,${PROXY_GROUPS.SELECT}`,
    `RULE-SET,StaticResources,${PROXY_GROUPS.DIRECT}`, // 静态资源 -> 直连
    `RULE-SET,CDNResources,${PROXY_GROUPS.DIRECT}`,    // 静态资源 -> 直连
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
const snifferConfig={sniff:{TLS:{ports:[443,8443]},HTTP:{ports:[80,8080,8880]},QUIC:{ports:[443,8443]}},"override-destination":!1,enable:!0,"force-dns-mapping":!0,"skip-domain":["Mijia Cloud","dlg.io.mi.com","+.push.apple.com"]};function buildDnsConfig({mode:e,fakeIpFilter:t}){const o={enable:!0,ipv6:ipv6Enabled,"prefer-h3":!0,"enhanced-mode":e,"default-nameserver":["119.29.29.29","223.5.5.5"],nameserver:["system","223.5.5.5","119.29.29.29","180.184.1.1"],fallback:["quic://dns0.eu","https://dns.cloudflare.com/dns-query","https://dns.sb/dns-query","tcp://208.67.222.222","tcp://8.26.56.2"],"proxy-server-nameserver":["https://dns.alidns.com/dns-query","tls://dot.pub"]};return t&&(o["fake-ip-filter"]=t),o}const dnsConfig=buildDnsConfig({mode:"redir-host"}),dnsConfigFakeIp=buildDnsConfig({mode:"fake-ip",fakeIpFilter:["geosite:private","geosite:connectivity-check","geosite:cn","Mijia Cloud","dig.io.mi.com","localhost.ptlogin2.qq.com","*.icloud.com","*.stun.*.*","*.stun.*.*.*"]}),geoxURL={geoip:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",geosite:"https://gcore.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",mmdb:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",asn:"https://gcore.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb"},countriesMeta={"香港":{pattern:"香港|港|HK|hk|Hong Kong|HongKong|hongkong|🇭🇰",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hong_Kong.png"},"澳门":{pattern:"澳门|MO|Macau|🇲🇴",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Macao.png"},"台湾":{pattern:"台|新北|彰化|TW|Taiwan|🇹🇼",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Taiwan.png"},"新加坡":{pattern:"新加坡|坡|狮城|SG|Singapore|🇸🇬",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Singapore.png"},"日本":{pattern:"日本|川日|东京|大阪|泉日|埼玉|沪日|深日|JP|Japan|🇯🇵",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Japan.png"},"韩国":{pattern:"KR|Korea|KOR|首尔|韩|韓|🇰🇷",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Korea.png"},"美国":{pattern:"美国|美|US|United States|🇺🇸",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_States.png"},"加拿大":{pattern:"加拿大|Canada|CA|🇨🇦",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Canada.png"},"英国":{pattern:"英国|United Kingdom|UK|伦敦|London|🇬🇧",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_Kingdom.png"},"澳大利亚":{pattern:"澳洲|澳大利亚|AU|Australia|🇦🇺",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Australia.png"},"德国":{pattern:"德国|德|DE|Germany|🇩🇪",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Germany.png"},"法国":{pattern:"法国|法|FR|France|🇫🇷",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/France.png"},"俄罗斯":{pattern:"俄罗斯|俄|RU|Russia|🇷🇺",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Russia.png"},"泰国":{pattern:"泰国|泰|TH|Thailand|🇹🇭",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Thailand.png"},"印度":{pattern:"印度|IN|India|🇮🇳",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/India.png"},"马来西亚":{pattern:"马来西亚|马来|MY|Malaysia|🇲🇾",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Malaysia.png"}};function hasLowCost(e){const t=/0\.[0-5]|低倍率|省流|大流量|实验性/i;return(e.proxies||[]).some(e=>t.test(e.name))}function parseCountries(e){const t=e.proxies||[],o=/家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地/i,r=Object.create(null),n={};for(const[e,t]of Object.entries(countriesMeta))n[e]=new RegExp(t.pattern.replace(/^\(\?i\)/,""));for(const e of t){const t=e.name||"";if(!o.test(t))for(const[e,o]of Object.entries(n))if(o.test(t)){r[e]=(r[e]||0)+1;break}}const s=[];for(const[e,t]of Object.entries(r))s.push({country:e,count:t});return s}function buildCountryProxyGroups({countries:e,landing:t,loadBalance:o}){const r=[],n="0\\.[0-5]|低倍率|省流|大流量|实验性",s=o?"load-balance":"url-test";for(const l of e){const e=countriesMeta[l];if(!e)continue;const i={name:`${l}节点`,icon:e.icon,"include-all":!0,filter:e.pattern,"exclude-filter":t?`(?i)家宽|家庭|家庭宽带|商宽|商业宽带|星链|Starlink|落地|${n}`:n,type:s};o||Object.assign(i,{url:"https://cp.cloudflare.com/generate_204",interval:60,tolerance:20,lazy:!1}),r.push(i)}return r}

// ================= 5. 策略组生成 (重点修改) =================
// 修改说明：重写此函数，忽略所有原本的复杂分组参数，只返回核心分组。
// 我们添加了一个新参数 params.allNodes 来接收所有节点名称。
function buildProxyGroups(params){
    // 获取传递进来的所有节点名称 (默认为空数组防报错)
    const allNodes = params.allNodes || [];
    
    return [
        {
            name: PROXY_GROUPS.SELECT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
            type: "select",
            proxies: [...allNodes, "DIRECT"] // 放入所有节点 + 直连
        },
        {
            name: PROXY_GROUPS.MANUAL,
            icon: "https://gcore.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png",
            "include-all": true,
            type: "select",
            proxies: ["DIRECT", ...allNodes] // 手动选择也放入所有节点
        },
        {
            name: PROXY_GROUPS.DIRECT,
            icon: "https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png",
            type: "select",
            proxies: ["DIRECT", PROXY_GROUPS.SELECT]
        }
    ];
}

// ================= 6. 主程序 (重点修改) =================
function main(e){
    // 提取所有节点名称
    const allNodeNames = e.proxies.map(p => p.name);

    // 调用新的分组生成函数，传入所有节点
    // 注意：这里我们故意忽略了原版的 o, r, n, s 等计算结果，只为了极简
    const u = buildProxyGroups({ allNodes: allNodeNames });

    // 添加 GLOBAL 分组 (Clash 必需)
    const d = u.map(e => e.name);
    u.push({name:"GLOBAL",icon:"https://gcore.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png","include-all":!0,type:"select",proxies:d});

    // 生成规则
    const g = buildRules({quicEnabled:quicEnabled});

    // 组装最终配置
    const t = {proxies:e.proxies};

    // 如果开启了 fullConfig 参数，注入完整内核配置
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
