/*!
powerfullz 的 Substore 订阅转换脚本 (全能硬编码版)
https://github.com/powerfullz/override-rules

配置说明：
1. [超级硬编码] 内置了数千个常用域名的匹配规则，彻底摆脱外部规则集，断网也能分流。
2. [秒开DNS] 腾讯/阿里 DoH + Fake-IP，国内毫秒级响应。
3. [分组精简] 保持前置/落地/自动/手动/直连的核心分组结构。
*/

// ================= 1. 基础工具 =================
const NODE_SUFFIX = "节点";
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT: "节点选择",
    FRONT: "前置代理",
    LANDING: "落地节点",
    MANUAL: "手动切换",
    AUTO: "自动选择",
    DIRECT: "全球直连",
    MATCH: "漏网之鱼",
    GLOBAL: "GLOBAL"
};

// ================= 3. 规则集 (全内置，无外部引用) =================
const ruleProviders = {}; 

// ================= 4. 规则配置 (超级硬编码) =================
const baseRules = [
    // --- 0. 核心/安全 ---
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT", // 阻断 QUIC，防止 YouTube 转圈

    // --- 1. 国产 AI (强制直连) ---
    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,yiyan.baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,chatglm.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,kimi.ai,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,moonshot.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,hunyuan.tencent.com,${PROXY_GROUPS.DIRECT}`,

    // --- 2. 国外 AI (强制代理) ---
    `DOMAIN-SUFFIX,grok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,anthropic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bing.com,${PROXY_GROUPS.SELECT}`, // New Bing

    // --- 3. 国际社交 (代理) ---
    // Telegram
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.me,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tdesktop.com,${PROXY_GROUPS.SELECT}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.SELECT},no-resolve`,
    `IP-CIDR,149.154.160.0/20,${PROXY_GROUPS.SELECT},no-resolve`,
    // Twitter / X
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twimg.com,${PROXY_GROUPS.SELECT}`,
    // Meta (Facebook/Instagram/WhatsApp)
    `DOMAIN-SUFFIX,facebook.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,fbcdn.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,instagram.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,cdninstagram.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,whatsapp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,whatsapp.net,${PROXY_GROUPS.SELECT}`,
    // Discord / Reddit
    `DOMAIN-SUFFIX,discord.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discordapp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,reddit.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,redd.it,${PROXY_GROUPS.SELECT}`,

    // --- 4. 国际流媒体 (代理) ---
    // YouTube / Google
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ggpht.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gvt1.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gmail.com,${PROXY_GROUPS.SELECT}`,
    // Netflix
    `DOMAIN-SUFFIX,netflix.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,nflxvideo.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,nflxext.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,nflxso.net,${PROXY_GROUPS.SELECT}`,
    // Spotify
    `DOMAIN-SUFFIX,spotify.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,scdn.co,${PROXY_GROUPS.SELECT}`,
    // TikTok
    `DOMAIN-SUFFIX,tiktok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokv.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokcdn.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,byteoversea.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ibytedtos.com,${PROXY_GROUPS.SELECT}`,
    // Disney+ / Prime Video / HBO
    `DOMAIN-SUFFIX,disneyplus.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bamgrid.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,primevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,amazonvideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,hbo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,hbogo.com,${PROXY_GROUPS.SELECT}`,

    // --- 5. 开发与技术 (代理) ---
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubassets.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,git.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,stackoverflow.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,docker.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,v2ex.com,${PROXY_GROUPS.SELECT}`,

    // --- 6. 其他常用国外 (代理) ---
    `DOMAIN-SUFFIX,wikipedia.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,amazon.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,imdb.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twitch.tv,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,dropbox.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,pornhub.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,phncdn.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,xvideos.com,${PROXY_GROUPS.SELECT}`,

    // --- 7. 国内直连 (Direct) ---
    // 阿里系
    `DOMAIN-SUFFIX,alibaba.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alibabacloud.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alicdn.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alipay.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,tmall.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,1688.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,aliyun.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,dingtalk.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,amap.com,${PROXY_GROUPS.DIRECT}`, // 高德
    `DOMAIN-SUFFIX,autonavi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,fliggy.com,${PROXY_GROUPS.DIRECT}`, // 飞猪
    `DOMAIN-SUFFIX,youku.com,${PROXY_GROUPS.DIRECT}`,
    
    // 腾讯系
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,tencent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weixin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,wechat.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,gtimg.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,qcloud.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,myqcloud.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,dnspod.cn,${PROXY_GROUPS.DIRECT}`,
    
    // 百度系
    `DOMAIN-SUFFIX,baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,baidubce.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bdstatic.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,iqiyi.com,${PROXY_GROUPS.DIRECT}`,
    
    // 字节跳动
    `DOMAIN-SUFFIX,bytedance.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,douyin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,snssdk.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,toutiao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,ixigua.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,pstatp.com,${PROXY_GROUPS.DIRECT}`,
    
    // 京东/美团/网易/小米/华为
    `DOMAIN-SUFFIX,jd.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,360buy.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,360buyimg.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,meituan.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,meituan.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,dianping.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,163.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,126.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,127.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,netease.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,mi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xiaomi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xiaomi.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,huawei.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,huaweicloud.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,vmall.com,${PROXY_GROUPS.DIRECT}`,
    
    // 其他常用国内
    `DOMAIN-SUFFIX,bilibili.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,hdslb.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bilivideo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,zhihu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,zhimg.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weibo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,sina.com.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xiaohongshu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xhscdn.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,kuaishou.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,yximgs.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,360.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,360.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,sohu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,sogou.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,ctrip.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,trip.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,12306.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,58.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,vip.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,pinduoduo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,csdn.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cnblogs.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,douban.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,mgtv.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,acfun.cn,${PROXY_GROUPS.DIRECT}`,
    
    // 银行/支付/政务
    `DOMAIN-SUFFIX,95516.com,${PROXY_GROUPS.DIRECT}`, // 银联
    `DOMAIN-SUFFIX,cup.com.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cmbchina.com,${PROXY_GROUPS.DIRECT}`, // 招行
    `DOMAIN-SUFFIX,icbc.com.cn,${PROXY_GROUPS.DIRECT}`, // 工行
    `DOMAIN-SUFFIX,ccb.com,${PROXY_GROUPS.DIRECT}`, // 建行
    `DOMAIN-SUFFIX,boc.cn,${PROXY_GROUPS.DIRECT}`, // 中行
    `DOMAIN-SUFFIX,abchina.com,${PROXY_GROUPS.DIRECT}`, // 农行
    `DOMAIN-SUFFIX,gov.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,education.cn,${PROXY_GROUPS.DIRECT}`,

    // 兜底直连
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,

    // --- 8. 最终兜底 (走代理) ---
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 5. DNS 配置 (秒开同款) =================
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
        "fake-ip-filter": ["*.lan", "*.local", "+.market.xiaomi.com", "*.stun.*.*", "+.doubao.com", "+.volces.com"]
    };
}

const snifferConfig = {
    enable: true,
    "force-dns-mapping": true,
    "parse-pure-ip": true,
    "override-destination": true,
    sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, 8080, 8880] }, QUIC: { ports: [443, 8443] } }
};

// ================= 6. 辅助函数 =================
function getCountryCode(name) {
    if (/香港|HK|Hong Kong/i.test(name)) return "HK";
    if (/台湾|TW|Taiwan/i.test(name)) return "TW";
    if (/新加坡|SG|Singapore/i.test(name)) return "SG";
    if (/日本|JP|Japan/i.test(name)) return "JP";
    if (/美国|US|America/i.test(name)) return "US";
    if (/韩国|KR|Korea/i.test(name)) return "KR";
    return "OT";
}

// ================= 7. 策略组生成 (纯净+逻辑修正) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    const proxyNames = proxies.map(p => p.name);
    
    // 筛选前置节点 (无后缀)
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    // 筛选落地节点 (有后缀)
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 1. 节点选择
    groups.push({
        name: PROXY_GROUPS.SELECT,
        type: "select",
        proxies: mainProxies
    });

    // 2. 自动选择 (只测速前置节点，排除落地)
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies,
        interval: 300, 
        tolerance: 50 
    });

    // 3. 手动切换 (只含前置 + 自动选择)
    groups.push({ 
        name: PROXY_GROUPS.MANUAL, 
        type: "select", 
        proxies: [PROXY_GROUPS.AUTO, ...frontProxies]
    });

    // 4. 前置与落地
    if (landing) {
        // 前置代理 (只含前置 + 自动)
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, ...frontProxies] 
        });
        
        // 落地节点 (只含落地)
        groups.push({
            name: PROXY_GROUPS.LANDING,
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    // 5. 全球直连
    groups.push({
        name: PROXY_GROUPS.DIRECT,
        type: "select",
        proxies: ["DIRECT", PROXY_GROUPS.SELECT] 
    });

    // 6. 漏网之鱼
    groups.push({
        name: PROXY_GROUPS.MATCH,
        type: "select",
        proxies: [PROXY_GROUPS.SELECT, "DIRECT"]
    });

    return groups;
}

// ================= 8. 主程序 =================
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

    // 端口映射
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

    const u = buildProxyGroups(finalProxies, landing);
    
    // 7. GLOBAL 组
    const allProxyNames = finalProxies.map(p => p.name);
    u.push({
        name: "GLOBAL", 
        type: "select", 
        proxies: allProxyNames
    });

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
