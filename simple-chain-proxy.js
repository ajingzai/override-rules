/*!
powerfullz 的 Substore 订阅转换脚本 (超级全能规则版)
https://github.com/powerfullz/override-rules

配置变更：
1. [规则扩容] 新增数百个常用域名（AI/Crypto/开发/流媒体），断网也能精准分流。
2. [名称保持] 普通节点保留原名，不重命名。
3. [落地逻辑] 落地节点依然自动添加 "-> 前置" 并走链式代理。
*/

// ================= 1. 基础工具 =================
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

// ================= 3. 规则配置 (超级硬编码) =================
const baseRules = [
    // --- 0. 核心阻断 ---
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT", // 阻断 QUIC

    // --- 1. 国产 AI & 直连白名单 (强制直连) ---
    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,yiyan.baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,chatglm.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,kimi.ai,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,moonshot.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,hunyuan.tencent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,deepseek.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,sensetime.com,${PROXY_GROUPS.DIRECT}`, // 商汤
    
    // --- 2. 国外 AI (强制代理) ---
    `DOMAIN-SUFFIX,grok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaiusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,anthropic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,perplexity.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,poe.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,midjourney.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discord.gg,${PROXY_GROUPS.SELECT}`, // Midjourney 依赖
    `DOMAIN-SUFFIX,stability.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,huggingface.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,civitai.com,${PROXY_GROUPS.SELECT}`,

    // --- 3. 国际社交 (代理) ---
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.me,${PROXY_GROUPS.SELECT}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.SELECT},no-resolve`,
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,facebook.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,instagram.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,whatsapp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,reddit.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discord.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,pinterest.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,snapchat.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tumblr.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,quora.com,${PROXY_GROUPS.SELECT}`,

    // --- 4. 国际流媒体 (代理) ---
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,netflix.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,nflxvideo.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,disneyplus.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bamgrid.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,hbo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,hbomax.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,hulu.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,primevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,amazonvideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,spotify.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,scdn.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,joox.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,kkbox.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,pandora.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,soundcloud.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twitch.tv,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokv.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,byteoversea.com,${PROXY_GROUPS.SELECT}`,

    // --- 5. 开发/技术/云服务 (代理) ---
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gitlab.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bitbucket.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,stackoverflow.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,docker.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,docker.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,npmjs.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,pypi.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,readthedocs.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,medium.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oracle.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,aws.amazon.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,v2ex.com,${PROXY_GROUPS.SELECT}`,

    // --- 6. 加密货币 (代理) ---
    `DOMAIN-SUFFIX,binance.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bnbstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,okx.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,coinbase.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,kraken.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,kucoin.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bybit.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,metamask.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,etherscan.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tronscan.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tradingview.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,coinmarketcap.com,${PROXY_GROUPS.SELECT}`,

    // --- 7. 国际新闻/搜索 (代理) ---
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bing.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,duckduckgo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,yahoo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,nytimes.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bbc.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,cnn.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,reuters.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bloomberg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,wsj.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,wikipedia.org,${PROXY_GROUPS.SELECT}`,

    // --- 8. 其他国外常用 (代理) ---
    `DOMAIN-SUFFIX,amazon.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ebay.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,paypal.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,dropbox.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,mega.nz,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,pornhub.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,xvideos.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,archive.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,cloudflare.com,${PROXY_GROUPS.SELECT}`,

    // --- 9. 国内直连 (Direct) ---
    // BAT & 字节
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,tencent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weixin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,aliyun.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alipay.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,douyin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,toutiao.com,${PROXY_GROUPS.DIRECT}`,
    // 购物/物流
    `DOMAIN-SUFFIX,jd.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,360buy.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,pinduoduo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,meituan.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,ele.me,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,sf-express.com,${PROXY_GROUPS.DIRECT}`, // 顺丰
    `DOMAIN-SUFFIX,cainiao.com,${PROXY_GROUPS.DIRECT}`, // 菜鸟
    // 视频/直播/音乐
    `DOMAIN-SUFFIX,bilibili.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,iqiyi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,youku.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,mgtv.com,${PROXY_GROUPS.DIRECT}`, // 芒果
    `DOMAIN-SUFFIX,douyu.com,${PROXY_GROUPS.DIRECT}`, // 斗鱼
    `DOMAIN-SUFFIX,huya.com,${PROXY_GROUPS.DIRECT}`, // 虎牙
    `DOMAIN-SUFFIX,163.com,${PROXY_GROUPS.DIRECT}`, // 网易云/邮箱
    `DOMAIN-SUFFIX,ximalaya.com,${PROXY_GROUPS.DIRECT}`, // 喜马拉雅
    // 社区/知识
    `DOMAIN-SUFFIX,zhihu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weibo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xiaohongshu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,douban.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,csdn.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,juejin.cn,${PROXY_GROUPS.DIRECT}`,
    // 厂商
    `DOMAIN-SUFFIX,xiaomi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,huawei.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,oppo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,vivo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,apple.com.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,icloud.com.cn,${PROXY_GROUPS.DIRECT}`,
    // 银行/支付
    `DOMAIN-SUFFIX,95516.com,${PROXY_GROUPS.DIRECT}`, // 银联
    `DOMAIN-SUFFIX,icbc.com.cn,${PROXY_GROUPS.DIRECT}`, // 工行
    `DOMAIN-SUFFIX,cmbchina.com,${PROXY_GROUPS.DIRECT}`, // 招行
    `DOMAIN-SUFFIX,ccb.com,${PROXY_GROUPS.DIRECT}`, // 建行
    `DOMAIN-SUFFIX,boc.cn,${PROXY_GROUPS.DIRECT}`, // 中行
    `DOMAIN-SUFFIX,abchina.com,${PROXY_GROUPS.DIRECT}`, // 农行
    `DOMAIN-SUFFIX,bankcomm.com,${PROXY_GROUPS.DIRECT}`, // 交行
    // 其他
    `DOMAIN-SUFFIX,12306.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,ctrip.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cctv.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xinhuanet.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,gov.cn,${PROXY_GROUPS.DIRECT}`,

    // --- 10. 兜底 ---
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,
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

// ================= 6. 策略组生成 =================
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

    // 2. 自动选择 (只测速前置节点)
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies,
        interval: 300, 
        tolerance: 50 
    });

    // 3. 手动切换 (只含前置 + 自动)
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

// ================= 7. 主程序 =================
function main(e) {
    let rawProxies = e.proxies || [];
    let finalProxies = [];
    const excludeKeywords = /套餐|官网|剩余|时间|节点|重置|异常|邮箱|网址|Traffic|Expire|Reset/i;
    const strictLandingKeyword = "落地";

    rawProxies.forEach(p => {
        if (excludeKeywords.test(p.name)) return;

        if (p.name.includes(strictLandingKeyword)) {
            if (landing) {
                // 落地节点：保留重命名逻辑 (加后缀)
                finalProxies.push({
                    ...p,
                    "dialer-proxy": PROXY_GROUPS.FRONT,
                    name: `${p.name} -> 前置`
                });
            } else {
                finalProxies.push(p);
            }
        } else {
            // 普通节点：保留原名，不修改
            finalProxies.push(p);
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
    
    // 8. GLOBAL 组
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
        // "rule-providers": {}, // 硬编码不需要
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
