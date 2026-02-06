/*!
powerfullz 的 Substore 订阅转换脚本 (终极全规则硬编码 + 香港宽松版)
https://github.com/powerfullz/override-rules

配置变更：
1. [规则究极增强] 覆盖币圈、游戏、开发、隐私、以及国内各大生活类 APP。
2. [负载均衡] 宽松筛选：包含 "香港"、"HK"、"Hong Kong" 或 "🇭🇰" 的节点均可入选。
3. [保底机制] 找不到香港节点时强制直连。
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT:   "01. 节点选择",
    AUTO:     "02. 自动选择",
    LB:       "03. 负载均衡",
    FRONT:    "04. 前置代理",
    LANDING:  "05. 落地节点",
    MANUAL:   "06. 手动切换",
    TELEGRAM: "07. 电报消息",
    MATCH:    "08. 漏网之鱼",
    DIRECT:   "09. 全球直连",
    GLOBAL:   "GLOBAL" 
};

// ================= 3. 规则配置 (究极硬编码版) =================
const baseRules = [
    // --- 0. 核心阻断 & 安全 ---
    "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT", // 阻断 QUIC

    // --- 1. 特殊直连 (国产 AI & 国内服务) ---
    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,yiyan.baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,chatglm.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,kimi.ai,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,moonshot.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,hunyuan.tencent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,deepseek.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,

    // --- 2. 电报专属 (Telegram) ---
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,t.me,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,tdesktop.com,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,tx.me,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,telegram.me,${PROXY_GROUPS.TELEGRAM}`,
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    `IP-CIDR,149.154.160.0/20,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    `IP-CIDR,5.28.192.0/18,${PROXY_GROUPS.TELEGRAM},no-resolve`,

    // --- 3. 国外 AI (OpenAI/Claude/Google) ---
    `DOMAIN-SUFFIX,openai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chatgpt.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaistatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oaiusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,anthropic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,claude.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,grok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gemini.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bard.google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,perplexity.ai,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,poe.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,midjourney.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,civitai.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,huggingface.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,sora.com,${PROXY_GROUPS.SELECT}`,

    // --- 4. Google 全家桶 ---
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gvt1.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gmail.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,android.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,appspot.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,blogger.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,chrome.com,${PROXY_GROUPS.SELECT}`,

    // --- 5. 国际社交 (Twitter/Meta/Insta) ---
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,facebook.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,fbcdn.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,instagram.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,cdninstagram.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,whatsapp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,whatsapp.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,reddit.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,redditmedia.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,pinterest.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tumblr.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,snapchat.com,${PROXY_GROUPS.SELECT}`,

    // --- 6. 开发者 & 技术 (Github/Docker/StackOverflow) ---
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,github.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,git.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,docker.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,docker.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,stackoverflow.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,npmjs.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,python.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,oracle.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,medium.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,archive.org,${PROXY_GROUPS.SELECT}`, // 互联网档案馆

    // --- 7. 加密货币 (Binance/OKX/MetaMask) ---
    `DOMAIN-SUFFIX,binance.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,binance.me,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bn-ent.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,okx.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,okex.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,coinbase.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gate.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,kraken.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,kucoin.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,metamask.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,etherscan.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tronscan.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tradingview.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,coinmarketcap.com,${PROXY_GROUPS.SELECT}`,

    // --- 8. 游戏 & 语音 (Steam/Discord/Twitch) ---
    `DOMAIN-SUFFIX,steamcommunity.com,${PROXY_GROUPS.SELECT}`, // 社区必须走代理
    `DOMAIN-SUFFIX,steampowered.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discord.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discord.gg,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discordapp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,twitch.tv,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ttvnw.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,epicgames.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ea.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ubisoft.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,playstation.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,xbox.com,${PROXY_GROUPS.SELECT}`,

    // --- 9. 国际流媒体 (Netflix/Disney/Spotify/Porn) ---
    `DOMAIN-SUFFIX,netflix.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,netflix.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,nflximg.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,nflxvideo.net,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,disneyplus.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bamgrid.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,spotify.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,scdn.co,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,hbo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,hulu.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,primevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,pornhub.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,phncdn.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,xvideos.com,${PROXY_GROUPS.SELECT}`,

    // --- 10. 隐私 & 搜索 (DuckDuckGo/Proton) ---
    `DOMAIN-SUFFIX,duckduckgo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,protonmail.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,proton.me,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,torproject.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,mega.nz,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,dropbox.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,wikipedia.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,reuters.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,bbc.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,nytimes.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,wsj.com,${PROXY_GROUPS.SELECT}`,

    // =======================================================
    // --- 下面全部强制直连 (防止国内应用绕路/风控) ---
    // =======================================================

    // 阿里系
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,tmall.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,jd.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alipay.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alicdn.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,aliyun.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,dingtalk.com,${PROXY_GROUPS.DIRECT}`,
    // 腾讯系
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weixin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,wechat.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,tencent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,gtimg.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,qcloud.com,${PROXY_GROUPS.DIRECT}`,
    // 字节/头条
    `DOMAIN-SUFFIX,douyin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,toutiao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,byteimg.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,feishu.cn,${PROXY_GROUPS.DIRECT}`,
    // 拼多多/美团/生活
    `DOMAIN-SUFFIX,pinduoduo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,yangkeduo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,meituan.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,ele.me,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,dianping.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,58.com,${PROXY_GROUPS.DIRECT}`,
    // 视频/社区
    `DOMAIN-SUFFIX,bilibili.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bilivideo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,zhihu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weibo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xiaohongshu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,iqiyi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,youku.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,mgtv.com,${PROXY_GROUPS.DIRECT}`,
    // 银行/支付 (防风控)
    `DOMAIN-SUFFIX,95516.com,${PROXY_GROUPS.DIRECT}`, // 银联
    `DOMAIN-SUFFIX,cmbchina.com,${PROXY_GROUPS.DIRECT}`, // 招行
    `DOMAIN-SUFFIX,icbc.com.cn,${PROXY_GROUPS.DIRECT}`, // 工行
    `DOMAIN-SUFFIX,ccb.com,${PROXY_GROUPS.DIRECT}`, // 建行
    `DOMAIN-SUFFIX,abchina.com,${PROXY_GROUPS.DIRECT}`, // 农行
    `DOMAIN-SUFFIX,boc.cn,${PROXY_GROUPS.DIRECT}`, // 中行
    // 运营商/政务/教育
    `DOMAIN-SUFFIX,10086.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,189.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,10010.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,gov.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,edu.cn,${PROXY_GROUPS.DIRECT}`,
    // 顺丰/菜鸟/12306
    `DOMAIN-SUFFIX,12306.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,sf-express.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cainiao.com,${PROXY_GROUPS.DIRECT}`,
    
    // --- 微软 & 苹果 (优化) ---
    `DOMAIN-SUFFIX,apple.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,icloud.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cdn-apple.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,microsoft.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,office.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,windows.net,${PROXY_GROUPS.DIRECT}`,

    // --- 兜底规则 ---
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 =================
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
        fallback: []
    };
}

// ================= 5. 策略组生成 (香港宽松版) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    if (!proxies || proxies.length === 0) return [];
    
    const proxyNames = proxies.map(p => p.name);
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    // 【核心筛选】宽松匹配：香港/HK/HongKong/🇭🇰
    const regionRegex = /香港|HK|Hong\s*Kong|🇭🇰/i;
    
    let fastProxies = frontProxies.filter(n => regionRegex.test(n));

    // 【保底逻辑】找不到香港就直连，防止乱飞
    let lbProxies = fastProxies.length > 0 ? fastProxies : ["DIRECT"];

    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 01. 节点选择
    groups.push({ name: PROXY_GROUPS.SELECT, type: "select", proxies: mainProxies });

    // 02. 自动选择
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies.length ? frontProxies : ["DIRECT"],
        interval: 300, 
        tolerance: 50 
    });

    // 03. 负载均衡 (香港全量)
    groups.push({
        name: PROXY_GROUPS.LB,
        type: "load-balance",
        strategy: "consistent-hashing",
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
        proxies: lbProxies 
    });

    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, ...frontProxies] 
        });
        groups.push({
            name: PROXY_GROUPS.LANDING,
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, ...frontProxies] });
    groups.push({ name: PROXY_GROUPS.TELEGRAM, type: "select", proxies: mainProxies });
    groups.push({ name: PROXY_GROUPS.MATCH, type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });
    groups.push({ name: PROXY_GROUPS.DIRECT, type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });

    return groups;
}

// ================= 6. 主程序 =================
function main(e) {
    try {
        let rawProxies = e.proxies || [];
        let finalProxies = [];
        const excludeKeywords = /套餐|官网|剩余|时间|重置|异常|邮箱|网址/i;
        const strictLandingKeyword = "落地"; 

        rawProxies.forEach(p => {
            if (excludeKeywords.test(p.name)) return;
            if (p.name.includes(strictLandingKeyword)) {
                if (landing) {
                    finalProxies.push({ ...p, "dialer-proxy": PROXY_GROUPS.FRONT, name: `${p.name} -> 前置` });
                } else {
                    finalProxies.push(p);
                }
            } else {
                finalProxies.push(p);
            }
        });

        if (finalProxies.length === 0) return e; 

        const autoListeners = [];
        let startPort = 8000;
        finalProxies.forEach(proxy => {
            autoListeners.push({ name: `mixed-${startPort}`, type: "mixed", address: "0.0.0.0", port: startPort, proxy: proxy.name });
            startPort++;
        });

        const u = buildProxyGroups(finalProxies, landing);
        const allProxyNames = finalProxies.map(p => p.name);
        u.push({ name: "GLOBAL", type: "select", proxies: allProxyNames });

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
            rules: baseRules,
            dns: buildDnsConfig()
        };
    } catch (error) {
        console.log("Script Error: " + error);
        return e;
    }
}
