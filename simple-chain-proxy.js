/*!
powerfullz 的 Substore 订阅转换脚本 (全量隐形域名增强版)
https://github.com/powerfullz/override-rules

配置变更：
1. [新增] 补全 twimg, githubusercontent, gravatar 等 20+ 个关键隐形域名。
2. [保留] YouTube 头像 (ggpht.com) 及 TikTok 视频修复 (QUIC阻断)。
3. [结构] 保持精简分组，智能分流。
*/

// ================= 1. 基础工具 =================
function parseBool(val) { return typeof val === "boolean" ? val : (typeof val === "string" && (val.toLowerCase() === "true" || val === "1")); }
const rawArgs = (typeof $arguments !== "undefined") ? $arguments : {};
const landing = parseBool(rawArgs.landing); 
const ipv6Enabled = parseBool(rawArgs.ipv6Enabled) || false;

// ================= 2. 核心组名定义 =================
const PROXY_GROUPS = {
    SELECT:   "01. 节点选择",
    FRONT:    "02. 前置代理",
    LANDING:  "03. 落地节点",
    MANUAL:   "04. 手动切换",
    AUTO:     "05. 自动选择",
    NETFLIX:  "06. Netflix",
    TELEGRAM: "07. Telegram",
    MATCH:    "08. 漏网之鱼",
    DIRECT:   "09. 全球直连",
    GLOBAL:   "GLOBAL" 
};

// ================= 3. 规则配置 (全量版) =================
const baseRules = [
    // ------------------------------------------------
    // ➤ 0. 特殊直连 (国内 AI / 直连优先)
    // ------------------------------------------------
    `DOMAIN-SUFFIX,doubao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,volces.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,deepseek.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,moonshot.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,amap.com,${PROXY_GROUPS.DIRECT}`, // 高德
    `DOMAIN-SUFFIX,autonavi.com,${PROXY_GROUPS.DIRECT}`, // 高德

    // ------------------------------------------------
    // ➤ 1. 国际 AI 服务
    // ------------------------------------------------
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
    `DOMAIN-SUFFIX,notion.so,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,notion.site,${PROXY_GROUPS.SELECT}`,

    // ------------------------------------------------
    // ➤ 2. TikTok (核心修复: 阻断 UDP)
    // ------------------------------------------------
    `AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-KEYWORD,tiktok)),REJECT`, 
    `DOMAIN-SUFFIX,tiktok.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokv.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tiktokcdn.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,byteoversea.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ibytedtos.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,tik-tokapi.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,musically.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-KEYWORD,tiktok,${PROXY_GROUPS.SELECT}`,

    // ------------------------------------------------
    // ➤ 3. 独立分组 App (Netflix & Telegram)
    // ------------------------------------------------
    // Netflix (包含 CDN)
    `DOMAIN-SUFFIX,netflix.com,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,netflix.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflximg.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflxvideo.net,${PROXY_GROUPS.NETFLIX}`,
    `DOMAIN-SUFFIX,nflxso.net,${PROXY_GROUPS.NETFLIX}`, // 新增
    `DOMAIN-SUFFIX,nflxext.com,${PROXY_GROUPS.NETFLIX}`, // 新增
    `DOMAIN-SUFFIX,fast.com,${PROXY_GROUPS.NETFLIX}`,
    // Telegram (包含短链和文章页)
    `DOMAIN-SUFFIX,telegram.org,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,t.me,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,tx.me,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,tdesktop.com,${PROXY_GROUPS.TELEGRAM}`,
    `DOMAIN-SUFFIX,telegra.ph,${PROXY_GROUPS.TELEGRAM}`, // 新增：Telegram文章
    `IP-CIDR,91.108.0.0/16,${PROXY_GROUPS.TELEGRAM},no-resolve`,
    `IP-CIDR,149.154.160.0/20,${PROXY_GROUPS.TELEGRAM},no-resolve`,

    // ------------------------------------------------
    // ➤ 4. 国际常用 & 隐形域名补全 (重点区域)
    // ------------------------------------------------
    // YouTube & Google 隐形域名
    `DOMAIN-SUFFIX,youtube.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googlevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ytimg.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ggpht.com,${PROXY_GROUPS.SELECT}`, // 头像
    `DOMAIN-SUFFIX,gvt1.com,${PROXY_GROUPS.SELECT}`, // 视频流
    `DOMAIN-SUFFIX,gvt2.com,${PROXY_GROUPS.SELECT}`, // 视频流
    `DOMAIN-SUFFIX,gvt3.com,${PROXY_GROUPS.SELECT}`, // 视频流
    `DOMAIN-SUFFIX,youtu.be,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,1e100.net,${PROXY_GROUPS.SELECT}`, // Google骨干网
    `DOMAIN-SUFFIX,xn--ngstr-lra8j.com,${PROXY_GROUPS.SELECT}`, // Google Play
    `DOMAIN-SUFFIX,google.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleapis.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gstatic.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,googleusercontent.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,gmail.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,recaptcha.net,${PROXY_GROUPS.SELECT}`, // 验证码
    `DOMAIN-SUFFIX,android.com,${PROXY_GROUPS.SELECT}`, 
    `DOMAIN-SUFFIX,app-measurement.com,${PROXY_GROUPS.SELECT}`, // App统计(防卡顿)

    // Twitter/X 隐形域名
    `DOMAIN-SUFFIX,twitter.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,x.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,t.co,${PROXY_GROUPS.SELECT}`, // 短链
    `DOMAIN-SUFFIX,twimg.com,${PROXY_GROUPS.SELECT}`, // 🚨 必须：推特图片CDN

    // Facebook/Meta 隐形域名
    `DOMAIN-SUFFIX,facebook.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,fbcdn.net,${PROXY_GROUPS.SELECT}`, // 🚨 必须：FB图片CDN
    `DOMAIN-SUFFIX,fbsbx.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,instagram.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,cdninstagram.com,${PROXY_GROUPS.SELECT}`, // Ins图片
    `DOMAIN-SUFFIX,whatsapp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,whatsapp.net,${PROXY_GROUPS.SELECT}`,

    // Github 隐形域名
    `DOMAIN-SUFFIX,github.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,github.io,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,githubusercontent.com,${PROXY_GROUPS.SELECT}`, // 🚨 必须：Raw文件/图片
    `DOMAIN-SUFFIX,githubassets.com,${PROXY_GROUPS.SELECT}`, // 静态资源

    // 开发者 & 常用工具
    `DOMAIN-SUFFIX,gravatar.com,${PROXY_GROUPS.SELECT}`, // 🚨 全网通用头像
    `DOMAIN-SUFFIX,imgur.com,${PROXY_GROUPS.SELECT}`, // 🚨 常用图床
    `DOMAIN-SUFFIX,vimeo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,vimeocdn.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,stackoverflow.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,medium.com,${PROXY_GROUPS.SELECT}`,
    
    // 娱乐 & 其他
    `DOMAIN-SUFFIX,spotify.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,spotifycdn.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,scdn.co,${PROXY_GROUPS.SELECT}`, // Spotify图片
    `DOMAIN-SUFFIX,twitch.tv,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,ttvnw.net,${PROXY_GROUPS.SELECT}`, // Twitch视频流
    `DOMAIN-SUFFIX,jtvnw.net,${PROXY_GROUPS.SELECT}`, // Twitch资源
    `DOMAIN-SUFFIX,hbo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,disneyplus.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,primevideo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,reddit.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,redd.it,${PROXY_GROUPS.SELECT}`, // Reddit媒体
    `DOMAIN-SUFFIX,discord.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discord.gg,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discordapp.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,discordapp.net,${PROXY_GROUPS.SELECT}`, // Discord媒体
    `DOMAIN-SUFFIX,wikipedia.org,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,duckduckgo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,yahoo.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,amazon.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,pinterest.com,${PROXY_GROUPS.SELECT}`,
    `DOMAIN-SUFFIX,dropbox.com,${PROXY_GROUPS.SELECT}`,

    // ------------------------------------------------
    // ➤ 5. 国内常用 (巨头直连)
    // ------------------------------------------------
    // Bilibili
    `DOMAIN-SUFFIX,bilibili.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bilivideo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,hdslb.com,${PROXY_GROUPS.DIRECT}`,
    // Alibaba
    `DOMAIN-SUFFIX,taobao.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,tmall.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,jd.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,360buy.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,360buyimg.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alicdn.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,alipay.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,aliyun.com,${PROXY_GROUPS.DIRECT}`,
    // Tencent
    `DOMAIN-SUFFIX,qq.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,tencent.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weixin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,wechat.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,gtimg.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,qpic.cn,${PROXY_GROUPS.DIRECT}`,
    // ByteDance CN
    `DOMAIN-SUFFIX,douyin.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,snssdk.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,pstatp.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,toutiao.com,${PROXY_GROUPS.DIRECT}`,
    // NetEase
    `DOMAIN-SUFFIX,163.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,126.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,127.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,netease.com,${PROXY_GROUPS.DIRECT}`,
    // Other CN
    `DOMAIN-SUFFIX,baidu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bdstatic.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,zhihu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,zhimg.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weibo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,weibo.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,sinaimg.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xiaohongshu.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xhscdn.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,meituan.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,dianping.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,pinduoduo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,yangkeduo.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,mi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,xiaomi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,huawei.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,vmall.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,12306.cn,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cctv.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,iqiyi.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,youku.com,${PROXY_GROUPS.DIRECT}`,

    // ------------------------------------------------
    // ➤ 6. Apple / Microsoft
    // ------------------------------------------------
    `DOMAIN-SUFFIX,apple.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,icloud.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,itunes.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,cdn-apple.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,microsoft.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,windows.net,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,office.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,live.com,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN-SUFFIX,bing.com,${PROXY_GROUPS.DIRECT}`,

    // ------------------------------------------------
    // ➤ 7. 兜底
    // ------------------------------------------------
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `MATCH,${PROXY_GROUPS.MATCH}`
];

// ================= 4. DNS 配置 =================
function buildDnsConfig() {
    return {
        enable: true,
        ipv6: false,
        "prefer-h3": false, // 保持 false
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "listen": ":1053",
        "use-hosts": true,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        nameserver: ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"],
        fallback: []
    };
}

// ================= 5. 策略组生成 =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    if (!proxies || proxies.length === 0) return [];
    
    const proxyNames = proxies.map(p => p.name);
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.MANUAL, "DIRECT"];
    
    const subProxies = [PROXY_GROUPS.AUTO, PROXY_GROUPS.SELECT, ...frontProxies];

    // 01. 节点选择
    groups.push({ name: PROXY_GROUPS.SELECT, type: "select", proxies: mainProxies });

    // 02. 前置代理
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, ...frontProxies] 
        });
    }

    // 03. 落地节点
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.LANDING,
            type: "select",
            proxies: landingProxies.length ? landingProxies : ["DIRECT"]
        });
    }

    // 04. 手动切换
    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: [PROXY_GROUPS.AUTO, ...frontProxies] });

    // 05. 自动选择
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies.length ? frontProxies : ["DIRECT"],
        interval: 300, 
        tolerance: 50 
    });

    // 06+. 独立 App (Netflix/Telegram)
    const customGroups = [PROXY_GROUPS.NETFLIX, PROXY_GROUPS.TELEGRAM];
    customGroups.forEach(groupName => {
        groups.push({ name: groupName, type: "select", proxies: subProxies });
    });

    // 末尾
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
