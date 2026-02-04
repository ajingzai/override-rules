// ================= 5. 策略组生成 (极速筛选版) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    const proxyNames = proxies.map(p => p.name);
    
    // 原始分类
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    // 【核心逻辑】筛选“理论延迟”低于 50ms 的节点
    // 逻辑：物理距离(HK/SG) + 线路质量(IEPL/IPLC/专线)
    // 注意：日本(JP)通常在 60-100ms，所以如果你严格要求 50ms，建议剔除日本
    
    // 1. 地区正则：只选香港和新加坡
    const regionRegex = /香港|HK|Hong Kong|新加坡|SG|Singapore|狮城/i;
    
    // 2. 线路正则：(可选) 如果你的机场普通线路很慢，可以把下面这行取消注释，强制只选专线
    // const lineRegex = /IEPL|IPLC|专线|Premium/i;

    const fastProxies = frontProxies.filter(n => {
        // 条件A: 必须是低延迟地区
        const isFastRegion = regionRegex.test(n);
        
        // 条件B: (可选) 必须是专线 (开启需取消上方 lineRegex 注释)
        // const isPremium = lineRegex.test(n);
        // return isFastRegion && isPremium; 
        
        return isFastRegion; 
    });

    // 如果筛选太严格导致没有节点了，就回退到使用所有香港/新加坡节点，或者全部节点
    const lbProxies = fastProxies.length > 0 ? fastProxies : frontProxies;

    const mainProxies = landing 
        ? [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, PROXY_GROUPS.FRONT, PROXY_GROUPS.LANDING, PROXY_GROUPS.MANUAL, "DIRECT"]
        : [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, PROXY_GROUPS.MANUAL, "DIRECT"];

    // 01. 节点选择
    groups.push({
        name: PROXY_GROUPS.SELECT,
        type: "select",
        proxies: mainProxies
    });

    // 02. 自动选择 (URL-Test)
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies, 
        interval: 300, 
        tolerance: 50 
    });

    // 03. 负载均衡 (极速版)
    groups.push({
        name: PROXY_GROUPS.LB,
        type: "load-balance",
        strategy: "consistent-hashing",
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
        proxies: lbProxies // <--- 使用筛选后的极速节点池
    });

    // ... 下面的代码保持不变 ...
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, ...frontProxies] 
        });
    }

    if (landing) {
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
