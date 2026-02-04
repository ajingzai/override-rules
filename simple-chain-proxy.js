// ...前面的代码保持不变...

// ================= 5. 策略组生成 (优化版) =================
function buildProxyGroups(proxies, landing) {
    const groups = [];
    const proxyNames = proxies.map(p => p.name);
    
    // 原始分类
    const frontProxies = proxyNames.filter(n => !n.includes("-> 前置"));
    const landingProxies = proxyNames.filter(n => n.includes("-> 前置"));

    // 【关键修改】筛选出适合做负载均衡的“高速地区”
    // 这里正则匹配：香港/HK, 日本/JP, 新加坡/SG, 台湾/TW, 韩国/KR
    const fastRegionRegex = /香港|HK|Hong Kong|日本|JP|Japan|新加坡|SG|Singapore|台湾|TW|Taiwan|韩国|KR|Korea/i;
    
    // 只取高速节点放入负载均衡组
    const fastProxies = frontProxies.filter(n => fastRegionRegex.test(n));
    // 如果筛选完没有节点（比如全是冷门地区），就回退到使用所有节点，防止报错
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

    // 02. 自动选择
    groups.push({ 
        name: PROXY_GROUPS.AUTO, 
        type: "url-test", 
        proxies: frontProxies, // 自动选择依然可以在所有节点里挑最快的
        interval: 300, 
        tolerance: 50 
    });

    // 03. 负载均衡 (只用高速节点！)
    groups.push({
        name: PROXY_GROUPS.LB,
        type: "load-balance",
        strategy: "consistent-hashing",
        url: "http://www.gstatic.com/generate_204",
        interval: 300,
        proxies: lbProxies // <--- 这里换成了筛选后的列表
    });

    // ...后续代码保持不变...
    
    // ...记得把下面这些组也补全，为了节省篇幅我省略了后续重复代码...
    // 04. 前置代理
    if (landing) {
        groups.push({
            name: PROXY_GROUPS.FRONT,
            type: "select",
            proxies: [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, ...frontProxies] 
        });
    }
    // ...
    
    // ...后面的代码逻辑不变...
    
    // 05, 06, 07, 08, 09 组的定义代码请保留原样
    groups.push({ name: PROXY_GROUPS.LANDING, type: "select", proxies: landingProxies.length ? landingProxies : ["DIRECT"] });
    groups.push({ name: PROXY_GROUPS.MANUAL, type: "select", proxies: [PROXY_GROUPS.AUTO, PROXY_GROUPS.LB, ...frontProxies] });
    groups.push({ name: PROXY_GROUPS.TELEGRAM, type: "select", proxies: mainProxies });
    groups.push({ name: PROXY_GROUPS.MATCH, type: "select", proxies: [PROXY_GROUPS.SELECT, "DIRECT"] });
    groups.push({ name: PROXY_GROUPS.DIRECT, type: "select", proxies: ["DIRECT", PROXY_GROUPS.SELECT] });

    return groups;
}
