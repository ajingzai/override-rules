/**
 * Clash/Mihomo 精简版链式代理覆写脚本
 * Sub-Store 兼容版本
 * 功能：中国直连 + 国外链式代理
 */

// ===== 解析 URL 参数 =====
function parseParams(url) {
  const params = {};
  const hashIndex = url.indexOf('#');
  if (hashIndex === -1) return params;
  
  const paramString = url.substring(hashIndex + 1);
  paramString.split('&').forEach(param => {
    const [key, value] = param.split('=');
    if (key) {
      params[key] = value === undefined ? 'true' : value;
    }
  });
  return params;
}

// 获取参数
const urlParams = parseParams($arguments?.url || '');

const parseBool = (val) => {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'string') return val === 'true' || val === '1';
  return Boolean(val);
};

// ===== 配置参数 =====
const CONFIG = {
  // 是否启用链式代理
  enableChain: parseBool(urlParams.chain || true),
  
  // 落地节点关键词
  landingKeywords: ["家宽", "家庭", "商宽", "落地", "Starlink", "星链", "住宅", "Residential"],
  
  // 代理组名称
  groups: {
    select: "节点选择",
    front: "前置代理",
    landing: "落地节点",
    auto: "自动选择"
  }
};

// ===== 核心函数 =====
function operator(proxies, targetPlatform, context) {
  const config = {
    proxies: proxies || [],
    "proxy-groups": [],
    rules: []
  };

  console.log("[精简覆写] 开始处理配置...");
  console.log(`[参数] 链式代理=${CONFIG.enableChain}`);

  // 分析节点
  const nodes = analyzeNodes(config.proxies);
  
  // 创建代理组
  createGroups(config, nodes);
  
  // 添加规则
  addRules(config);

  console.log("[精简覆写] 配置完成");
  
  // Sub-Store 返回格式
  return {
    proxies: config.proxies,
    "proxy-groups": config["proxy-groups"],
    rules: config.rules
  };
}

/**
 * 分析节点
 */
function analyzeNodes(proxies) {
  const result = {
    landing: [],   // 落地节点
    normal: [],    // 普通节点
    all: []        // 所有节点
  };

  proxies.forEach(proxy => {
    const name = proxy.name;
    result.all.push(name);

    // 检查是否为落地节点
    const isLanding = CONFIG.landingKeywords.some(kw => name.includes(kw));
    
    if (isLanding && CONFIG.enableChain) {
      result.landing.push(name);
    } else {
      result.normal.push(name);
    }
  });

  console.log(`[节点] 总数=${result.all.length}, 落地=${result.landing.length}, 普通=${result.normal.length}`);
  return result;
}

/**
 * 创建代理组
 */
function createGroups(config, nodes) {
  const groups = [];

  // 1. 节点选择（手动）
  const selectGroup = {
    name: CONFIG.groups.select,
    type: "select",
    proxies: [CONFIG.groups.auto, "DIRECT"]
  };

  // 如果有落地节点，添加到选择列表
  if (CONFIG.enableChain && nodes.landing.length > 0) {
    selectGroup.proxies.splice(1, 0, CONFIG.groups.landing);
  }

  groups.push(selectGroup);

  // 2. 自动选择
  groups.push({
    name: CONFIG.groups.auto,
    type: "url-test",
    proxies: nodes.normal,
    url: "https://www.gstatic.com/generate_204",
    interval: 300
  });

  // 3. 链式代理相关组
  if (CONFIG.enableChain && nodes.landing.length > 0) {
    // 前置代理
    groups.push({
      name: CONFIG.groups.front,
      type: "select",
      proxies: ["DIRECT", ...nodes.normal]
    });

    // 落地节点
    groups.push({
      name: CONFIG.groups.landing,
      type: "select",
      proxies: nodes.landing
    });
  }

  config["proxy-groups"] = groups;
  console.log(`[代理组] 创建了 ${groups.length} 个组`);
}

/**
 * 添加分流规则
 */
function addRules(config) {
  const rules = [
    // 局域网直连
    "GEOIP,LAN,DIRECT,no-resolve",
    
    // 中国大陆直连
    "GEOIP,CN,DIRECT,no-resolve",
    
    // 其他流量走代理
    `MATCH,${CONFIG.groups.select}`
  ];

  config.rules = rules;
  console.log(`[规则] 添加了 ${rules.length} 条规则`);
}
