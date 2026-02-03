# 精简版链式代理覆写脚本

## 功能说明

**极简设计，只做两件事：**
1. 🇨🇳 **中国流量直连** - GEOIP CN 直接访问
2. 🌍 **国外流量代理** - 其他流量走代理节点

**可选功能：**
- 🔗 **链式代理** - 支持前置代理 + 落地节点

## 快速开始

### 基础用法（无链式代理）

```
https://your-domain.com/simple-chain-proxy.js
```

**效果：**
- 创建"节点选择"和"自动选择"两个代理组
- 中国流量直连
- 国外流量走代理

### 启用链式代理

```
https://your-domain.com/simple-chain-proxy.js#chain=true
```

**效果：**
- 额外创建"前置代理"和"落地节点"两个组
- 自动识别家宽/商宽等落地节点
- 支持配置 `dialer-proxy`

## 代理组结构

### 不启用链式代理

```
节点选择 (select)
├── 自动选择
└── DIRECT

自动选择 (url-test)
└── [所有节点]
```

### 启用链式代理后

```
节点选择 (select)
├── 自动选择
├── 落地节点
└── DIRECT

自动选择 (url-test)
└── [普通节点]

前置代理 (select)
├── DIRECT
└── [普通节点]

落地节点 (select)
└── [落地节点]
```

## 分流规则

脚本只添加 3 条基础规则：

```yaml
- GEOIP,LAN,DIRECT,no-resolve      # 局域网直连
- GEOIP,CN,DIRECT,no-resolve       # 中国大陆直连
- MATCH,节点选择                    # 其他走代理
```

**简洁明了，不干扰原有规则。**

## 链式代理配置

### 第一步：启用脚本

```
simple-chain-proxy.js#chain=true
```

### 第二步：配置订阅

在你的订阅配置中，为落地节点添加 `dialer-proxy`：

```yaml
proxies:
  - name: '香港家宽落地'
    type: ss
    server: hk-home.example.com
    port: 6666
    cipher: aes-256-gcm
    password: your-password
    dialer-proxy: "前置代理"  # 指定前置代理组
```

### 第三步：使用

在 Clash 中选择"落地节点"组，流量会：
1. 先连接"前置代理"中选择的节点
2. 再通过前置节点连接到落地节点
3. 最终访问目标网站

## 落地节点识别

包含以下关键词的节点会自动识别为落地节点：

- 家宽
- 家庭
- 商宽
- 落地
- Starlink / 星链
- 住宅
- Residential

**示例节点名：**
- ✅ 香港 HGC 家宽
- ✅ 美国 ATT 商宽落地
- ✅ 新加坡 Starlink
- ❌ 香港 IEPL（普通节点）

## 自定义配置

### 修改落地节点关键词

编辑脚本中的 `CONFIG.landingKeywords`：

```javascript
landingKeywords: [
  "家宽", "商宽", "落地",
  "你的关键词1",
  "你的关键词2"
]
```

### 修改代理组名称

编辑 `CONFIG.groups`：

```javascript
groups: {
  select: "节点选择",
  front: "前置代理",
  landing: "落地节点",
  auto: "自动选择"
}
```

## 使用场景

### 场景 1：日常上网

**需求：** 国内直连，国外代理，简单够用

**配置：**
```
simple-chain-proxy.js
```

### 场景 2：家宽落地

**需求：** 使用家宽 IP 访问特定服务（如流媒体）

**配置：**
```
simple-chain-proxy.js#chain=true
```

**订阅配置：**
```yaml
- name: '家宽节点'
  ...
  dialer-proxy: "前置代理"
```

## 与完整版的区别

| 功能 | 精简版 | 完整版 |
|------|--------|--------|
| 国家分组 | ❌ | ✅ |
| 负载均衡 | ❌ | ✅ |
| 自定义规则 | ❌ | ✅ |
| 节点阈值 | ❌ | ✅ |
| 链式代理 | ✅ | ✅ |
| 代码大小 | ~120 行 | ~400 行 |

**选择建议：**
- 只需要基础功能 → 用精简版
- 需要详细分组和规则 → 用完整版

## 故障排查

### Q: 脚本没有生效？
A: 检查客户端是否支持 Script 覆写，查看控制台日志

### Q: 没有识别到落地节点？
A: 
1. 确认节点名包含关键词
2. 确认传入了 `chain=true` 参数
3. 查看控制台输出的节点分析日志

### Q: 链式代理不工作？
A:
1. 检查订阅中是否配置了 `dialer-proxy`
2. 确认前置代理组名称匹配
3. 测试两个代理单独是否可用

## 注意事项

1. ⚠️ 需要 GeoIP 数据库支持（客户端通常会自动下载）
2. ⚠️ 链式代理会增加延迟，根据需求使用
3. ⚠️ 确保订阅中 `dialer-proxy` 字段拼写正确

## 示例配置

### Clash Verge Rev

```yaml
订阅管理 → 编辑 → 覆写脚本
URL: https://your-domain.com/simple-chain-proxy.js#chain=true
```

### Mihomo Party

```yaml
覆写 → Script → 添加
URL: https://your-domain.com/simple-chain-proxy.js#chain=true
应用到订阅: [选择目标订阅]
```

### Sub-Store

```javascript
{
  "url": "https://your-subscription-url",
  "process": [
    {
      "type": "script",
      "url": "https://your-domain.com/simple-chain-proxy.js#chain=true"
    }
  ]
}
```

## 日志示例

```
[精简覆写] 开始处理配置...
[参数] 链式代理=true
[节点] 总数=20, 落地=2, 普通=18
[代理组] 创建了 4 个组
[规则] 添加了 3 条规则
[精简覆写] 配置完成
```

## License

MIT License
