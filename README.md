# GYREAD Analytics · 真人访客面板

GYREAD 站点的每日流量面板。从 Cloudflare GraphQL 拉取数据，剔除爬虫/扫描器/自家监控，按 IP 粒度判定真人访客，生成自包含 HTML 面板。

## 在线查看

https://gengyueworks.github.io/gyread-analytics/

## 本地使用

```bash
# 拉取最近 30 天数据并生成面板
python3 fetch_traffic.py --days 30

# 需要环境变量（从 ~/.config/gyread/cf_deploy.env 自动读取）
export CLOUDFLARE_API_TOKEN=...
export CLOUDFLARE_ACCOUNT_ID=...
```

## 每日自动化

launchd `com.gyread.traffic-dashboard` 每天 09:05 自动拉取 + 推送本仓库。

## 真人判定规则

- 排除：自家监控 UA（gyread-monitor、probe-drift、gyread-newsletter、gyread-check）+ 自家 IP 前缀
- 排除：已知爬虫 UA（38 类）
- 排除：只扫漏洞路径（wp-*、xmlrpc、.php）的 IP
- 保留：访问过内容页的 IP、有 CF RUM 信标的 IP、低频次正常路径的 IP

## 文件说明

| 文件 | 说明 |
|------|------|
| `fetch_traffic.py` | 核心脚本：拉数据 + 生成面板 |
| `daily_update.sh` | launchd 入口：拉取 + 推送 |
| `own_markers.json` | 爬虫/自家/扫描路径配置 |
| `data/cn_names.json` | ISO 国家代码 → 中文名映射 |
| `data/world.geojson` | 世界地图数据（Natural Earth 公共领域） |
| `data/traffic-*.json` | 每日快照 |
| `index.html` | 生成的面板（自包含，file:// 可打开） |

---

# GYREAD Analytics · Real Visitor Dashboard

Daily traffic dashboard for GYREAD. Pulls from Cloudflare GraphQL, filters out bots/scanners/own monitors, identifies real visitors by IP behavior, generates a self-contained HTML panel.

## View Online

https://gengyueworks.github.io/gyread-analytics/

## Local Usage

```bash
python3 fetch_traffic.py --days 30
```

## Automation

launchd `com.gyread.traffic-dashboard` runs daily at 09:05: fetch → render → push.

## Real Visitor Detection

- Excludes: own monitor UAs, known bot UAs (38 types), scan-only IPs
- Keeps: IPs that visited content pages, IPs with CF RUM beacon, low-frequency normal-path IPs
