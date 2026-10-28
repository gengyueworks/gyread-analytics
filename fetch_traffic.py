#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GYREAD 每日流量面板 · 数据采集与渲染
=====================================
只统计 gyread 本站（gyread.com / gyread.top / www.* / the-music workers.dev），
剔除自家监控（UA 片段 / IP 前缀命中）与已知爬虫 UA，剩下按「独立 IP」计为真人访客。

数据源：Cloudflare GraphQL（account 级 httpRequestsAdaptiveGroups）
产物：
  data/traffic-YYYY-MM-DD.json   每日原始快照（归档，防 CF 30 天留存过期）
  data/aggregated.json           30 天聚合（趋势 + 国家分布 + 页面 + 明细）
  index.html                     自包含可视化面板（无外链，file:// 直接打开）

用法：
  python3 fetch_traffic.py [--days 30] [--host HOST...]
环境变量：CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID（读 ~/.config/gyread/cf_deploy.env）
"""

import argparse, json, os, re, subprocess, sys, datetime, collections, math

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
INDEX = os.path.join(BASE, "index.html")
MARKERS = json.load(open(os.path.join(BASE, "own_markers.json"), encoding="utf-8"))

SITE_HOSTS = [
    "gyread.com", "gyread.top", "www.gyread.com", "www.gyread.top",
    "the-music-membership.yue-membership.workers.dev",
]

def load_env():
    envfile = os.path.expanduser("~/.config/gyread/cf_deploy.env")
    if os.path.exists(envfile):
        for line in open(envfile):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v)
    if not os.environ.get("CLOUDFLARE_API_TOKEN") or not os.environ.get("CLOUDFLARE_ACCOUNT_ID"):
        sys.exit("缺少 CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID")

def gql(query):
    body = json.dumps({"query": query}).encode()
    out = subprocess.run(
        ["curl", "-sS", "--retry", "3", "--retry-delay", "2",
         "-X", "POST", "-H", f"Authorization: Bearer {os.environ['CLOUDFLARE_API_TOKEN']}",
         "-H", "Content-Type: application/json",
         "--data-binary", "@-", "https://api.cloudflare.com/client/v4/graphql"],
        input=body, capture_output=True, timeout=120).stdout
    return json.loads(out)

def query_adaptive(filter_expr, dims, limit=2000):
    d = ",".join(dims)
    q = ('{ viewer { accounts(filter:{accountTag:"%s"}) { httpRequestsAdaptiveGroups('
         'limit:%d, orderBy:[count_DESC], filter:{%s}) { count dimensions { %s } } } } }'
         % (os.environ["CLOUDFLARE_ACCOUNT_ID"], limit, filter_expr, d))
    r = gql(q)
    if r.get("errors"):
        raise RuntimeError(r["errors"][0]["message"])
    return r["data"]["viewer"]["accounts"][0]["httpRequestsAdaptiveGroups"]

def day_bounds(d):
    return f'date_geq:"{d}",date_leq:"{d}"'

def classify(ua, ip):
    u = (ua or "").lower()
    ip = ip or ""
    if any(t in u for t in MARKERS["ua_tokens"]):
        return "own"
    if any(ip.startswith(p) for p in MARKERS["ip_prefixes"]):
        return "own"
    if any(t in u for t in MARKERS["bot_ua_tokens"]):
        return "bot"
    if any(t in u for t in ["python-requests", "curl/", "wget", "scrapy", "go-http-client",
                            "httpclient", "libwww", "okhttp", "aria2", "node-fetch", "axios", "java/"]):
        return "script"
    if "chrome" in u or "safari" in u or "firefox" in u or "edg/" in u or "mozilla/5.0" in u:
        return "human"
    if not u:
        return "empty"
    return "other"

def fetch_day(d):
    f = day_bounds(d)
    hosts = ",".join('"%s"' % h for h in SITE_HOSTS)
    rows = query_adaptive(f'{f},clientRequestHTTPHost_in:[{hosts}]',
                          ["clientCountryName", "clientIP", "userAgent", "date"])
    agg = collections.defaultdict(lambda: collections.Counter())
    for x in rows:
        dm = x["dimensions"]; n = x["count"]
        cc, ip, ua = dm.get("clientCountryName") or "??", dm.get("clientIP") or "", dm.get("userAgent") or ""
        cls = classify(ua, ip)
        agg[cls][cc] += n
    # 重新用 IP 粒度查询（带路径维度，用于真人/扫描器判定）：
    # 同一 IP 的所有请求路径聚合后判定——看过内容页 = 真人；只扫 wp-*/xmlrpc/php = 扫描器。
    iprows = query_adaptive(f'{f},clientRequestHTTPHost_in:[{hosts}]',
                            ["clientCountryName", "clientIP", "userAgent", "clientRequestPath"], limit=4000)
    # 按 IP 聚合路径集合
    ip_paths = collections.defaultdict(set)   # ip -> set(path)
    ip_meta = {}                               # ip -> (cc, ua)
    ip_req = collections.Counter()             # ip -> total requests
    for x in iprows:
        dm = x["dimensions"]; n = x["count"]
        cc = dm.get("clientCountryName") or "??"
        ip = dm.get("clientIP") or ""
        ua = dm.get("userAgent") or ""
        path = dm.get("clientRequestPath") or "/"
        if ip not in ip_meta:
            ip_meta[ip] = (cc, ua)
        ip_paths[ip].add(path)
        ip_req[ip] += n
    # 判定每个 IP
    uniq = collections.defaultdict(set)   # cls -> set((ip,cc))
    per_cc = collections.defaultdict(set)  # cc -> set(ip)  真人
    per_cc_req = collections.Counter()     # 真人请求
    for ip, paths in ip_paths.items():
        cc, ua = ip_meta[ip]
        n = ip_req[ip]
        # 先按 UA/IP 前缀硬排除（自家 + 已知爬虫 UA）
        base = classify(ua, ip)
        if base != "human":
            uniq[base].add((ip, cc))
            continue
        # 路径行为判定
        hit_content = any(any(p.startswith(cp) for cp in MARKERS["content_paths"]) for p in paths)
        hit_scan = any(any(sp in p for sp in MARKERS["scan_paths"]) for p in paths)
        has_rum = any("/cdn-cgi/rum" in p for p in paths)
        if has_rum:
            cls = "human"  # CF 浏览器测量信标，真人浏览器铁证
        elif hit_scan and not hit_content:
            cls = "scanner"  # 只扫漏洞路径
        elif hit_content:
            cls = "human"  # 看过内容页
        elif n >= 200:
            cls = "suspect"  # 高频但没看内容——监控/抓取，不算真人
        else:
            cls = "human"  # 路过访客（只访问首页/少数正常页），保留
        uniq[cls].add((ip, cc))
        if cls == "human":
            per_cc[cc].add(ip)
            per_cc_req[cc] += n
    # 页面榜从真人 IP 的路径聚合（避免机器人路径混入）
    page_agg = collections.Counter()
    for ip, paths in ip_paths.items():
        cc, ua = ip_meta[ip]
        base = classify(ua, ip)
        if base != "human":
            continue
        hit_content = any(any(p.startswith(cp) for cp in MARKERS["content_paths"]) for p in paths)
        hit_scan = any(any(sp in p for sp in MARKERS["scan_paths"]) for p in paths)
        has_rum = any("/cdn-cgi/rum" in p for p in paths)
        if has_rum or hit_content:
            # 真人：该 IP 访问过的每个路径按请求数累加
            for p in paths:
                if any(sp in p for sp in MARKERS["scan_paths"]):
                    continue
                if p.startswith("/cdn-cgi/") or p.startswith("/api/"):
                    continue
                page_agg[p] += 1  # 每个 IP 对每页计 1 次（近似"人次"）
    return {
        "date": d,
        "requests_total": sum(x["count"] for x in rows),
        "by_type": {cls: sum(agg[cls].values()) for cls in ["human", "bot", "own", "script", "other", "empty"]},
        "unique_human_ips": len(uniq["human"]),
        "unique_bot_ips": len(uniq["bot"]),
        "unique_own_ips": len(uniq["own"]),
        "unique_scanner_ips": len(uniq.get("scanner", set())),
        "unique_suspect_ips": len(uniq.get("suspect", set())),
        "countries": {cc: {"ips": len(s), "requests": per_cc_req[cc]} for cc, s in per_cc.items()},
        "top_pages": page_agg.most_common(20),
    }
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--start", help="起始日期 YYYY-MM-DD（默认：今天往前 days 天）")
    args = ap.parse_args()
    load_env()
    os.makedirs(DATA_DIR, exist_ok=True)

    today = datetime.date.today()
    start = datetime.date.fromisoformat(args.start) if args.start else today - datetime.timedelta(days=args.days - 1)
    days = [(start + datetime.timedelta(days=i)).isoformat() for i in range((today - start).days + 1)]

    # 每个日期先读已有快照，缺的才现查（CF 只留 30 天，早于 30 天用缓存）
    snapshots = {}
    for d in sorted(days):
        p = os.path.join(DATA_DIR, f"traffic-{d}.json")
        if os.path.exists(p):
            try:
                snapshots[d] = json.load(open(p, encoding="utf-8"))
                continue
            except Exception:
                pass
        if d < (today - datetime.timedelta(days=29)).isoformat():
            continue  # 超过 CF 留存，跳过
        print("fetch", d, flush=True)
        try:
            snap = fetch_day(d)
            # 空数据日（UTC 还没到 / CF 未出数）：不写盘，避免 0 数据污染趋势
            if snap["requests_total"] == 0:
                print("  EMPTY(跳过)", d, flush=True)
                continue
            snapshots[d] = snap
            json.dump(snap, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        except Exception as e:
            print("  ERR", d, e, flush=True)

    # 全国列表（含新增标记）
    all_cc = set()
    for s in snapshots.values():
        all_cc |= set(s["countries"].keys())
    # 汇总近 30 天
    last30 = [s for d, s in sorted(snapshots.items())[-30:]]
    total_human_ips = set()
    cc_stats = {cc: {"ips": 0, "requests": 0} for cc in all_cc}
    daily = []
    for s in last30:
        daily.append({"date": s["date"], "human_ips": s["unique_human_ips"],
                      "human_req": sum(v["requests"] for v in s["countries"].values()),
                      "bot_ips": s["unique_bot_ips"], "own_ips": s["unique_own_ips"]})
    latest = None
    for d in reversed(sorted(snapshots.keys())):
        s = snapshots[d]
        if s.get("requests_total", 0) > 0:
            latest = s
            break
    if latest is None:
        sys.exit("没有任何有数据的快照")
    prev = None
    for d in reversed(sorted(snapshots.keys())):
        if d < latest["date"] and snapshots[d].get("requests_total", 0) > 0:
            prev = snapshots[d]; break
    new_cc = set(latest["countries"].keys()) - (set(prev["countries"].keys()) if prev else set())

    # ---- 全期累计（上线以来 = CF 可查最远 30 天）+ 近 7 天累计 ----
    def add_days(snaps, n):
        """把最近 n 个有数据的快照累加：页面请求、国家请求、总量。IP 数不跨天相加。"""
        recent = sorted(snaps.values(), key=lambda s: s["date"])[-n:]
        page_tot = collections.Counter()
        cc_req = collections.Counter()
        human_req = 0
        bot_req = 0
        own_req = 0
        days = 0
        for s in recent:
            days += 1
            for p, c in s.get("top_pages", []):
                page_tot[p] += c
            for cc, v in s.get("countries", {}).items():
                cc_req[cc] += v["requests"]
            human_req += sum(v["requests"] for v in s["countries"].values())
            bot_req += s["by_type"].get("bot", 0)
            own_req += s["by_type"].get("own", 0)
        return {
            "days": days,
            "page_tot": page_tot.most_common(30),
            "cc_req": cc_req.most_common(60),
            "human_req": human_req,
            "bot_req": bot_req,
            "own_req": own_req,
        }

    all30 = add_days(snapshots, 999)
    last7 = add_days(snapshots, 7)

    agg = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "latest_date": latest["date"],
        "latest_human_ips": latest["unique_human_ips"],
        "latest_scanner_ips": latest.get("unique_scanner_ips", 0),
        "latest_suspect_ips": latest.get("unique_suspect_ips", 0),
        "latest_countries": len(latest["countries"]),
        "new_countries": sorted(new_cc),
        "latest_by_type": latest["by_type"],
        "prev_human_ips": prev["unique_human_ips"] if prev else None,
        "cc": latest["countries"],
        "daily": daily[-30:],
        "top_pages": latest.get("top_pages", []),
        # 累计账
        "total_days": all30["days"],
        "total_page_tot": all30["page_tot"],
        "total_cc_req": all30["cc_req"],
        "total_human_req": all30["human_req"],
        "total_bot_req": all30["bot_req"],
        "total_own_req": all30["own_req"],
        "total_cc_count": len(all30["cc_req"]),
        "d7_days": last7["days"],
        "d7_page_tot": last7["page_tot"],
        "d7_cc_req": last7["cc_req"],
        "d7_human_req": last7["human_req"],
    }
    json.dump(agg, open(os.path.join(DATA_DIR, "aggregated.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    render(agg)
    print("OK ->", INDEX)

WORLD = os.path.join(DATA_DIR, "world.geojson")
CN_NAMES = json.load(open(os.path.join(DATA_DIR, "cn_names.json"), encoding="utf-8"))

def cname(code):
    return CN_NAMES.get(code) or code

# ---------- 世界地图 SVG 渲染（等距圆柱投影，预渲染，无外链） ----------
def _proj(lon, lat):
    """lon/lat 度 → x/y（等距圆柱）。返回 0..1100 × 0..500 范围"""
    x = (lon + 180) / 360.0 * 1100
    y = (90 - lat) / 180.0 * 470
    return x, y

def _path_d(geom):
    """把 GeoJSON geometry 转成 SVG path d 字符串（只处理 Polygon / MultiPolygon）"""
    if geom["type"] == "Polygon":
        polys = [geom["coordinates"]]
    elif geom["type"] == "MultiPolygon":
        polys = geom["coordinates"]
    else:
        return ""
    d_parts = []
    for poly in polys:
        # poly[0] 是外环，其余是洞（简单起见洞也画成子路径，用 fill-rule=evenodd 剔除）
        for ring in poly:
            pts = ["%.1f,%.1f" % _proj(c[0], c[1]) for c in ring]
            if pts:
                d_parts.append("M" + "L".join(pts) + "Z")
    return " ".join(d_parts)

def render_map_svg(cc_data, new_countries):
    """cc_data: {CC: {"ips": n, "requests": m}} → SVG 字符串"""
    world = json.load(open(WORLD, encoding="utf-8"))
    name_by_id = {f["id"]: f.get("name") or "" for f in world["features"]}
    maxips = max((v["ips"] for v in cc_data.values()), default=1) or 1
    # 色阶：克莱因蓝深浅
    def color(n):
        if n <= 0: return "#e8e6df"
        t = n / maxips
        # 蓝色渐变：#dbe4f5 → #002FA7
        r = 0x00 + int((0xDB - 0x00) * (1 - t) ** 1.4)
        g = 0x2F + int((0xE4 - 0x2F) * (1 - t) ** 1.4)
        b = 0xA7 + int((0xF5 - 0xA7) * (1 - t) ** 1.4)
        return "#%02x%02x%02x" % (r, g, b)
    nf = set(new_countries)
    parts = []
    for f in world["features"]:
        cid = f["id"]
        dn = cc_data.get(cid)
        fill = color(dn["ips"]) if dn else "#e8e6df"
        stroke = "#c0392b" if cid in nf else "#fff"
        sw = 1.6 if cid in nf else 0.7
        tip = f"{cname(cid)} {name_by_id.get(cid,'')} ({cid})".strip()
        if dn: tip += f"\n累计请求 {dn['requests']}"
        parts.append(
            f'<path d="{_path_d(f["g"])}" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="{sw}" fill-rule="evenodd"><title>{tip}</title></path>'
        )
    svg = (
        '<svg viewBox="40 40 1100 470" xmlns="http://www.w3.org/2000/svg" role="img" '
        'style="width:100%;height:auto;background:#faf8f2;border-radius:10px;border:1px solid #e7e3da">'
        + "".join(parts) + "</svg>"
    )
    return svg

def render(a):
    mk = MARKERS["bot_ua_tokens"]
    shf = MARKERS["suspicious_high_freq"]
    # 地图用累计账：上线以来所有访问过的国家，请求越多颜色越深
    map_cc = {cc: {"ips": c, "requests": c} for cc, c in a["total_cc_req"]}
    map_svg = render_map_svg(map_cc, a["new_countries"])
    cc_rows = "".join(
        f"<tr><td class=cc>{cname(cc)} <span class=code>{cc}</span></td><td>{v['ips']}</td><td>{v['requests']}</td><td>{'<span class=new>新</span>' if cc in a['new_countries'] else ''}</td></tr>"
        for cc, v in sorted(a["cc"].items(), key=lambda kv: -kv[1]["ips"])
    )
    _dr = lambda d: f"<tr><td>{d['date']}</td><td>{d['human_ips']}</td><td>{d['human_req']}</td><td>{d['bot_ips']}</td></tr>"
    _d = list(reversed(a["daily"]))
    daily_rows_7 = "".join(_dr(d) for d in _d[:7])
    _trend_all = "".join(_dr(d) for d in _d[7:])
    if _trend_all:
        daily_rows_7 += (f'<tr class=more-tr><td colspan=4><details><summary>展开更早 {len(a["daily"][:-7])} 天</summary>'
                         f'<table class=inner><tr><th>日期</th><th>真人IP</th><th>真人请求</th><th>爬虫IP</th></tr>{_trend_all}</table></details></td></tr>')
    pages = "".join(f"<tr><td class=pg>{p[0][:80]}</td><td>{p[1]}</td></tr>"
                    for p in a.get("top_pages", []))
    # 累计账表（条形比例 + Top10 折叠）
    def _rank_block(items, is_cc=False):
        if not items:
            return "<tr><td colspan=3>暂无</td></tr>"
        maxc = items[0][1] or 1
        def row(k, v):
            cls = "cc" if is_cc else "pg"
            name = f"{cname(k)} <span class=code>{k}</span>" if is_cc else k
            return (f'<tr><td class="{cls}">{name}</td>'
                    f'<td class=barw><div class=bar style="width:{max(3, int(v/maxc*100))}%"></div></td>'
                    f'<td class=num>{v}</td></tr>')
        top = "".join(row(k, v) for k, v in items[:10])
        rest = items[10:]
        if rest:
            more = "".join(row(k, v) for k, v in rest)
            top += (f'<tr class=more-tr><td colspan=3>'
                    f'<details><summary>还有 {len(rest)} 项 · 点击展开</summary>'
                    f'<table class=inner><tbody>{more}</tbody></table></details></td></tr>')
        return top
    total_page_rows = _rank_block(a["total_page_tot"])
    d7_page_rows = _rank_block(a["d7_page_tot"])
    total_cc_rows = _rank_block(a["total_cc_req"], is_cc=True)
    b = a["latest_by_type"]
    total = sum(b.values()) or 1
    human_req = sum(v["requests"] for v in a["cc"].values())
    html = f"""<!doctype html><html lang=zh-CN><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>GYREAD 真人访客面板 · {a["latest_date"]}</title>
<style>
:root{{--nk:#0A2540;--blue:#002FA7;--cream:#FAF8F2;--ink:#2a2a2a;--mut:#8a93a3}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--cream);color:var(--nk);font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Songti SC",serif;padding:32px 20px 64px}}
.wrap{{max-width:960px;margin:0 auto}}
h1{{font-size:22px;font-weight:800;letter-spacing:.02em}}
h1 .y{{color:var(--blue);font-weight:900}}
.sub{{color:var(--mut);font-size:12px;margin:4px 0 24px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:#fff;border:1px solid #e7e3da;border-radius:10px;padding:14px 16px}}
.card .n{{font-size:26px;font-weight:800;color:var(--blue)}}
.card .t{{font-size:12px;color:var(--mut);margin-top:2px}}
.card.new .n{{color:#c0392b}}
.card .tag{{display:inline-block;font-size:10px;background:#c0392b;color:#fff;border-radius:4px;padding:1px 6px;margin-top:4px}}
h2{{font-size:15px;font-weight:700;margin:28px 0 10px;color:var(--nk);border-left:3px solid var(--blue);padding-left:8px}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e7e3da;border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid #f0ede5;font-size:13px}}
th{{background:#f6f4ee;font-weight:600;color:var(--mut)}}
tr:last-child td{{border-bottom:none}}
.cc{{font-weight:700}}
.code{{color:var(--mut);font-weight:400;font-size:11px;margin-left:4px;font-family:ui-monospace,Menlo,monospace}}
.new{{color:#c0392b;font-weight:700}}
.pg{{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}}
.foot{{color:var(--mut);font-size:11px;margin-top:32px;line-height:1.9}}
.pill{{display:inline-block;background:#eef1f7;color:var(--blue);border-radius:20px;padding:2px 10px;font-size:12px;margin-right:6px}}
.mapwrap{{background:#fff;border:1px solid #e7e3da;border-radius:10px;padding:10px}}
.mapwrap path{{transition:fill .2s}}
.mapwrap path:hover{{fill:#ffb4a2 !important}}
.num{{text-align:right;font-variant-numeric:tabular-nums;font-weight:600;white-space:nowrap}}
.barw{{width:36%}}
.bar{{height:8px;border-radius:4px;background:var(--blue);opacity:.22;min-width:3%}}
.more-tr td{{padding:0!important}}
.more-tr summary{{cursor:pointer;padding:8px 12px;font-size:12px;color:var(--mut);background:#f6f4ee}}
.more-tr details{{border-top:1px solid #f0ede5}}
table.inner{{border:none;border-radius:0;width:100%;table-layout:fixed}}
table.inner td{{border-bottom:1px solid #f0ede5;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
table{{table-layout:fixed}}
.pg{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.trenddet summary{{cursor:pointer;padding:6px 0;font-size:13px;color:var(--mut)}}
</style></head><body><div class=wrap>
<h1><span class=y>GYREAD</span> · 真人访客面板</h1>
<div class=sub>数据源：Cloudflare GraphQL（账户级） · 已剔除自家监控（gyread-monitor / probe-drift / 222.209.110-109）与已知爬虫UA · UTC 日界 · 生成于 {a["generated_at"]}</div>

<div class=cards>
 <div class=card><div class=n>{a["latest_human_ips"]}</div><div class=t>最新一天真人访客（独立IP）{f'"　较前一日 {a["latest_human_ips"]-(a["prev_human_ips"] or 0):+d}"' if a["prev_human_ips"] is not None else ""}</div></div>
 <div class=card><div class=n>{human_req}</div><div class=t>当天真人页面请求</div></div>
 <div class=card><div class=n>{a["latest_countries"]}</div><div class=t>覆盖国家/地区</div></div>
 <div class=card class="{'new' if a['new_countries'] else ''}"><div class=n>{len(a['new_countries'])}</div><div class=t>新增国家{('<div class=tag>' + ' · '.join(a['new_countries']) + '</div>') if a['new_countries'] else ''}</div></div>
 <div class=card><div class=n>{b.get('bot',0)}</div><div class=t>爬虫请求（不计入上面）</div></div>
 <div class=card><div class=n>{a["latest_scanner_ips"]}</div><div class=t>扫描器 IP（已剔除）</div></div>
 <div class=card><div class=n>{a["latest_suspect_ips"]}</div><div class=t>疑似高频 IP（未计入真人）</div></div>
</div>

<h2>世界地图 · 上线以来访客足迹（累计 {a["total_cc_count"]} 个国家/地区）</h2>
<div class=mapwrap>{map_svg}</div>
<div class=sub style="margin-top:6px">颜色越深 = 上线以来累计请求越多　·　<span style="color:#c0392b">红色描边</span> = 最近一天新出现　·　悬停国家查看详情</div>

<h2>国家 / 地区分布（最新一天 · 真人独立 IP）</h2>
<div class=cards style="margin-bottom:8px">
<span class=pill>爬虫UA名单已剔除 {len(mk)} 类</span><span class=pill>自家监控单列</span><span class=pill>高频单IP(>{shf}/天)需人工看</span>
</div>
<table><tr><th>国家</th><th>独立IP数</th><th>请求数</th><th></th></tr>
{cc_rows or "<tr><td colspan=4>暂无数据</td></tr>"}
</table>

<h2>上线以来累计（{a["total_days"]} 天）</h2>
<div class=cards>
 <div class=card><div class=n>{a["total_human_req"]:,}</div><div class=t>真人页面请求（累计）</div></div>
 <div class=card><div class=n>{a["total_cc_count"]}</div><div class=t>累计覆盖国家/地区</div></div>
 <div class=card><div class=n>{a["total_bot_req"]:,}</div><div class=t>爬虫请求（不计入）</div></div>
 <div class=card><div class=n>{a["total_own_req"]:,}</div><div class=t>自家监控（不计入）</div></div>
</div>

<h2>页面总访问榜（上线以来 · 真人请求）</h2>
<table><tr><th>路径</th><th>占比</th><th>请求</th></tr>{total_page_rows}</table>

<h2>国家累计榜（上线以来 · 真人请求）</h2>
<table><tr><th>国家</th><th>占比</th><th>请求</th></tr>{total_cc_rows}</table>

<h2>近 7 天页面访问</h2>
<table><tr><th>路径</th><th>占比</th><th>请求</th></tr>{d7_page_rows}</table>

<h2>每日趋势（真人独立 IP / 请求 · 最近 7 天，点开展开全部）</h2>
<details class=trenddet><summary>最近 7 天</summary>
<table><tr><th>日期</th><th>真人IP</th><th>真人请求</th><th>爬虫IP</th></tr>{daily_rows_7}</table>
</details>

<div class=foot>口径说明：真人 = 独立 IP（浏览器 UA，非自家监控、非已知爬虫）。请求数含静态资源。<br>
新增国家 = 与最近一个已有数据日对比。<br>
机器人/爬虫：AhrefsBot、DotBot、Googlebot-Image、Twitterbot 等已剔除；伪装成浏览器的抓取器会留在“真人”里，单个 IP 单日高频（>{shf} 请求）需人工复核。<br>
本文件为本地生成产物，不公开、不进 git 仓库。</div>
</div></body></html>"""
    open(INDEX, "w", encoding="utf-8").write(html)

if __name__ == "__main__":
    main()