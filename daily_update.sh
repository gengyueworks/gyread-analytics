#!/bin/bash
# GYREAD 真人访客面板：每日拉取 + 推送 GitHub
# launchd com.gyread.traffic-dashboard 每天 09:05 触发
set -e
cd "/Volumes/拓展坞 1T2022/2 Codex-Workspace/Codex-Workspace-Main/30-项目-网站/gyread-流量面板"
/Library/Frameworks/Python.framework/Versions/3.11/bin/python3 fetch_traffic.py --days 30
# 有变化才推送
if ! git diff --quiet || ! git diff --cached --quiet; then
  git add -A
  git commit -m "data: $(date +%Y-%m-%d) 流量快照更新"
  GIT_EDITOR=true git pull --rebase origin main 2>/dev/null || true
  git push origin main 2>/dev/null || echo "push failed"
fi
