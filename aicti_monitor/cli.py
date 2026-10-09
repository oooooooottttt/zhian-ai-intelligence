from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
import time

from .config import DEFAULT_CONFIG, load_sources
from .runner import Monitor
from .storage import Store

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / ".data" / "monitor.sqlite3"


def main(argv=None):
    parser = argparse.ArgumentParser(description="AI 安全情报 · 监测模块")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="来源配置文件")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="实时数据库路径")
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect", help="运行一个有界采集周期")
    collect.add_argument("--source", action="append", help="仅采集指定来源，可重复")
    collect.add_argument("--force", action="store_true", help="检查未到期的来源，仍遵守失败退避")
    sub.add_parser("watch", help="持续运行自动采集调度")
    serve = sub.add_parser("serve", help="打开本地监测页面并启动自动调度")
    serve.add_argument("--port", type=int, default=8849)
    serve.add_argument("--no-collect", action="store_true", help="仅查看已有真实记录")
    serve.add_argument("--demo", action="store_true", help="独立演示库，不访问网络")
    sub.add_parser("status", help="查看来源状态与数据统计")
    export = sub.add_parser("export", help="导出带来源证据的 JSON；遵守各来源许可")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--all", action="store_true", help="包含非 AI 相关条目")
    export.add_argument("--limit", type=int, default=100, help="一次最多 500 条")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        sources = load_sources(args.config)
        demo = args.command == "serve" and args.demo
        database = ROOT / ".data" / "demo.sqlite3" if demo else args.db
        if not demo and database.name == "demo.sqlite3":
            raise ValueError("演示库不能用于真实采集，请选择独立实时数据库")
        store = Store(database)
        if demo:
            from .demo import seed_demo
            seed_demo(store)
        monitor = Monitor(store, sources)
        if args.command == "collect":
            selected = set(args.source) if args.source else None
            if selected and selected - {s.id for s in sources if s.enabled}:
                raise ValueError("指定的来源不存在或尚未启用")
            result = monitor.run_once(selected, force=args.force)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return int(any(r["status"] == "failed" for r in result))
        if args.command == "watch":
            monitor.start()
            try:
                while True:
                    time.sleep(1)
            finally:
                monitor.stop()
        elif args.command == "serve":
            from .web import serve
            if not 1 <= args.port <= 65535:
                raise ValueError("端口无效")
            serve(store, sources, monitor, port=args.port, demo=demo, collect=not (demo or args.no_collect))
        elif args.command == "status":
            print(json.dumps({"stats": store.stats(), "sources": [
                {"id": s.id, "name": s.name, "enabled": s.enabled, **store.get_source_state(s.id)} for s in sources
            ]}, ensure_ascii=False, indent=2))
        elif args.command == "export":
            records = store.list_records(limit=args.limit, include_non_ai=args.all)
            payload = {"notice": "保留来源署名与使用条件。导出许可不扩展至链接网页或论文全文。",
                       "records": records}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"已导出 {len(records)} 条记录。")
    except KeyboardInterrupt:
        return 0
    except (ValueError, TypeError, OSError):
        # Do not echo unknown exception text that may contain a credentialed URL.
        print("无法启动或完成操作：请检查配置、参数、端口和本地文件权限。", file=sys.stderr)
        return 2
    return 0
