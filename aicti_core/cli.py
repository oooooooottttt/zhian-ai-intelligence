from __future__ import annotations

import argparse
import csv
import json
import logging
from pathlib import Path
import sys

from aicti_monitor.config import DEFAULT_CONFIG, load_sources
from aicti_monitor.runner import Monitor
from .gateway import ModelGateway, ModelError
from .service import Application
from .store import CoreStore

ROOT = Path(__file__).resolve().parent.parent

def read_inventory(path):
    if path.stat().st_size > 1_000_000:
        raise ValueError("Inventory file too large")
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        return value["assets"] if isinstance(value,dict) and set(value)=={"assets"} else value
    with path.open(encoding="utf-8-sig",newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        for key in ("exposed","authenticated"):
            if key in row:
                value = row[key].strip().lower()
                if value not in {"","unknown","null","true","false"}:
                    raise ValueError("CSV conditions must be true/false/unknown")
                row[key] = None if value in {"","unknown","null"} else value=="true"
        if "capabilities" in row:
            row["capabilities"] = json.loads(row["capabilities"] or "{}")
    return rows

def main(argv=None):
    parser = argparse.ArgumentParser(description="AI 安全知识情报系统")
    parser.add_argument("--db",type=Path,default=ROOT/".data"/"monitor.sqlite3")
    parser.add_argument("--config",type=Path,default=DEFAULT_CONFIG)
    parser.add_argument("--model",help="已安装的本地 Ollama 模型名称；默认仅事实查询")
    parser.add_argument("--embedding-model",help="已安装的本地 Ollama 向量模型名称；可选")
    parser.add_argument("--provider",choices=("facts","ollama","deepseek","mock"),help="事实、本地、官方 DeepSeek 或明确标注的离线 Mock")
    parser.add_argument("--reasoning-effort",choices=("none","low","high","max"),default="none")
    parser.add_argument("--model-url",default="http://127.0.0.1:11434")
    sub = parser.add_subparsers(dest="command",required=True)
    serve_parser = sub.add_parser("serve",help="启动本机系统")
    serve_parser.add_argument("--demo",action="store_true",help="独立虚构演示，无网络采集")
    serve_parser.add_argument("--replay-demo",action="store_true",help="演示公告新增修订以重演流程，保留原历史；需 --demo")
    serve_parser.add_argument("--no-collect",action="store_true",help="读取已有真实情报，不启动网络采集")
    serve_parser.add_argument("--port",type=int,default=8849)
    sub.add_parser("process",help="处理已有情报和清单")
    sub.add_parser("status",help="本地运行状态")
    ask_parser = sub.add_parser("ask",help="基于现有证据查询")
    ask_parser.add_argument("question")
    ask_parser.add_argument("--session-id")
    import_parser = sub.add_parser("import-assets",help="导入授权资产清单 JSON/CSV")
    import_parser.add_argument("path",type=Path)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    try:
        demo = args.command == "serve" and args.demo
        if args.command=="serve" and args.replay_demo and not demo:
            raise ValueError("Replay is restricted to fictional demo")
        database = ROOT/".data"/"system-demo.sqlite3" if demo else args.db
        if not demo and "demo" in database.name.lower():
            raise ValueError("Demo data needs isolation")
        store = CoreStore(database)
        if not demo:
            with store.connection() as db:
                if db.execute("SELECT 1 FROM observations WHERE source_id LIKE 'demo-%' LIMIT 1").fetchone():
                    raise ValueError("Fictional database cannot be used for real collection")
        else:
            from .demo import seed_demo,default_assets
            seed_demo(store.monitor_store)
            if args.replay_demo:
                from .demo import replay_demo
                replay_demo(store.monitor_store)
            if not store.snapshot(demo=True)["assets"]:
                store.import_assets(default_assets())
        sources = load_sources(args.config)
        if not demo:
            from .catalog_ingest import seed_catalog
            seed_catalog(store.monitor_store)
        provider = args.provider or ("ollama" if args.model or args.embedding_model else "facts")
        if provider=="deepseek":
            if args.embedding_model:
                raise ValueError("DeepSeek chat is not an embedding endpoint")
            from .cloud_gateway import DeepSeekGateway
            gateway = DeepSeekGateway(model=args.model or "deepseek-v4-pro",reasoning_effort=args.reasoning_effort)
        elif provider=="mock":
            from .model_settings import make_gateway
            gateway = make_gateway(provider,model=args.model,reasoning_effort=args.reasoning_effort)
            if args.embedding_model:
                raise ValueError("Mock does not use a real embedding model")
        elif provider=="facts":
            if args.model or args.embedding_model or args.reasoning_effort!="none":
                raise ValueError("Facts mode has no model")
            gateway = None
        else:
            if args.reasoning_effort!="none":
                raise ValueError("Local reasoning settings are not implemented")
            gateway = ModelGateway(args.model_url,args.model,timeout=8)
            if args.embedding_model:
                gateway = gateway.with_embedding_model(args.embedding_model)
        app = Application(store,sources,Monitor(store.monitor_store,sources),gateway=gateway,demo=demo,
            collect=args.command=="serve" and not args.no_collect and not demo)
        if args.command == "serve":
            from .web import serve
            if not 1 <= args.port <= 65535:
                raise ValueError("Invalid port")
            serve(app,args.port)
        elif args.command == "process":
            print(json.dumps(app.process(),ensure_ascii=False,indent=2))
        elif args.command == "status":
            print(json.dumps(app.system(),ensure_ascii=False,indent=2))
        elif args.command == "import-assets":
            print(json.dumps(app.import_assets(read_inventory(args.path)),ensure_ascii=False,indent=2))
            app.process()
        elif args.command == "ask":
            app.process()
            print(json.dumps(app.ask(args.question,args.session_id),ensure_ascii=False,indent=2))
    except KeyboardInterrupt:
        return 0
    except (ValueError,TypeError,OSError,ModelError):
        print("无法完成操作：请检查本地配置、输入格式、模型名称或端口。",file=sys.stderr)
        return 2
    return 0
