"""Local-only dashboard. External text is rendered through DOM textContent."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
from urllib.parse import parse_qs, urlsplit


PAGE = r'''<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI 安全情报 · 监测台</title>
<style nonce="__NONCE__">
:root{color-scheme:light;--bg:#f4f5f0;--ink:#1b2d29;--muted:#62736c;--line:#dce3da;--accent:#15644d}
header .pill{color:var(--ink)}.spaced{margin-top:20px}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,-apple-system,sans-serif}
header{background:#183f34;color:white;padding:30px max(5vw,20px)}header .top{display:flex;justify-content:space-between;align-items:center;gap:16px}h1{font-size:30px;margin:4px 0}p{margin:5px 0}.eyebrow{font-size:12px;letter-spacing:.12em;color:#bfd9ca}.subtitle{color:#d1e3d8}
main{max-width:1350px;margin:auto;padding:24px}.banner{padding:12px 18px;border-radius:10px;background:#fff2d2;margin-bottom:18px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}.stat,.panel{background:white;border:1px solid var(--line);border-radius:12px}.stat{padding:17px 20px}.stat strong{display:block;font-size:29px}.muted{color:var(--muted);font-size:13px}.layout{display:grid;grid-template-columns:minmax(0,290px) minmax(0,1fr);gap:20px}.panel{padding:20px;min-width:0;overflow-wrap:anywhere}h2{font-size:18px;margin:0 0 15px}.source{padding:13px 0;border-top:1px solid var(--line)}.source:first-of-type{border-top:0}.source b{font-size:14px}.pill{font-size:12px;padding:3px 8px;border-radius:20px;background:#eef4ed;display:inline-block;margin:3px 3px 0 0}.error{color:#a33620}.filters{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:18px}input,select,button{font:inherit;border-radius:7px;border:1px solid var(--line);padding:8px 12px}input{min-width:140px;flex:1}button{cursor:pointer;background:var(--accent);color:white;border-color:var(--accent)}button:disabled{opacity:.5;cursor:default}button.secondary{color:var(--ink);background:white;border-color:var(--line)}.item{padding:17px 0;border-top:1px solid var(--line)}.item h3{font-size:17px;margin:0 0 7px}.item .title{background:none;border:0;padding:0;color:var(--ink);text-align:left;font-weight:600}.summary{color:#43564d;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;white-space:pre-wrap}.bottom{display:flex;justify-content:space-between;align-items:center;margin-top:14px}a{color:var(--accent)}.empty{padding:32px 0;color:var(--muted)}dialog{border:1px solid var(--line);border-radius:12px;width:min(820px,94vw);max-height:90vh;overflow:auto;padding:26px;color:var(--ink)}dialog::backdrop{background:#17382b70}.close{float:right}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}.evidence{padding:14px 0;border-top:1px solid var(--line)}.smalltitle{font-size:14px;font-weight:600;margin-top:18px}.status{font-size:12px;color:#d1e3d8}.run{font-size:13px;padding:8px 0;border-top:1px solid var(--line)}.notice{font-size:12px;color:var(--muted);margin-top:20px}#message{min-height:24px;margin:6px 0}.detail-title{padding-right:40px}
@media(max-width:800px){.layout{grid-template-columns:minmax(0,1fr)}.stats{grid-template-columns:repeat(2,1fr)}header .top{align-items:start;flex-direction:column}main{padding:16px}}
</style>
<header><div class="top"><div><div class="eyebrow">AI SECURITY INTELLIGENCE</div><h1>让关键安全信息持续汇聚</h1><p class="subtitle">漏洞公告 · 研究论文 · 安全订阅</p></div><div><div id="mode" class="pill"></div><p id="clock" class="status">正在加载监测状态…</p></div></div></header>
<main><div id="demo" class="banner" hidden>离线演示：所有条目均为虚构示例，不代表真实漏洞或论文；演示库不进行网络采集。</div>
<div class="stats"><div class="stat"><span class="muted">汇聚条目</span><strong id="total">0</strong></div><div class="stat"><span class="muted">AI 相关</span><strong id="ai">0</strong></div><div class="stat"><span class="muted">来源证据</span><strong id="obs">0</strong></div><div class="stat"><span class="muted">已记录版本</span><strong id="rev">0</strong></div></div>
<div class="layout"><aside><section class="panel"><h2>持续监测来源</h2><div id="sources"></div><button id="check" class="secondary">检查定时任务</button><p class="notice">按各来源允许的节奏采集；失败后等待重试，恢复后接续未完成的数据。</p></section><section class="panel spaced"><h2>近期采集</h2><div id="runs"></div></section></aside>
<section class="panel"><h2>情报动态</h2><form id="filters" class="filters"><input id="q" aria-label="搜索情报" placeholder="搜索组件、标题或漏洞编号"><select id="kind" aria-label="类型"><option value="">全部类型</option><option value="vulnerability">漏洞公告</option><option value="paper">研究论文</option><option value="article">订阅动态</option><option value="standard">标准</option><option value="policy">政策</option></select><select id="scope" aria-label="相关性"><option value="0">AI 相关</option><option value="1">全部采集结果</option></select><button>搜索</button></form><div id="message" class="muted" role="status"></div><div id="records"></div><div class="bottom"><button id="prev" class="secondary">上一页</button><span id="pageno" class="muted"></span><button id="next" class="secondary">下一页</button></div><p class="notice">相关性由组件名称和安全术语筛选，仅用于整理监测信息。查看原始证据后再判断风险。</p></section></div></main>
<dialog id="detail"><button id="close" class="secondary close">关闭</button><div id="detailbody"></div></dialog>
<script nonce="__NONCE__">
const $=id=>document.getElementById(id), types={vulnerability:'漏洞公告',paper:'研究论文',article:'订阅动态',standard:'标准',policy:'政策'};
let offset=0,lastLength=0;const pageSize=20;
function el(tag,text,cls){let n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n}
function date(x){if(!x)return '暂无';let d=new Date(x);return isNaN(d)?String(x):d.toLocaleString('zh-CN',{hour12:false})}
function link(url,label){let n=el('span',label);try{let u=new URL(url);if(!['https:','http:'].includes(u.protocol)||u.username||u.password)return n;let h=u.hostname.toLowerCase();if(h==='localhost'||h.endsWith('.local')||h.endsWith('.internal')||h==='127.0.0.1'||h==='[::1]')return n;n=el('a',label);n.href=u.href;n.target='_blank';n.rel='noopener noreferrer'}catch{}return n}
async function api(path,options){let r=await fetch(path,options);if(!r.ok)throw Error('页面请求失败，请检查服务状态');return r.json()}
async function status(){let s=await api('/api/status');$('mode').textContent=s.demo?'离线演示':'实时监测';$('demo').hidden=!s.demo;$('clock').textContent=s.busy?'正在采集…':s.collect?'自动监测已开启':'仅查看已有记录';$('total').textContent=s.stats.total_records;$('ai').textContent=s.stats.ai_related_records;$('obs').textContent=s.stats.total_observations;$('rev').textContent=s.stats.total_revisions;$('check').disabled=!s.collect||s.busy;$('sources').replaceChildren();for(let x of s.sources){let n=el('div',undefined,'source');n.append(el('b',x.name));let state=s.demo?'演示模式未联网':!x.enabled?'待启用':x.last_error?'等待重试':x.last_result?.complete===false?'接续采集中':x.last_success_at?'监测中':'等待首次采集';n.append(el('div',state,'pill'));n.append(el('div','最近成功：'+date(x.last_success_at),'muted'));if(x.next_run_at)n.append(el('div','下次检查：'+date(x.next_run_at),'muted'));if(x.last_error)n.append(el('div',x.last_error,'muted error'));n.append(link(x.terms_url,'来源使用条件'));$('sources').append(n)}let runs=await api('/api/runs');$('runs').replaceChildren();for(let x of runs.runs.slice(0,6)){$('runs').append(el('div',x.source_id+' · '+({success:'完成',partial:'待接续',failed:'失败',running:'采集中'}[x.status]||x.status)+'\n'+date(x.started_at),'run'))}if(!runs.runs.length)$('runs').append(el('p','尚无采集记录','muted'))}
async function records(){let p=new URLSearchParams({limit:pageSize,offset,q:$('q').value,kind:$('kind').value,all:$('scope').value});let data=await api('/api/records?'+p);lastLength=data.records.length;$('records').replaceChildren();for(let x of data.records){let n=el('article',undefined,'item'),h=el('h3'),b=el('button',x.title,'title');b.addEventListener('click',()=>detail(x.id).catch(showError));h.append(b);n.append(h);n.append(el('span',types[x.kind]||x.kind,'pill'));if(x.withdrawn)n.append(el('span','来源已撤回','pill error'));n.append(el('div',(x.source_ids||[x.source_id]).join(' · ')+' · 更新 '+date(x.latest_upstream_at||x.updated_at||x.published_at),'muted'));if(x.summary)n.append(el('p',x.summary,'summary'));let foot=el('div',undefined,'bottom');foot.append(el('span',x.observation_count+' 份来源证据 · '+x.revision_count+' 个已记录版本','muted'),link(x.url,'查看原始来源 ↗'));n.append(foot);$('records').append(n)}if(!lastLength)$('records').append(el('div','暂无匹配条目。可以查看全部采集结果，或等待首次采集完成。','empty'));$('pageno').textContent='第 '+(offset/pageSize+1)+' 页';$('prev').disabled=offset===0;$('next').disabled=lastLength<pageSize}
async function detail(id){let x=await api('/api/records/'+id),root=$('detailbody');root.replaceChildren();root.append(el('h2',x.title,'detail-title'));root.append(el('div','首次发现 '+date(x.first_seen_at)+' · 最近采集 '+date(x.last_seen_at),'muted'));root.append(el('p',(x.relevance_reasons||[]).join('；'),'muted'));for(let o of x.observations){let n=el('section',undefined,'evidence');n.append(el('h3',o.metadata?.source_name||o.source_id),el('p','上游编号：'+o.upstream_id),link(o.url,'原始来源 ↗'));n.append(el('p','上游更新：'+date(o.updated_at)+' · 本地采集：'+date(o.last_seen_at),'muted'),el('pre',o.summary));if(o.withdrawn)n.append(el('p','该来源已标记撤回','error'));n.append(el('p','使用范围：'+(o.metadata?.content_scope||'来源条件适用')+' · '+(o.metadata?.license||''),'muted'));if(o.metadata?.attribution)n.append(el('p','署名：'+o.metadata.attribution,'muted'));if(o.metadata?.local_processing)n.append(el('p',o.metadata.local_processing,'muted'));if(o.metadata?.license_url)n.append(link(o.metadata.license_url,'来源许可 ↗'));if(o.metadata?.terms_url)n.append(link(o.metadata.terms_url,'查看使用条件'));if(o.metadata?.disclaimer)n.append(el('p',o.metadata.disclaimer,'muted'));if(o.references?.length){n.append(el('p','参考链接','smalltitle'));for(let u of o.references.slice(0,20)){let p=el('p');p.append(link(u,u));n.append(p)}}n.append(el('p','修订历史','smalltitle'));for(let r of (o.revisions||[]).slice(-30).reverse()){let d=el('details'),s=el('summary','版本 '+r.revision_number+' · 采集 '+date(r.collected_at)+(r.withdrawn?' · 已撤回':''));d.append(s,el('pre',r.summary));n.append(d)}root.append(n)}$('detail').showModal()}
function showError(e){$('message').textContent=e.message}
async function refresh(){try{await status();await records();$('message').textContent=''}catch(e){showError(e)}}
$('filters').addEventListener('submit',e=>{e.preventDefault();offset=0;records().catch(showError)});$('prev').addEventListener('click',()=>{offset=Math.max(0,offset-pageSize);records().catch(showError)});$('next').addEventListener('click',()=>{offset+=pageSize;records().catch(showError)});$('close').addEventListener('click',()=>$('detail').close());$('check').addEventListener('click',async()=>{try{await api('/api/collect',{method:'POST',headers:{'X-Monitor-Token':'__TOKEN__','Content-Type':'application/json'},body:'{}'});$('message').textContent='已唤醒调度，检查到期来源；尚未到期和退避中的来源会继续等待。';await status()}catch(e){showError(e)}});refresh();setInterval(refresh,15000);
</script></html>'''


def make_server(store, sources, monitor, port=8849, demo=False, collect=True):
    token = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    page = PAGE.replace('__NONCE__', nonce).replace('__TOKEN__', token).encode('utf-8')

    class Handler(BaseHTTPRequestHandler):
        def allowed(self):
            actual_port = self.server.server_address[1]
            hosts = {f"127.0.0.1:{actual_port}", f"localhost:{actual_port}"}
            if self.headers.get('Host', '') not in hosts:
                self.reply(403, {"error": "仅允许本机访问"})
                return False
            if self.headers.get('Sec-Fetch-Site') == 'cross-site':
                self.reply(403, {"error": "拒绝跨站访问"})
                return False
            return True

        def reply(self, status, payload, html=False):
            body = payload if html else json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
            self.send_header('Content-Security-Policy', f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self.allowed():
                return
            url = urlsplit(self.path)
            params = parse_qs(url.query)
            def param(name, default=''):
                return params.get(name, [default])[0]
            try:
                if url.path == '/':
                    self.reply(200, page, html=True)
                elif url.path == '/api/status':
                    stats = store.stats()
                    stats.pop('sources', None)
                    rows = []
                    for s in sources:
                        state = store.get_source_state(s.id)
                        rows.append({"id": s.id, "name": s.name, "enabled": s.enabled,
                                     "category": s.category, "terms_url": s.terms_url,
                                     **{k: state.get(k) for k in ('last_success_at', 'last_error', 'next_run_at', 'last_result')}})
                    self.reply(200, {"stats": stats, "sources": rows, "demo": demo,
                                     "collect": collect, "busy": monitor.busy})
                elif url.path == '/api/records':
                    rows = store.list_records(limit=int(param('limit', '20')), offset=int(param('offset', '0')),
                                              query=param('q') or None, kind=param('kind') or None,
                                              source_id=param('source') or None, include_non_ai=param('all') == '1')
                    self.reply(200, {"records": rows})
                elif url.path.startswith('/api/records/'):
                    record = store.get_record(int(url.path.removeprefix('/api/records/')))
                    self.reply(200 if record else 404, record or {"error": "条目不存在"})
                elif url.path == '/api/runs':
                    self.reply(200, {"runs": store.list_runs(limit=20)})
                else:
                    self.reply(404, {"error": "页面不存在"})
            except (ValueError, TypeError):
                self.reply(400, {"error": "查询参数无效"})
            except Exception:
                self.reply(500, {"error": "无法读取本地数据"})

        def do_POST(self):
            if not self.allowed():
                return
            if self.path != '/api/collect' or not collect:
                self.reply(403, {"error": "当前模式未启用采集"})
                return
            expected = f"http://{self.headers.get('Host')}"
            if self.headers.get('Origin') != expected or not secrets.compare_digest(self.headers.get('X-Monitor-Token', ''), token):
                self.reply(403, {"error": "请求来源校验失败"})
                return
            self.reply(202, {"queued": monitor.trigger()})

        def log_message(self, *args):
            # Untrusted paths/queries are never echoed into console logs.
            pass

    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def serve(store, sources, monitor, port=8849, demo=False, collect=True):
    server = make_server(store, sources, monitor, port, demo, collect)
    if collect:
        monitor.start()
    print(f"监测页面：http://127.0.0.1:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        monitor.stop()
        server.server_close()
