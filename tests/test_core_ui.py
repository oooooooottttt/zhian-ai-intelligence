"""Offline PAGE contract, injection, import and client-state tests.

Python's standard library checks HTML. When Node is present its built-in VM runs
the *actual* inline script against a minimal DOM and an offline fetch fake. No
web server, browser, network access or third-party JavaScript package is needed.
The integration owner separately verifies real browser layout and server routes.
"""
from __future__ import annotations

from html.parser import HTMLParser
import json
import re
import shutil
import subprocess
import unittest

from aicti_core.ui import PAGE


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.ids: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        self.tags.append((tag, data))
        if "id" in data:
            if data["id"] in self.ids:
                raise AssertionError("Duplicate element ID")
            self.ids[data["id"]] = tag


PARSED = PageParser()
PARSED.feed(PAGE)
SCRIPT = re.search(r'<script nonce="__NONCE__">(.*?)</script>', PAGE, re.S).group(1)
NODE = shutil.which("node")

# A rejecting HTML setter makes accidental unsafe rendering fail immediately.
# This is a behavior harness, not a substitute for browser layout/accessibility QA.
HARNESS = r"""
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
class Node {
 constructor(tag='div'){this.tagName=tag.toUpperCase();this.childNodes=[];this.attributes={};this.events={};this.dataset={};this._text='';this.value='';this.disabled=false;this.hidden=false;this.checked=false;this.open=false;this.scrollTop=0;this.scrollHeight=0;}
 set textContent(v){this._text=String(v);this.childNodes=[];}
 get textContent(){return this._text+this.childNodes.map(n=>n.textContent).join('');}
 set innerHTML(v){throw new Error('Unsafe HTML setter');}
 set outerHTML(v){throw new Error('Unsafe HTML setter');}
 append(...nodes){this.childNodes.push(...nodes);this.scrollHeight=this.childNodes.length;}
 prepend(...nodes){this.childNodes.unshift(...nodes);}
 replaceChildren(...nodes){this._text='';this.childNodes=nodes;}
 setAttribute(k,v){this.attributes[k]=String(v);}
 removeAttribute(k){delete this.attributes[k];}
 addEventListener(k,fn){(this.events[k]??=[]).push(fn);}
 async fire(k,event={}){for(const f of this.events[k]||[])await f(event);}
 focus(){this.focused=true;}
 scrollIntoView(){this.scrolled=true;}
 showModal(){this.open=true;}
 close(){this.open=false;}
 querySelectorAll(selector){const found=[];const tags=selector.split(',').map(s=>s.trim().toUpperCase());function walk(n){for(const c of n.childNodes){if(tags.includes(c.tagName))found.push(c);walk(c);}}walk(this);return found;}
}
const elements=new Map(Object.entries(input.ids).map(([id,tag])=>[id,new Node(tag)]));
const navigation=['chat','overview','knowledge','assets','status','model'].map(view=>{const n=new Node('button');n.dataset.view=view;return n;});
const created=[];
const document={hidden:false,getElementById(id){if(!elements.has(id))throw new Error('Unknown ID: '+id);return elements.get(id);},createElement(tag){const n=new Node(tag);created.push(n);return n;},querySelectorAll(selector){if(selector==='[data-view]')return navigation;return [];}};
let timerId=0;const timers=new Map();
const ctx=vm.createContext({document,window:{addEventListener(){}},URL,URLSearchParams,Date,Map,Set,TextEncoder,AbortController,assert,created,elements,navigation,timers,Node,setTimeout(fn,ms){timers.set(++timerId,{fn,ms});return timerId;},clearTimeout(id){timers.delete(id);},fetch:async()=>{throw new TypeError('Offline fetch');}});
const program=input.script.replace(/\nbindUI\(\);\s*$/,'\n');
new vm.Script(program).runInContext(ctx,{timeout:2000});
Promise.resolve(new vm.Script('(async()=>{'+input.test+'\n})()').runInContext(ctx,{timeout:3000})).then(value=>process.stdout.write(JSON.stringify(value??true))).catch(error=>{process.stderr.write(error.stack);process.exitCode=1;});
"""


class PageContractTests(unittest.TestCase):
    def test_document_is_complete_and_inline_resources_have_nonces(self):
        self.assertTrue(PAGE.startswith("<!doctype html>"))
        self.assertTrue(PAGE.rstrip().endswith("</html>"))
        self.assertIn('<html lang="zh-CN">', PAGE)
        resources = [(tag, attrs) for tag, attrs in PARSED.tags if tag in {"script", "style"}]
        self.assertEqual(len(resources), 2)
        for _, attrs in resources:
            self.assertEqual(attrs.get("nonce"), "__NONCE__")
            self.assertNotIn("src", attrs)
        self.assertEqual(PAGE.count("__NONCE__"), 2)
        self.assertEqual(PAGE.count("__TOKEN__"), 1)
        self.assertFalse(any(tag in {"iframe", "object", "embed", "img", "link"} for tag, _ in PARSED.tags))
        for _, attrs in PARSED.tags:
            self.assertFalse(any(name.startswith("on") for name in attrs))
            self.assertNotIn("style", attrs)

    def test_rendering_does_not_interpret_html_or_model_markdown(self):
        self.assertNotRegex(SCRIPT, r"\b(innerHTML|outerHTML|insertAdjacentHTML|eval)\b")
        self.assertNotIn("document.write", SCRIPT)
        self.assertNotIn("new Function", SCRIPT)
        self.assertNotIn("localStorage", SCRIPT)
        self.assertNotIn("sessionStorage", SCRIPT)
        self.assertIn("textContent", SCRIPT)
        self.assertIn("n.href=href", SCRIPT)
        self.assertEqual(len(re.findall(r"\.href\s*=", SCRIPT)), 1)

    def test_contract_endpoints_token_and_navigation(self):
        for endpoint in ("/api/system", "/api/events/", "/api/evidence/", "/api/sessions/", "/api/assets",
                         "/api/process", "/api/ask", "/api/collect", "/api/demo/withdraw",
                         "/api/entities/confirm", "/api/model", "/api/model/test", "/api/model/clear",
                         "/api/knowledge", "/api/assets/sbom"):
            self.assertIn(endpoint, SCRIPT)
        self.assertIn("['Content-Type']='application/json'", SCRIPT)
        self.assertIn("['X-Monitor-Token']=TOKEN", SCRIPT)
        self.assertIn("expected_generation:event.generation", SCRIPT)
        for view in ("overview", "assets", "chat", "status", "knowledge", "model"):
            self.assertIn("view-" + view, PARSED.ids)
        for tag, attrs in PARSED.tags:
            if "aria-controls" in attrs:
                self.assertIn(attrs["aria-controls"], PARSED.ids)
        for target in re.findall(r"\$\('([^']+)'\)", SCRIPT):
            self.assertIn(target, PARSED.ids)
        self.assertNotIn("setInterval", SCRIPT)

    def test_default_workspace_and_password_settings_are_explicit(self):
        by_id = {attrs["id"]: attrs for _, attrs in PARSED.tags if "id" in attrs}
        self.assertNotIn("hidden", by_id["view-chat"])
        for view in ("overview", "assets", "status", "knowledge", "model"):
            self.assertIn("hidden", by_id["view-" + view])
        self.assertEqual(by_id["model-key"]["type"], "password")
        self.assertEqual(by_id["model-key"]["autocomplete"], "off")
        self.assertNotIn("value", by_id["model-key"])
        self.assertEqual(by_id["cloud-consent"]["type"], "checkbox")
        self.assertIn("deepseek-v4-pro", PAGE)
        self.assertIn("Mock · 离线流程演示（无需 Key）", PAGE)
        self.assertIn("原始清单和内部资产名称留在本机", PAGE)


@unittest.skipUnless(NODE, "Node not available; dynamic browser-script tests skipped")
class ScriptBehaviorTests(unittest.TestCase):
    def js(self, source):
        result = subprocess.run(
            [NODE, "-e", HARNESS],
            input=json.dumps({"script": SCRIPT, "ids": PARSED.ids, "test": source}),
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_script_parses_and_resource_free_url_filter_normalizes_addresses(self):
        self.js(r"""
        for(const value of ['https://github.com/aicti','http://8.8.8.8/','https://example.org/path?q=abc','HTTPS://WWW.EXAMPLE.COM/'])assert.ok(publicURL(value),value);
        const bad=['javascript:alert(1)','data:text/html,a','file:///etc/passwd','//example.org/','/path',
          'https://user:pass@example.org/','https://user@example.org/','https://example.org\\@127.0.0.1/',
          'https://example.org/\npath','https://localhost/','https://localhost./','https://sub.localhost/',
          'https://printer.local/','https://admin.internal/','https://server.lan/','https://admin.home.arpa/',
          'http://127.1/','http://2130706433/','http://0177.0.0.1/','http://0x7f000001/',
          'http://10.1.2.3/','http://172.16.0.1/','http://172.31.255.1/','http://192.168.1.5/',
          'http://169.254.169.254/','http://100.64.0.1/','http://100.127.255.1/',
          'http://0.0.0.0/','http://224.0.0.1/','http://255.255.255.255/','http://198.18.0.1/',
          'http://192.0.2.1/','http://198.51.100.1/','http://203.0.113.1/',
          'http://[::1]/','http://[fc00::1]/','http://[fe80::1]/','http://[::ffff:127.0.0.1]/',
          'https://[2606:4700:4700::1111]/','http://internal/','https://bad..example.org/',
          'https://example.org:99999/'];
        for(const value of bad)assert.equal(publicURL(value),null,value);
        const a=link('https://example.org/','Safe');assert.equal(a.tagName,'A');assert.equal(a.rel,'noopener noreferrer');assert.equal(a.target,'_blank');
        assert.equal(link('http://user:secret@127.0.0.1/','Original').tagName,'SPAN');
        """)

    def test_untrusted_titles_summaries_metadata_and_model_output_are_text(self):
        self.js(r"""
        const payload='<img src=x onerror="globalThis.PWN=1"><script>globalThis.PWN=2</script> [x](javascript:alert(1))';
        state.snapshot={demo:true,knowledge_epoch:1,asset_snapshot_id:1,events:[],assets:[],evidence:[{id:'obs:1:r:1',observation_id:1,revision_number:1,source_id:payload,title:payload,withdrawn:false}]};
        state.connected=true;state.sessionId='safe';state.chats.set('safe',[{question:payload,answer:{answer:payload,mode:'degraded',knowledge_epoch:1,as_of:'2026-10-03T00:00:00Z',entities:[],claims:[{text:payload,evidence_ids:['obs:1:r:1']}],citations:[{evidence_id:'obs:1:r:1',title:payload,source_id:payload,url:'javascript:alert(1)',revision_number:1}],warnings:[payload],trace:[{action:payload}]}}]);
        renderChat();assert.ok($('transcript').textContent.includes(payload));assert.equal(globalThis.PWN,undefined);
        appendEvidence($('evidence-body'),{title:payload,summary:payload,metadata:{attribution:payload,url:'javascript:alert(1)'},references:['http://127.0.0.1/'],url:'javascript:alert(1)'});
        assert.ok($('evidence-body').textContent.includes(payload));assert.equal(globalThis.PWN,undefined);
        assert.equal(created.filter(n=>['SCRIPT','IMG','IFRAME'].includes(n.tagName)).length,0);
        assert.equal(created.filter(n=>n.tagName==='A').length,0);
        """)

    def test_csv_and_tsv_import_preserves_utc_timestamp_and_unknowns(self):
        self.js(r"""
        const csv='\uFEFF资产ID,名称,生态,组件,版本,暴露,认证,清单时间\r\na1,"服务, ""甲"" ",PyPI,vllm,,未知,否,2020-10-03T08:09:10+08:00\r\n';
        const rows=parseTable(csv);assert.equal(rows.length,1);assert.equal(rows[0].name,'服务, "甲"');assert.equal(rows[0].version,'unknown');assert.equal(rows[0].exposed,null);assert.equal(rows[0].authenticated,false);assert.equal(rows[0].observed_at,'2020-10-03T00:09:10.000Z');
        const tsv='asset_id\tname\tecosystem\tcomponent\tversion\texposed\tauthenticated\tobserved_at\tcapabilities\na2\t服务\tPyPI\tvllm\t1.0\t是\tunknown\t2020-10-03T00:00:00Z\trag=true;network=false';
        const a=parseTable(tsv)[0];assert.equal(a.capabilities.rag,true);assert.equal(a.capabilities.network,false);assert.equal(a.authenticated,null);assert.equal(Object.keys(a).sort().join(','),'asset_id,authenticated,capabilities,component,ecosystem,exposed,name,observed_at,version');
        assert.equal(triLabel(null),'未知');assert.equal(versionLabel('unknown'),'版本未知');assert.ok(age('2020-01-01T00:00:00Z',Date.parse('2020-01-03T00:00:00Z')).includes('2 天'));
        """)

    def test_asset_validation_rejects_credentials_arbitrary_fields_duplicate_ids_and_bad_time(self):
        self.js(r"""
        const good={asset_id:'a1',name:'服务',ecosystem:'PyPI',component:'vllm',version:'',exposed:null,authenticated:null,observed_at:'2020-01-01T00:00:00Z',capabilities:{}};
        for(const bad of [{...good,url:'http://10.0.0.1/'},{...good,name:'password=secret'}, {...good,name:'https://u:p@example.org/'}, {...good,script:'alert(1)'}, {...good,capabilities:{exec:true}}, {...good,exposed:'false'}, {...good,observed_at:''}, {...good,observed_at:'2020-01-01T00:00:00'}, {...good,observed_at:'2020-02-30T00:00:00Z'}, {...good,observed_at:'2099-01-01T00:00:00Z'}])assert.throws(()=>validateAssets([bad]));
        assert.throws(()=>validateAssets([good,good]));assert.throws(()=>validateAssets([]));assert.throws(()=>validateAssets(Array.from({length:257},(_,i)=>({...good,asset_id:'a'+i}))));
        assert.throws(()=>parseTable('asset_id,name,ecosystem,component,observed_at,url\na,n,PyPI,vllm,2020-01-01T00:00:00Z,http://example.org'));
        assert.throws(()=>parseTable('asset_id,name,ecosystem,component,observed_at,capabilities\na,n,PyPI,vllm,2020-01-01T00:00:00Z,__proto__=true'));
        assert.throws(()=>parseTable('资产ID,名称,生态,组件,清单时间\na,"未闭合,PyPI,vllm,2020-01-01T00:00:00Z'));
        assert.throws(()=>parseTable('名'.repeat(30000)));assert.throws(()=>parseTri('maybe'));
        const clean=validateAssets([good])[0];assert.equal(clean.version,'unknown');assert.equal(clean.exposed,null);assert.equal(good.version,'');
        """)

    def test_csv_row_limit_and_optional_boolean_capability_boundary(self):
        self.js(r"""
        const head='asset_id,name,ecosystem,component,observed_at\n',rows=Array.from({length:100},(_,i)=>'a'+i+',n,PyPI,vllm,2020-01-01T00:00:00Z');
        assert.equal(parseTable(head+rows.join('\n')).length,100);assert.throws(()=>parseTable(head+rows.concat('extra,n,PyPI,vllm,2020-01-01T00:00:00Z').join('\n')));
        const caps='asset_id,name,ecosystem,component,observed_at,capabilities\na,n,PyPI,vllm,2020-01-01T00:00:00Z,rag=unknown;tools=false';
        const row=parseTable(caps)[0];assert.equal(Object.hasOwn(row.capabilities,'rag'),false);assert.equal(row.capabilities.tools,false);
        assert.throws(()=>parseTable(caps.replace('rag=unknown;tools=false','rag=true;rag=false')));
        """)

    def test_answer_epoch_changes_do_not_claim_error_and_revisions_remain_historical(self):
        self.js(r"""
        const e={id:'obs:1:r:1',observation_id:1,revision_number:1,withdrawn:false}, a={knowledge_epoch:1,asset_snapshot_id:1,policy_generation:1,entities:[3],citations:[{evidence_id:e.id}],claims:[{text:'影响',evidence_ids:[e.id]}]}, s={knowledge_epoch:1,asset_snapshot_id:1,policy_generation:1,evidence:[e],events:[{id:3,status:'ready'}]};
        assert.equal(answerFreshness(a,s).kind,'ok');const epoch=answerFreshness(a,{...s,knowledge_epoch:2});assert.equal(epoch.kind,'warn');assert.ok(!epoch.label.includes('错误'));
        assert.equal(answerFreshness(a,{...s,asset_snapshot_id:2}).kind,'warn');assert.equal(answerFreshness(a,{...s,policy_generation:2}).kind,'warn');
        assert.equal(answerFreshness(a,{...s,evidence:[{...e,withdrawn:true}]}).kind,'bad');
        assert.equal(answerFreshness(a,{...s,evidence:[{...e,id:'obs:1:r:2',revision_number:2}]}).kind,'bad');
        assert.equal(answerFreshness(a,{...s,events:[{id:3,status:'dirty'}]}).kind,'warn');
        assert.equal(a.knowledge_epoch,1);assert.equal(a.citations[0].evidence_id,'obs:1:r:1');
        """)

    def test_claim_citations_are_local_and_unavailable_facts_are_not_current(self):
        self.js(r"""
        state.snapshot={knowledge_epoch:1,demo:false,assets:[],evidence:[{id:'obs:1:r:1',source_id:'A',revision_number:1,withdrawn:false},{id:'obs:2:r:3',source_id:'B',revision_number:3,withdrawn:false}],events:[]};
        state.sessionId='s';state.chats.set('s',[{question:'q',answer:{mode:'facts',answer:'答',knowledge_epoch:1,claims:[{text:'claim A',evidence_ids:['obs:1:r:1']},{text:'claim B',evidence_ids:['obs:2:r:3']}],citations:[],trace:[],entities:[]}}]);renderChat();
        const claims=created.filter(n=>n.className==='claim');assert.equal(claims.length,2);assert.ok(claims[0].textContent.includes('A · r1'));assert.ok(!claims[0].textContent.includes('B · r3'));assert.ok(claims[1].textContent.includes('B · r3'));
        renderDetail({id:3,status:'dirty',title:'更新中',evidence_ids:['obs:1:r:1'],facts:[{predicate:'fix',value:{text:'OLD FIX SENTINEL'}}],assessments:[{asset_id:'OLD ASSET SENTINEL'}]});assert.ok(!$('event-detail').textContent.includes('OLD FIX SENTINEL'));assert.ok(!$('event-detail').textContent.includes('OLD ASSET SENTINEL'));
        """)

    def test_post_requests_use_token_deadline_and_redirect_rejection(self):
        self.js(r"""
        let recorded;fetch=async(path,options)=>{recorded={path,options};return {ok:true,text:async()=>'{"count":1}'};};
        await api('/api/assets',{assets:[]});assert.equal(recorded.options.method,'POST');assert.equal(recorded.options.headers['Content-Type'],'application/json');assert.equal(recorded.options.headers['X-Monitor-Token'],'__TOKEN__');assert.equal(recorded.options.redirect,'error');assert.equal(recorded.options.credentials,'same-origin');assert.ok(recorded.options.signal);assert.equal(timers.size,0);
        fetch=async()=>({ok:false,status:409,text:async()=>'<script>secret</script>'});await assert.rejects(api('/api/process',{}),error=>error.message.includes('资料正在更新')&&!error.message.includes('secret'));
        """)

    def test_failed_asset_submission_preserves_input_and_blocks_duplicate_submission(self):
        self.js(r"""
        state.draft=[{asset_id:'a1',name:'服务',ecosystem:'PyPI',component:'vllm',version:'',exposed:null,authenticated:false,observed_at:'2020-01-01T00:00:00Z',capabilities:{}}];
        let calls=0,release;fetch=async()=>{calls++;await new Promise(resolve=>release=resolve);return {ok:false,status:400};};
        const event={preventDefault(){}};const first=saveAssets(event);await saveAssets(event);assert.equal(calls,1);assert.equal(state.saving,true);release();await first;assert.equal(state.saving,false);assert.equal(state.draft[0].observed_at,'2020-01-01T00:00:00Z');assert.equal(state.draft[0].version,'');assert.equal($('save-assets').disabled,false);
        """)

    def test_refresh_failure_preserves_last_snapshot_and_disables_demo_collection(self):
        self.js(r"""
        const snapshot={demo:true,knowledge_epoch:1,as_of:'2020-01-01T00:00:00Z',events:[],evidence:[],assets:[]};
        fetch=async()=>({ok:true,text:async()=>JSON.stringify({snapshot,jobs:[],model:{enabled:false},monitoring:{collect:true,sources:[]},sessions:[]})});await refresh();assert.equal(state.connected,true);assert.equal($('collect').disabled,true);assert.equal($('demo-banner').hidden,false);assert.ok($('model-badge').textContent.includes('事实模式'));const previous=state.snapshot;
        fetch=async()=>{throw new TypeError('offline');};await refresh();assert.equal(state.snapshot,previous);assert.equal(state.connected,false);assert.equal($('connection-banner').hidden,false);assert.ok($('last-sync').textContent.includes('未核验'));
        """)

    def test_manual_partition_payload_binds_review_generation_and_observation_ids(self):
        self.js(r"""
        state.snapshot={evidence:[{id:'obs:10:r:2',observation_id:10},{id:'obs:20:r:1',observation_id:20},{id:'obs:21:r:1',observation_id:21}]};const event={id:5,status:'quarantined',generation:7,evidence_ids:['obs:10:r:2','obs:20:r:1','obs:21:r:1']};
        const p=partitionPayload(event,{10:1,20:2,21:2},'原始公告描述不同缺陷');assert.equal(p.expected_generation,7);assert.equal(p.event_id,5);assert.equal(JSON.stringify(p.groups),'[[10],[20,21]]');
        assert.throws(()=>partitionPayload(event,{10:1,20:2},'reason'));assert.throws(()=>partitionPayload(event,{10:'',20:2,21:2},'reason'));assert.throws(()=>partitionPayload({...event,status:'ready'},{10:1,20:2,21:2},'reason'));assert.throws(()=>partitionPayload(event,{10:1,20:2,21:2},''));
        """)

    def test_old_answer_arriving_after_withdrawal_remains_historical(self):
        self.js(r"""
        state.snapshot={knowledge_epoch:2,assets:[],events:[{id:1,status:'dirty'}],evidence:[{id:'obs:1:r:2',observation_id:1,revision_number:2,withdrawn:true}]};
        $('question').value='原来的判断？';let release,calls=0;
        const session='a'.repeat(32);fetch=async(path)=>{if(path==='/api/ask'){calls++;await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({answer:'旧回答',session_id:session,mode:'facts',knowledge_epoch:1,as_of:'2020-01-01T00:00:00Z',entities:[1],claims:[{text:'旧结论',evidence_ids:['obs:1:r:1']}],citations:[{evidence_id:'obs:1:r:1',source_id:'A',revision_number:1}]})};}throw new TypeError('offline');};
        const ev={preventDefault(){}};const pending=askQuestion(ev);await askQuestion(ev);assert.equal(calls,1);release();await pending;assert.ok($('transcript').textContent.includes('历史回答'));assert.ok(!$('transcript').textContent.includes('已核验回答快照'));assert.equal(state.chats.get(session)[0].answer.knowledge_epoch,1);
        """)

    def test_polling_is_optional_bounded_and_pauses_when_tab_is_hidden(self):
        self.js(r"""
        let calls=0;fetch=async()=>{calls++;return {ok:true,text:async()=>JSON.stringify({snapshot:{events:[],evidence:[],assets:[],demo:false},jobs:[],monitoring:{sources:[]},sessions:[]})};};
        $('auto-refresh').checked=true;state.polls=0;document.hidden=true;schedulePoll();let timer=[...timers.values()][0];timers.clear();await timer.fn();assert.equal(calls,0);assert.equal(state.polls,0);document.hidden=false;
        for(let i=0;i<30;i++){const t=[...timers.values()][0];assert.equal(t.ms,20000);timers.clear();await t.fn();}
        assert.equal(calls,30);assert.equal(state.polls,30);assert.equal($('auto-refresh').checked,false);assert.equal(timers.size,0);assert.ok($('poll-status').textContent.includes('上限'));
        """)

    def test_historical_evidence_uses_current_flag_and_revision_navigation(self):
        self.js(r"""
        state.snapshot={evidence:[],demo:false};fetch=async()=>({ok:true,text:async()=>JSON.stringify({id:'obs:3:r:2',observation_id:3,revision_number:2,current:false,current_revision_number:4,title:'旧公告',summary:'旧说明',source_id:'A',metadata:{},references:[],url:'https://example.org'})});await openEvidence('obs:3:r:2');assert.equal($('evidence-dialog').open,true);assert.ok($('evidence-body').textContent.includes('历史修订'));assert.ok($('evidence-body').textContent.includes('r1'));assert.ok($('evidence-body').textContent.includes('最新修订 r4'));
        """)

    def test_sensitive_url_query_and_fragment_keys_are_not_clickable(self):
        self.js(r"""
        for(const part of ['?api_key=value','?API-KEY=value','?%74oken=value','?auth_token=value','#access_token=value','?x-amz-signature=value','?password=value','?session_id=value'])assert.equal(publicURL('https://example.org/'+part),null,part);
        assert.ok(publicURL('https://example.org/?q=token%20vulnerability#section'));
        """)

    def test_partition_rejects_any_unresolved_evidence_id(self):
        self.js(r"""
        state.snapshot={evidence:[{id:'obs:1:r:1',observation_id:1}]};const event={id:1,generation:2,status:'quarantined',evidence_ids:['obs:1:r:1','obs:2:r:1']};assert.throws(()=>partitionPayload(event,{1:1},'理由'),error=>error.message.includes('不完整'));
        """)

    def test_refresh_after_withdrawal_is_queued_and_rejects_an_older_inflight_snapshot(self):
        self.js(r"""
        const old={demo:true,knowledge_epoch:1,asset_snapshot_id:1,events:[{id:1,generation:1,status:'ready',title:'旧事件',facts:[{predicate:'fix',value:{text:'OLD CURRENT FIX'}}],assessments:[]}],evidence:[],assets:[]};state.snapshot=old;state.system={};state.connected=true;
        const current={...old,knowledge_epoch:2,events:[{id:1,generation:2,status:'dirty',title:'更新中',facts:[],assessments:[]}]};let calls=0,release;
        fetch=async(path)=>{if(path==='/api/demo/withdraw')return {ok:true,text:async()=>'{"updated":true,"knowledge_epoch":2}'};calls++;if(calls===1){await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({snapshot:old})};}return {ok:true,text:async()=>JSON.stringify({snapshot:current})};};
        const initial=refresh();const mutation=action('withdraw','/api/demo/withdraw',()=> '已撤回');await Promise.resolve();await Promise.resolve();await Promise.resolve();release();await Promise.all([initial,mutation]);
        assert.equal(calls,2);assert.equal(state.snapshot.knowledge_epoch,2);assert.equal(state.snapshot.events[0].status,'dirty');assert.equal(state.requiredEpoch,2);assert.equal(state.pendingCurrent,false);assert.ok(!$('events').textContent.includes('OLD CURRENT FIX'));
        """)

    def test_newer_or_stale_event_detail_never_restores_ready_facts_from_old_snapshot(self):
        self.js(r"""
        const old={id:1,generation:1,status:'ready',title:'旧事件',evidence_ids:[],facts:[{predicate:'fix',value:{text:'OLD FIX'}}],assessments:[]};state.snapshot={knowledge_epoch:1,events:[old],evidence:[],assets:[]};
        fetch=async(path)=>{if(path.startsWith('/api/events/'))return {ok:true,text:async()=>JSON.stringify({...old,generation:2,status:'dirty',stale:true,knowledge_epoch:2,facts:[],assessments:[]})};throw new TypeError('offline');};await selectEvent(1);assert.equal(state.snapshot.events[0].status,'dirty');assert.ok(!$('event-detail').textContent.includes('OLD FIX'));assert.ok($('event-detail').textContent.includes('暂不可用'));assert.equal(state.requiredEpoch,2);
        """)

    def test_refresh_retries_are_bounded_when_server_keeps_returning_stale_data(self):
        self.js(r"""
        state.requiredEpoch=5;state.pendingCurrent=true;let calls=0;fetch=async()=>{calls++;return {ok:true,text:async()=>JSON.stringify({snapshot:{knowledge_epoch:1,events:[],evidence:[],assets:[]}})};};await refresh();assert.equal(calls,3);assert.equal(state.snapshot,null);assert.equal(state.pendingCurrent,true);assert.equal($('connection-banner').hidden,false);
        """)

    def test_all_256_facts_are_rendered_and_internal_fields_are_collapsed(self):
        self.js(r"""
        state.snapshot={assets:[{asset_id:'asset1',name:'推理服务甲'}],evidence:[]};const facts=Array.from({length:255},(_,i)=>({predicate:'fix',status:'valid',value:{description:'修复卡 '+i,score_recomputed:false,scope:'internal_scope'},evidence_ids:[]}));facts.push({predicate:'risk_pattern',status:'candidate',value:{asset_id:'asset1',asset_snapshot_id:5,pattern:'retrieval_content_poisoning',basis:'asset_declared_capabilities',capabilities:{external_documents:true,rag:true},observed_at:'2020-01-01T00:00:00Z',stale:true,confirmed_vulnerability:false},evidence_ids:[]});
        renderDetail({id:1,title:'情报',status:'ready',facts,assessments:[],evidence_ids:[]});const cards=created.filter(n=>n.className==='card');assert.equal(cards.length,256);const risk=cards.find(n=>n.textContent.includes('检索内容投毒'));assert.ok(risk.textContent.includes('推理服务甲'));assert.ok(risk.textContent.includes('声明'));const folded=risk.childNodes.filter(n=>n.tagName==='DETAILS');assert.equal(folded.length,1);assert.ok(folded[0].textContent.includes('清单快照'));assert.ok(!risk.childNodes.filter(n=>n.tagName!=='DETAILS').map(n=>n.textContent).join('').includes('asset_id'));
        const fix=cards.find(n=>n.textContent.includes('修复卡 254'));assert.ok(fix);assert.ok(fix.childNodes.find(n=>n.tagName==='DETAILS').textContent.includes('internal_scope'));
        const conditions=fields({conditions:[{field:'exposed',equals:true},{field:'authenticated',equals:false}]});assert.ok(conditions.textContent.includes('互联网暴露：是'));assert.ok(conditions.textContent.includes('启用认证：否'));assert.ok(!conditions.textContent.includes('{'));
        """)

    def test_pending_answer_and_fact_cards_do_not_repeat_full_answer_in_primary_content(self):
        self.js(r"""
        state.snapshot={knowledge_epoch:2,events:[],evidence:[],assets:[]};state.connected=true;state.sessionId='a'.repeat(32);state.chats.set(state.sessionId,[{question:'q',answer:{answer:'合并全文',mode:'facts',knowledge_epoch:2,claims:[{text:'逐条事实',evidence_ids:[]}],citations:[],warnings:[],trace:[],entities:[]}}]);renderChat();const answer=created.find(n=>n.className==='message assistant');assert.ok(!answer.childNodes.some(n=>n.className==='answer-text'));assert.ok(answer.childNodes.some(n=>n.tagName==='DETAILS'&&n.textContent.includes('合并全文')));
        state.chats.set(state.sessionId,[{question:'q',answer:{answer:'旧结论未发布',mode:'pending',knowledge_epoch:2,claims:[],citations:[],warnings:[],trace:[],entities:[]}}]);renderChat();assert.ok($('transcript').textContent.includes('资料更新中'));assert.ok(!$('transcript').textContent.includes('已核验回答快照'));
        """)

    def test_event_history_is_available_without_changing_evidence_api(self):
        self.js(r"""
        state.snapshot={evidence:[],demo:false};state.detail={evidence:[{observation_id:3,history:[{id:'obs:3:r:1',revision_number:1,summary:'初始版本'},{id:'obs:3:r:2',revision_number:2,summary:'撤回更正',withdrawn:true}]}]};fetch=async()=>({ok:true,text:async()=>JSON.stringify({id:'obs:3:r:2',observation_id:3,revision_number:2,current:true,current_revision_number:2,title:'公告',metadata:{},references:[]})});await openEvidence('obs:3:r:2');assert.ok($('evidence-body').textContent.includes('已记录的修订历史'));assert.ok($('evidence-body').textContent.includes('初始版本'));assert.ok($('evidence-body').textContent.includes('撤回更正'));
        """)

    def test_fieldless_write_responses_do_not_invent_an_extra_epoch_after_new_snapshot_arrives(self):
        self.js(r"""
        const old={knowledge_epoch:1,asset_snapshot_id:1,assets:[],evidence:[{id:'obs:1:r:1',observation_id:1}],events:[{id:1,title:'事件',generation:1,status:'quarantined',evidence_ids:['obs:1:r:1'],facts:[],assessments:[]}]};
        const newer={...old,knowledge_epoch:2,asset_snapshot_id:2,events:[{...old.events[0],generation:2,status:'ready'}]};
        for(const kind of ['assets','process','confirm']){
         state.snapshot={...old};state.requiredEpoch=1;state.requiredAssetSnapshot=1;state.connected=true;state.pendingCurrent=false;state.selected=null;let release;
         fetch=async(path)=>{if(path==='/api/system')return {ok:true,text:async()=>JSON.stringify({snapshot:newer})};await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify(kind==='assets'?{count:1,snapshot_id:2}:kind==='process'?{processed:1,remaining:0}:{updated:true})};};
         let pending;const e={preventDefault(){}};
         if(kind==='assets'){state.draft=[{asset_id:'a',name:'服务',ecosystem:'pip',component:'vllm',version:'unknown',exposed:null,authenticated:null,observed_at:'2020-01-01T00:00:00Z',capabilities:{}}];pending=saveAssets(e);}
         else if(kind==='process')pending=action('process','/api/process',()=> '完成');
         else{const panel=entityConfirmation(old.events[0]),form=panel.childNodes.find(n=>n.tagName==='FORM'),select=form.querySelectorAll('select')[0];select.value='1';await select.fire('change');form.querySelectorAll('textarea')[0].value='来源核对完成';pending=form.fire('submit',e);}
         await refresh();assert.equal(state.snapshot.knowledge_epoch,2);release();await pending;assert.equal(state.requiredEpoch,2,kind);assert.equal(state.pendingCurrent,false,kind);assert.equal(state.connected,true,kind);assert.equal(state.snapshot.knowledge_epoch,2,kind);
        }
        """)

    def test_write_barrier_rejects_prewrite_fetch_without_an_initial_epoch(self):
        self.js(r"""
        state.snapshot=null;let release,calls=0;const old={knowledge_epoch:5,events:[],evidence:[],assets:[]};fetch=async(path)=>{if(path==='/api/process')return {ok:true,text:async()=>'{"processed":1,"remaining":0}'};calls++;if(calls===1){await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({snapshot:old})};}return {ok:true,text:async()=>JSON.stringify({snapshot:{...old,knowledge_epoch:6}})};};const initial=refresh(),write=action('process','/api/process',()=> '完成');await Promise.resolve();await Promise.resolve();await Promise.resolve();release();await Promise.all([initial,write]);assert.equal(calls,2);assert.equal(state.snapshot.knowledge_epoch,6);assert.equal(state.pendingCurrent,false);
        """)

    def test_session_history_restores_pairs_preserves_citations_and_stale_state(self):
        self.js(r"""
        const payload={answer:'当时回答',mode:'facts',knowledge_epoch:1,claims:[{text:'旧事实',evidence_ids:['obs:1:r:1']}],citations:[{evidence_id:'obs:1:r:1'}],trace:[],warnings:[],entities:[],as_of:'2020-01-01T00:00:00Z'};
        const data={messages:[{role:'user',content:'原问题'},{role:'assistant',content:'当时回答',payload,knowledge_epoch:1,stale:true,created_at:'2020-01-01T00:00:00Z'},{role:'user',content:'续问'},{role:'assistant',content:'权限变化后的隐藏提示',knowledge_epoch:1,stale:true}]};const rows=restoredMessages(data);assert.equal(rows.length,2);assert.equal(rows[0].question,'原问题');assert.equal(rows[0].answer.citations[0].evidence_id,'obs:1:r:1');assert.equal(rows[0].answer.knowledge_epoch,1);assert.equal(answerFreshness(rows[0].answer,{knowledge_epoch:2}).kind,'warn');assert.equal(rows[1].answer.answer,'权限变化后的隐藏提示');assert.equal(rows[1].answer.citations.length,0);assert.equal(payload.history_stale,undefined);
        """)

    def test_loading_existing_session_recovers_messages_once_and_follows_current_epoch(self):
        self.js(r"""
        const id='b'.repeat(32);state.snapshot={knowledge_epoch:1,evidence:[],assets:[],events:[]};let historyCalls=0,systemCalls=0;
        fetch=async(path)=>{if(path==='/api/sessions/'+id){historyCalls++;return {ok:true,text:async()=>JSON.stringify({id,knowledge_epoch:2,messages:[{role:'user',content:'历史问题'},{role:'assistant',content:'历史回答',knowledge_epoch:1,stale:true,payload:{answer:'历史回答',mode:'facts',claims:[],citations:[],trace:[],warnings:[],entities:[],knowledge_epoch:1}}]})};}systemCalls++;return {ok:true,text:async()=>JSON.stringify({snapshot:{...state.snapshot,knowledge_epoch:2}})};};await loadSession(id);assert.equal(historyCalls,1);assert.equal(systemCalls,1);assert.equal(state.sessionId,id);assert.ok($('transcript').textContent.includes('历史问题'));assert.ok($('transcript').textContent.includes('历史回答'));assert.equal(state.snapshot.knowledge_epoch,2);assert.equal($('ask').disabled,false);await loadSession(id);assert.equal(historyCalls,1);
        """)

    def test_session_loading_race_does_not_overwrite_newer_selection(self):
        self.js(r"""
        const first='a'.repeat(32),second='b'.repeat(32);state.snapshot={knowledge_epoch:1,evidence:[],assets:[],events:[]};let release;fetch=async(path)=>{const id=path.slice('/api/sessions/'.length);if(id===first)await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({id,knowledge_epoch:1,messages:[{role:'user',content:id===first?'旧选择':'新选择'},{role:'assistant',content:'历史内容',knowledge_epoch:1,stale:false}]})};};const old=loadSession(first);await loadSession(second);release();await old;assert.equal(state.sessionId,second);assert.ok($('transcript').textContent.includes('新选择'));assert.ok(!$('transcript').textContent.includes('旧选择'));assert.equal(state.chats.has(first),false);
        """)

    def test_session_read_failure_is_visible_retryable_and_does_not_accept_invalid_id(self):
        self.js(r"""
        let calls=0;fetch=async()=>{calls++;throw new TypeError('offline');};await loadSession('x/../../private');assert.equal(calls,0);await loadSession('c'.repeat(32));assert.equal(calls,1);assert.ok($('transcript').textContent.includes('无法连接'));assert.ok($('transcript').textContent.includes('重新读取历史'));assert.equal(state.sessionLoading,false);assert.equal($('ask').disabled,false);
        """)

    def test_pending_ask_response_keeps_valid_session_and_visible_retry_state(self):
        self.js(r"""
        const id='d'.repeat(32);$('question').value='问题';fetch=async(path)=>({ok:true,text:async()=>JSON.stringify(path==='/api/ask'?{session_id:id,answer:'资料发生变化，请重新核验',mode:'pending',knowledge_epoch:2,claims:[],citations:[],trace:[],warnings:[],entities:[]}: {snapshot:{knowledge_epoch:2,events:[],evidence:[],assets:[]}})});await askQuestion({preventDefault(){}});assert.equal(state.sessionId,id);assert.equal(state.chats.get(id)[0].answer.mode,'pending');assert.ok($('transcript').textContent.includes('资料更新中'));assert.ok($('ask-status').textContent.includes('重新提问'));assert.equal($('question').value,'');
        """)

    def test_real_job_status_names_are_chinese_and_linked_to_event_titles(self):
        self.js(r"""
        state.snapshot={events:[{id:8,title:'情报甲'}],assets:[],evidence:[]};state.system={jobs:[{id:1,entity_id:8,status:'retry_wait',attempt:2},{id:2,entity_id:8,status:'succeeded',attempt:1}],monitoring:{sources:[]},model:{},sessions:[]};renderSystem();assert.ok($('jobs').textContent.includes('等待重试'));assert.ok($('jobs').textContent.includes('完成'));assert.ok($('jobs').textContent.includes('情报甲'));assert.ok(!$('jobs').textContent.includes('retry_wait'));
        """)

    def test_policy_change_hides_cached_content_before_reloading_authorized_history(self):
        self.js(r"""
        const id='e'.repeat(32);state.snapshot={knowledge_epoch:1,policy_generation:1,events:[],evidence:[],assets:[]};state.connected=true;state.sessionId=id;state.chats.set(id,[{question:'原问题',answer:{answer:'REVOKED BODY',claims:[{text:'REVOKED CLAIM',evidence_ids:['obs:1:r:1']}],citations:[{evidence_id:'obs:1:r:1'}],mode:'facts',knowledge_epoch:1,trace:[],warnings:[],entities:[]}}]);renderChat();let historyCalls=0,release;
        fetch=async(path)=>{if(path==='/api/system')return {ok:true,text:async()=>JSON.stringify({snapshot:{...state.snapshot,knowledge_epoch:2,policy_generation:2}})};historyCalls++;await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({id,knowledge_epoch:2,messages:[{role:'user',content:'原问题'},{role:'assistant',content:'该历史回答包含当前未获授权的来源，内容已隐藏。',knowledge_epoch:1,stale:true,payload:{answer:'内容已隐藏',claims:[],citations:[],mode:'history',knowledge_epoch:1,trace:[],warnings:[],entities:[]}}]})};};
        await refresh();assert.equal(historyCalls,1);assert.ok(!$('transcript').textContent.includes('REVOKED BODY'));assert.ok(!$('transcript').textContent.includes('REVOKED CLAIM'));assert.equal(state.chats.has(id),false);release();for(let i=0;i<8;i++)await Promise.resolve();assert.ok($('transcript').textContent.includes('内容已隐藏'));assert.ok(!$('transcript').textContent.includes('REVOKED'));await loadSession(id);assert.equal(historyCalls,1);
        """)

    def test_policy_change_invalidates_history_request_already_inflight(self):
        self.js(r"""
        const id='f'.repeat(32);state.snapshot={knowledge_epoch:1,policy_generation:1,events:[],evidence:[],assets:[]};let release,calls=0;
        fetch=async(path)=>{if(path==='/api/system')return {ok:true,text:async()=>JSON.stringify({snapshot:{...state.snapshot,knowledge_epoch:2,policy_generation:2}})};calls++;const old=calls===1;if(old)await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({id,knowledge_epoch:old?1:2,messages:[{role:'user',content:'q'},{role:'assistant',content:old?'REVOKED OLD RESPONSE':'已按当前权限隐藏',knowledge_epoch:old?1:2,stale:old}]})};};
        const prior=loadSession(id);await refresh();release();await prior;for(let i=0;i<8;i++)await Promise.resolve();assert.equal(calls,2);assert.ok(!$('transcript').textContent.includes('REVOKED'));assert.ok($('transcript').textContent.includes('当前权限隐藏'));
        """)

    def test_six_views_update_navigation_and_preserve_model_draft(self):
        self.js(r"""
        state.modelFormReady=true;state.knowledge={items:[],coverage:{}};
        for(const view of ['chat','overview','knowledge','assets','status','model']){showView(view);assert.equal(state.view,view);for(const key of ['chat','overview','knowledge','assets','status','model'])assert.equal($('view-'+key).hidden,key!==view);assert.equal(navigation.filter(n=>n.attributes['aria-current']==='page').length,1);assert.equal(navigation.find(n=>n.attributes['aria-current']==='page').dataset.view,view);}
        showView('unknown');assert.equal(state.view,'model');
        $('model-provider').value='deepseek';$('model-key').value='sk-test-only-123';state.modelFormDirty=true;state.model=publicModel({provider:'facts'});fillModelForm();assert.equal($('model-provider').value,'deepseek');assert.equal($('model-key').value,'sk-test-only-123');$('model-provider').value='mock';modelFieldsChanged();assert.equal($('model-key').value,'');assert.equal($('deepseek-fields').hidden,true);
        """)

    def test_model_reads_project_public_status_without_testing_or_echoing_secrets(self):
        self.js(r"""
        const secret='sk-NEVER-IN-PUBLIC-STATE';let calls=[];fetch=async(path,options)=>{calls.push([path,options.method]);return {ok:true,text:async()=>JSON.stringify({provider:'deepseek',enabled:true,configured:true,credential_configured:true,model:'deepseek-v4-pro',api_key:secret,reasoning_content:'HIDDEN REASONING',last_test:{status:'ok',message:secret,api_key:secret,at:'2020-01-01T00:00:00Z'}})};};await loadModel();assert.equal(calls.length,1);assert.equal(calls[0][0],'/api/model');assert.equal(calls[0][1],undefined);assert.equal($('model-key').value,'');assert.ok(!JSON.stringify(state).includes(secret));assert.ok(!JSON.stringify(state).includes('HIDDEN REASONING'));assert.ok(![...elements.values()].some(n=>n.textContent.includes(secret)));assert.ok($('model-summary').textContent.includes('连接测试成功'));
        """)

    def test_cloud_settings_require_opt_in_and_mock_requires_no_key(self):
        self.js(r"""
        $('model-provider').value='deepseek';$('model-key').value='sk-local-test';$('reasoning-effort').value='none';let calls=0;fetch=async()=>{calls++;return {ok:true,text:async()=>JSON.stringify({provider:'mock',enabled:true,configured:true,semantic_mode:'mock_plan'})};};await saveModel({preventDefault(){}});assert.equal(calls,0);assert.equal($('model-key').value,'');assert.ok($('model-status').textContent.includes('发送范围'));
        $('cloud-consent').checked=true;await saveModel({preventDefault(){}});assert.equal(calls,0);assert.ok($('model-status').textContent.includes('API Key'));
        $('model-provider').value='mock';await saveModel({preventDefault(){}});assert.equal(calls,1);assert.equal(state.model.provider,'mock');assert.ok($('model-badge').textContent.includes('离线演示'));assert.ok($('model-status').textContent.includes('没有连接 DeepSeek'));assert.ok(!$('model-summary').textContent.includes('官方 DeepSeek V4 Pro'));
        """)

    def test_model_save_clears_key_before_wait_and_failure_never_echoes_it(self):
        self.js(r"""
        $('model-provider').value='deepseek';$('cloud-consent').checked=true;$('reasoning-effort').value='high';$('model-key').value='sk-private-test-123';let calls=0,release,body;
        fetch=async(path,options)=>{calls++;assert.equal(path,'/api/model');assert.equal($('model-key').value,'');assert.equal(options.headers['X-Monitor-Token'],TOKEN);body=JSON.parse(options.body);await new Promise(resolve=>release=resolve);throw Error(body.api_key);};const first=saveModel({preventDefault(){}});await saveModel({preventDefault(){}});assert.equal(calls,1);assert.equal($('save-model').disabled,true);assert.equal(body.api_key,'sk-private-test-123');assert.equal(body.model,'deepseek-v4-pro');release();await first;assert.equal($('model-key').value,'');assert.equal(state.modelBusy,false);assert.ok(!$('model-status').textContent.includes('sk-private-test-123'));assert.ok(!JSON.stringify(state).includes('sk-private-test-123'));
        """)

    def test_model_test_is_explicit_bounded_and_clear_disables_generation(self):
        self.js(r"""
        state.model=publicModel({provider:'deepseek',enabled:true,configured:true,credential_configured:true});state.modelFormDirty=false;let calls=[],release;
        fetch=async(path,options)=>{calls.push(path);assert.equal(options.method,'POST');assert.deepEqual(JSON.parse(options.body),{});if(path==='/api/model/test'){await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({last_test:{status:'ok'}})};}return {ok:true,text:async()=>JSON.stringify({provider:'facts',enabled:false,configured:false,credential_configured:false})};};
        const first=testModel();await testModel();await clearModel();assert.equal(calls.length,1);release();await first;assert.ok($('model-status').textContent.includes('连接测试成功'));$('model-key').value='sk-leftover';await clearModel();assert.deepEqual(calls,['/api/model/test','/api/model/clear']);assert.equal($('model-key').value,'');assert.equal(state.model.provider,'facts');assert.equal(state.model.enabled,false);assert.equal($('model-provider').value,'facts');assert.ok($('model-summary').textContent.includes('正常'));
        const before=calls.length;await testModel();assert.equal(calls.length,before);assert.ok($('model-status').textContent.includes('无需连接测试'));
        """)

    def test_old_system_response_cannot_restore_model_after_clear(self):
        self.js(r"""
        state.model=publicModel({provider:'deepseek',enabled:true,configured:true,credential_configured:true});let release;
        fetch=async(path)=>{if(path==='/api/model/clear')return {ok:true,text:async()=>JSON.stringify({provider:'facts',enabled:false})};await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({model:{provider:'deepseek',enabled:true,configured:true,credential_configured:true},snapshot:{knowledge_epoch:1,events:[],assets:[],evidence:[]}})};};const pending=refresh();await clearModel();assert.equal(state.model.provider,'facts');release();await pending;assert.equal(state.model.provider,'facts');assert.equal(state.system.model.credential_configured,false);assert.ok(!$('model-badge').textContent.includes('DeepSeek'));
        """)

    def test_system_read_started_during_model_write_cannot_restore_old_configuration(self):
        self.js(r"""
        state.model=publicModel({provider:'deepseek',enabled:true,configured:true,credential_configured:true});let releasePost,releaseGet;
        fetch=async(path)=>{if(path==='/api/model/clear'){await new Promise(resolve=>releasePost=resolve);return {ok:true,text:async()=>JSON.stringify({model:{provider:'facts',enabled:false}})};}await new Promise(resolve=>releaseGet=resolve);return {ok:true,text:async()=>JSON.stringify({model:{provider:'deepseek',enabled:true,configured:true,credential_configured:true},snapshot:{knowledge_epoch:1,events:[],assets:[],evidence:[]}})};};const clear=clearModel(),read=refresh();releasePost();await clear;assert.equal(state.model.provider,'facts');releaseGet();await read;assert.equal(state.model.provider,'facts');assert.equal(state.model.credential_configured,false);
        """)

    def test_mock_output_separates_canonical_facts_analysis_unknowns_and_trace(self):
        self.js(r"""
        const ref='obs:1:r:1',claim={id:'event:1:fact:0',text:'来源提供修复依据',evidence_ids:[ref]};state.snapshot={demo:true,knowledge_epoch:1,events:[],assets:[],evidence:[{id:ref,source_id:'演示来源',revision_number:1}]};state.connected=true;state.sessionId='mock';state.chats.set('mock',[{question:'修复建议？',answer:{mode:'mock_model',retrieval:'mock_plan',knowledge_epoch:1,answer:'合并全文',claims:[claim],citations:[],trace:[{event:'generation',number:1,reasoning_content:'DO NOT DISPLAY',prompt:'PRIVATE PROMPT'},{event:'tool',name:'evidence_read',status:'ok'}],analysis_sections:[{kind:'recommendation',text:'核对来源声明的适用条件后安排修复。',claim_ids:[claim.id],evidence_ids:[ref]},{kind:'uncertainty',text:'资产条件仍需调查。',claim_ids:[claim.id],evidence_ids:[ref]}]}}]);renderChat();const root=$('transcript');assert.ok(root.textContent.includes('已核验事实'));assert.ok(root.textContent.includes('Mock 分析与建议'));assert.ok(root.textContent.includes('条件未知'));assert.ok(root.textContent.includes('没有连接 DeepSeek'));assert.ok(root.textContent.includes('结构校验不证明语义正确'));assert.ok(root.textContent.includes('只读工具取证'));assert.ok(!root.textContent.includes('DO NOT DISPLAY'));assert.ok(!root.textContent.includes('PRIVATE PROMPT'));const sections=created.filter(n=>n.className?.startsWith('analysis-section'));assert.equal(sections.length,2);assert.ok(sections.every(n=>n.textContent.includes('演示来源 · r1')));assert.ok(sections.every(n=>n.textContent.includes('依据事实 1')));
        """)

    def test_analysis_rejects_unlinked_extra_or_mismatched_evidence_fields(self):
        self.js(r"""
        const claim={id:'event:1:fact:0',text:'事实',evidence_ids:['obs:1:r:1']},base={kind:'analysis',text:'分析',claim_ids:[claim.id],evidence_ids:['obs:1:r:1']};assert.equal(supportedAnalysis({claims:[claim],analysis_sections:[base]}).length,1);
        for(const bad of [{...base,claim_ids:[]},{...base,claim_ids:['invented']},{...base,evidence_ids:['obs:2:r:1']},{...base,evidence_ids:['obs:1:r:1','obs:1:r:1']},{...base,reasoning_content:'hidden'},{...base,kind:'verified'},{...base,text:'x'.repeat(1201)}])assert.equal(supportedAnalysis({claims:[claim],analysis_sections:[bad]}).length,0);assert.equal(supportedAnalysis({claims:[claim],analysis_sections:Array(9).fill(base)}).length,0);
        """)

    def test_cloud_model_label_is_distinct_and_analysis_is_text_only(self):
        self.js(r"""
        const ref='obs:1:r:1',claim={id:'event:1:fact:0',text:'事实',evidence_ids:[ref]},payload='<script>globalThis.PWN=1</script> [link](javascript:alert(1))';state.snapshot={knowledge_epoch:1,evidence:[{id:ref,source_id:'A'}],events:[],assets:[]};state.connected=true;state.sessionId='cloud';state.chats.set('cloud',[{question:'q',answer:{mode:'cloud_model',model:'deepseek-v4-pro',retrieval:'llm_semantic',knowledge_epoch:1,claims:[claim],answer:'事实',analysis_sections:[{kind:'analysis',text:payload,claim_ids:[claim.id],evidence_ids:[ref]}]}}]);renderChat();assert.ok($('transcript').textContent.includes('DeepSeek 云端研判'));assert.ok($('transcript').textContent.includes('模型语义检索'));assert.ok($('transcript').textContent.includes('模型推断'));assert.ok($('transcript').textContent.includes(payload));assert.equal(globalThis.PWN,undefined);assert.equal(created.filter(n=>n.tagName==='SCRIPT'||n.tagName==='A').length,0);
        """)

    def test_knowledge_catalog_marks_curated_and_feed_preserves_terms_and_filters(self):
        self.js(r"""
        const payload='<img src=x onerror="globalThis.PWN=1">';fetch=async(path)=>{assert.equal(path,'/api/knowledge');return {ok:true,text:async()=>JSON.stringify({items:[{id:'1',title:'官方 AI 指南',kind:'guide',source:'NIST',summary:payload,topics:['风险治理'],attribution:payload,usage_conditions:'仅元数据，请署名',monitoring:'curated',url:'https://example.org/guide'},{id:'2',title:'政策观察',kind:'policy',source:'官方来源',monitoring:'feed',url:'http://127.0.0.1/private'}],coverage:{scope:'官方元数据',gaps:['标准覆盖尚缺']}})};};await loadKnowledge();assert.ok($('knowledge-coverage').textContent.includes('人工精选 1 项，订阅观察 1 项'));assert.ok($('knowledge-coverage').textContent.includes('技术标准 0'));assert.ok($('knowledge-items').textContent.includes('不代表持续监测')||$('knowledge-coverage').textContent.includes('不代表持续监测'));assert.ok($('knowledge-items').textContent.includes(payload));assert.ok($('knowledge-items').textContent.includes('仅元数据，请署名'));assert.equal(globalThis.PWN,undefined);assert.equal(created.filter(n=>n.tagName==='A').length,1);$('knowledge-search').value='风险治理';renderKnowledge();assert.ok($('knowledge-items').textContent.includes('官方 AI 指南'));assert.ok(!$('knowledge-items').textContent.includes('政策观察'));$('knowledge-search').value='';$('knowledge-kind').value='policy';renderKnowledge();assert.ok(!$('knowledge-items').textContent.includes('官方 AI 指南'));assert.ok($('knowledge-items').textContent.includes('政策观察'));
        """)

    def test_knowledge_loading_failure_empty_and_old_catalog_are_distinct(self):
        self.js(r"""
        let release;fetch=async()=>{await new Promise(resolve=>release=resolve);throw new TypeError('offline');};const first=loadKnowledge();assert.ok($('knowledge-items').textContent.includes('正在读取'));assert.equal($('reload-knowledge').disabled,true);release();await first;assert.ok($('knowledge-items').textContent.includes('未读取成功'));assert.equal($('reload-knowledge').disabled,false);
        fetch=async()=>({ok:true,text:async()=>JSON.stringify({items:[],coverage:{}})});await loadKnowledge();assert.ok($('knowledge-items').textContent.includes('目录当前为空'));assert.ok($('knowledge-coverage').textContent.includes('目录 0 项'));
        state.knowledge={items:[{title:'之前的目录',kind:'guide',monitoring:'curated'}],coverage:{}};fetch=async()=>{throw new TypeError('offline');};await loadKnowledge();assert.ok($('knowledge-items').textContent.includes('之前的目录'));assert.ok($('knowledge-status').textContent.includes('上次读取'));
        """)

    def test_monitor_counts_sources_separately_from_categories(self):
        self.js(r"""
        state.snapshot={events:[],assets:[],evidence:[]};state.system={model:{provider:'facts'},monitoring:{sources:[{id:'a',category:'vulnerability_database'},{id:'b',category:'vulnerability_database'},{id:'c',category:'vendor_advisory'},{id:'d',category:'research_paper'},{id:'e',category:'security_community'}]}};renderSystem();renderStats();assert.ok($('monitor-summary').textContent.includes('5 个来源，覆盖 4 类'));assert.ok($('stage-monitor').textContent.includes('5 个来源 · 4 类'));assert.ok($('model-badge').textContent.includes('事实模式'));assert.ok(!$('model-summary').textContent.includes('错误'));
        """)

    def test_sbom_malformed_oversize_and_unrecognized_formats_never_post(self):
        self.js(r"""
        for(const raw of ['', '[1]', 'null', '{"foo":"bar"}', '{invalid}', 'x'.repeat(1048577)])assert.throws(()=>sbomDocument(raw));assert.equal(sbomDocument('{"bomFormat":"CycloneDX","components":[]}').bomFormat,'CycloneDX');assert.equal(sbomDocument('{"spdxVersion":"SPDX-2.3","packages":[]}').spdxVersion,'SPDX-2.3');let calls=0;fetch=async()=>{calls++;};$('sbom-text').value='{invalid}';await saveSBOM({preventDefault(){}});assert.equal(calls,0);assert.equal($('sbom-text').value,'{invalid}');assert.ok($('sbom-status').textContent.includes('无法解析'));let reads=0;$('sbom-file').files=[{size:1048577,text:async()=>{reads++;return '{}';}}];await readSBOMFile();assert.equal(reads,0);assert.ok($('sbom-status').textContent.includes('超过'));
        """)

    def test_sbom_failure_preserves_input_blocks_concurrent_imports_and_duplicate_posts(self):
        self.js(r"""
        const raw='{"bomFormat":"CycloneDX","components":[]}';$('sbom-text').value=raw;let calls=0,release;fetch=async(path)=>{calls++;assert.equal(path,'/api/assets/sbom');await new Promise(resolve=>release=resolve);throw new TypeError('offline');};const first=saveSBOM({preventDefault(){}});await saveSBOM({preventDefault(){}});await saveAssets({preventDefault(){}});assert.equal(calls,1);assert.equal($('save-sbom').disabled,true);assert.equal($('save-assets').disabled,true);release();await first;assert.equal(state.sbomSaving,false);assert.equal($('sbom-text').value,raw);assert.ok($('sbom-status').textContent.includes('原文已保留'));
        """)

    def test_sbom_success_invalidates_old_current_facts_before_refresh_finishes(self):
        self.js(r"""
        const old={knowledge_epoch:1,asset_snapshot_id:1,assets:[],evidence:[],events:[{id:1,status:'ready',facts:[{predicate:'fix',value:{text:'OLD FIX'}}],assessments:[]}]};state.snapshot=old;state.connected=true;$('sbom-text').value='{"spdxVersion":"SPDX-2.3","packages":[]}';let release;
        fetch=async(path,options)=>{if(path==='/api/assets/sbom'){assert.equal(JSON.parse(options.body).document.spdxVersion,'SPDX-2.3');return {ok:true,text:async()=>'{"count":1,"snapshot_id":2,"knowledge_epoch":2,"warnings":["导入时间不等于安装观察时间","组件版本未知"]}'};}await new Promise(resolve=>release=resolve);return {ok:true,text:async()=>JSON.stringify({snapshot:{...old,knowledge_epoch:2,asset_snapshot_id:2,events:[{...old.events[0],status:'dirty',facts:[],assessments:[]}]}})};};const first=saveSBOM({preventDefault(){}});for(let i=0;i<8;i++)await Promise.resolve();assert.equal(state.pendingCurrent,true);assert.equal(state.snapshot.events[0].status,'dirty');assert.deepEqual(state.snapshot.events[0].facts,[]);assert.equal(state.requiredAssetSnapshot,2);release();await first;assert.equal(state.snapshot.asset_snapshot_id,2);assert.equal(state.pendingCurrent,false);assert.ok($('sbom-status').textContent.includes('1 项组件'));assert.ok($('sbom-warnings').textContent.includes('导入时间不等于安装观察时间'));assert.ok($('sbom-warnings').textContent.includes('组件版本未知'));
        """)

    def test_metadata_fact_distinguishes_summary_and_curated_update_basis(self):
        self.js(r"""
        state.snapshot={evidence:[],assets:[]};const n=factCard({predicate:'source_metadata',status:'valid',value:{title:'官方资料',summary:'来源摘要',monitoring:'curated',source_reported_time:'2020-01-01'},evidence_ids:[]});assert.ok(n.textContent.includes('资料元数据'));assert.ok(n.textContent.includes('不代表已经核验全文或实验结论'));assert.ok(n.textContent.includes('人工精选'));assert.ok(n.textContent.includes('来源报告时间'));assert.ok(n.textContent.includes('来源摘要'));
        """)

    def test_wrapped_model_api_shape_and_mock_identity_are_supported(self):
        self.js(r"""
        fetch=async()=>({ok:true,text:async()=>JSON.stringify({model:{provider:'mock',enabled:true,configured:true,credential_configured:false,model:'mock-deepseek-v4-pro',semantic_mode:'mock_plan'}})});await loadModel();assert.equal(state.model.provider,'mock');assert.equal(state.model.model,'mock-deepseek-v4-pro');assert.equal(state.model.semantic_mode,'mock_plan');assert.equal($('model-provider').value,'mock');assert.ok($('model-summary').textContent.includes('无需 Key'));assert.ok($('test-model').textContent.includes('离线流程'));await testModel();assert.ok(!$('model-status').textContent.includes('连接测试成功'));
        """)

    def test_sbom_file_read_race_keeps_the_latest_selected_document(self):
        self.js(r"""
        let release;$('sbom-file').files=[{size:20,text:async()=>{await new Promise(resolve=>release=resolve);return 'OLD DOCUMENT';}}];const old=readSBOMFile();$('sbom-file').files=[{size:20,text:async()=> 'NEW DOCUMENT'}];await readSBOMFile();release();await old;assert.equal($('sbom-text').value,'NEW DOCUMENT');
        """)

    def test_new_sbom_file_loading_blocks_submission_of_previous_text(self):
        self.js(r"""
        $('sbom-text').value='{"bomFormat":"CycloneDX","components":[]}';let calls=0,release;fetch=async()=>{calls++;};$('sbom-file').files=[{size:60,text:async()=>{await new Promise(resolve=>release=resolve);return '{"spdxVersion":"SPDX-2.3","packages":[]}';}}];const pending=readSBOMFile();assert.equal(state.sbomReading,true);assert.equal($('save-sbom').disabled,true);await saveSBOM({preventDefault(){}});assert.equal(calls,0);assert.ok($('sbom-status').textContent.includes('仍在读取'));release();await pending;assert.equal(state.sbomReading,false);assert.ok($('sbom-text').value.includes('SPDX-2.3'));assert.equal($('save-sbom').disabled,false);
        """)

    def test_old_sbom_file_failure_does_not_replace_latest_read_status_and_http_limit(self):
        self.js(r"""
        let reject;$('sbom-file').files=[{size:20,text:async()=>{await new Promise((resolve,no)=>reject=no);return 'old';}}];const prior=readSBOMFile();$('sbom-file').files=[{size:20,text:async()=> 'NEW DOCUMENT'}];await readSBOMFile();reject(Error('read failed'));await prior;assert.equal($('sbom-text').value,'NEW DOCUMENT');assert.ok($('sbom-status').textContent.includes('文档已读入'));assert.equal(state.sbomReading,false);assert.equal(MAX_SBOM_BYTES,1000000);assert.throws(()=>sbomDocument(JSON.stringify({bomFormat:'CycloneDX',notes:'x'.repeat(1000000)})));
        """)

    def test_context_disconnect_and_unsynced_counts_are_honest(self):
        self.js(r"""
        state.model=publicModel({provider:'mock',enabled:true,configured:true});renderStats();assert.equal($('stat-events').textContent,'—');state.snapshot={knowledge_epoch:1,events:[],assets:[],evidence:[]};state.connected=true;renderContext();fetch=async()=>{throw new TypeError('offline');};await refresh();assert.equal(state.connected,false);assert.ok($('context-freshness').textContent.includes('上次同步'));
        """)


if __name__ == "__main__":
    unittest.main()
