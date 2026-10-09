"""Self-contained local intelligence workbench; the integration server owns HTTP.

PAGE uses only nonce-bearing inline resources and renders untrusted content as
text. The client never interprets model Markdown or fetches external sources.
"""

PAGE = r'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>知安 · AI 安全情报工作台</title>
<style nonce="__NONCE__">
:root{color-scheme:light;--bg:#f2f5f7;--paper:#fff;--ink:#172e41;--muted:#667986;--line:#dce5e9;--teal:#087b70;--teal-light:#e8f5f1;--navy:#102b40;--amber:#855b13;--amber-bg:#fff6e4;--red:#a33d43;--red-bg:#fff0f1;--radius:16px}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.7 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}button,input,textarea,select{font:inherit}button{cursor:pointer;min-height:36px;padding:8px 14px;background:#fff;color:var(--ink);border:1px solid var(--line);border-radius:8px}button:hover:enabled{background:#edf5f3;border-color:#b6d7cf}button:disabled{cursor:default;opacity:.5}button.primary{background:var(--teal);border-color:var(--teal);color:#fff;font-weight:600}button.primary:hover:enabled{background:#06695f}button.danger{color:var(--red);border-color:#e3b9bd}input,textarea,select{border:1px solid #ccd9df;border-radius:8px;background:#fff;color:var(--ink);padding:9px 11px;min-width:0;max-width:100%}textarea{resize:vertical}input:focus,textarea:focus,select:focus,button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #71bfb4;outline-offset:3px}a{color:var(--teal);text-underline-offset:3px}h1,h2,h3,h4,p{margin:0}h1{font-size:28px;letter-spacing:-.8px;line-height:1.35;font-weight:700}h2{font-size:18px;line-height:1.45}h3{font-size:15px}h4{font-size:14px}p+p{margin-top:8px}[hidden]{display:none!important}.muted{color:var(--muted);font-size:12px}.prewrap{white-space:pre-wrap;overflow-wrap:anywhere}.skip{position:fixed;top:-100px;left:16px;z-index:20;padding:12px;background:#fff}.skip:focus{top:12px}.shell{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}.sidebar{background:var(--navy);color:#e8f2f5;padding:30px 18px 22px;display:flex;flex-direction:column;gap:34px;position:sticky;top:0;height:100vh}.brand{display:flex;align-items:center;gap:12px;font-size:24px;font-weight:700;padding:0 10px}.brand-mark{width:40px;height:42px;color:#83d3c5;display:grid;place-items:center}.brand-mark svg{width:38px;height:38px}.brand small{display:block;font-size:9px;letter-spacing:2.4px;font-weight:500;color:#a1b7c7}.nav-label{font-size:10px;letter-spacing:2px;color:#8ba7ba;padding:0 13px;margin-bottom:10px}.nav{display:grid;gap:6px}.nav button{display:flex;align-items:center;gap:12px;border:1px solid transparent;background:transparent;color:#b7cbd8;text-align:left;padding:12px 13px;font-size:13px;font-weight:600;position:relative}.nav button svg{width:19px;height:19px;flex-shrink:0;opacity:.9}.nav button:hover:enabled{background:#193c52;border-color:transparent}.nav button[aria-current="page"]{background:#1b4757;border-color:#2b6265;color:#f7fffd}.nav button[aria-current="page"]::after{content:"";position:absolute;right:13px;top:20px;width:5px;height:5px;background:#83d3c5;border-radius:50%}.nav-settings{margin-top:18px;padding-top:18px;border-top:1px solid #28485d}.sidebar-footer{margin-top:auto;font-size:11px;color:#93b0c2;line-height:1.9;padding:16px 10px 0;border-top:1px solid #28485d}.sidebar-footer strong{display:block;color:#d6e7ef;font-size:12px;margin-bottom:5px}.workspace{min-width:0;padding:27px clamp(20px,2.4vw,42px) 24px}.topbar,.section-head,.row,.toolbar{display:flex;align-items:center;gap:12px}.topbar{justify-content:space-between;align-items:flex-start;margin-bottom:22px}.eyebrow{font-size:10px;font-weight:700;letter-spacing:2px;color:var(--teal);margin-bottom:7px}.topbar p{margin-top:7px;color:var(--muted);font-size:13px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end;padding-top:6px}.pill{display:inline-block;font-size:11px;font-weight:600;border-radius:5px;padding:3px 8px;background:#edf2f5;color:#536b7b;vertical-align:middle;white-space:normal;overflow-wrap:anywhere}.pill.ok{background:var(--teal-light);color:#126459}.pill.warn{background:var(--amber-bg);color:var(--amber)}.pill.bad{background:var(--red-bg);color:var(--red)}.banner{border:1px solid #e8d4a7;background:var(--amber-bg);border-radius:10px;padding:12px 16px;font-size:12px;margin-bottom:16px;display:flex;gap:12px;align-items:center;justify-content:space-between}.banner.error{background:var(--red-bg);border-color:#e8bcbc;color:var(--red)}.banner strong{font-weight:650}.pipeline{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;border:1px solid var(--line);border-radius:12px;background:#f8fafb;margin:0 0 20px}.stage{padding:13px 17px;display:flex;gap:12px;align-items:center;border-right:1px solid var(--line)}.stage:last-child{border:0}.stage .number{color:var(--teal);font-size:11px;font-weight:800}.stage strong{display:block;font-size:12px}.stage span:last-child{font-size:11px;color:var(--muted)}.section-head{justify-content:space-between;margin:0 0 18px;align-items:flex-start}.section-head p{margin-top:5px}.grid{display:grid;grid-template-columns:minmax(340px,.92fr) minmax(0,1.35fr);gap:20px;align-items:start}.panel{background:var(--paper);border:1px solid var(--line);border-radius:var(--radius);padding:23px;min-width:0;overflow-wrap:anywhere;box-shadow:0 2px 8px #122c4003}.panel+.panel{margin-top:20px}.grid>.panel+.panel,.status-grid>.panel+.panel,.settings-grid>.panel+.panel{margin-top:0}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}.stat{border:1px solid var(--line);background:#fff;border-radius:12px;padding:17px 20px}.stat strong{display:block;font-size:30px;line-height:1.4;letter-spacing:-.7px;font-variant-numeric:tabular-nums}.stat span{font-size:12px;color:var(--muted)}.stat .note{font-size:11px;color:var(--muted);margin-top:3px}.filters{display:flex;gap:8px;flex-wrap:wrap;padding-bottom:17px;border-bottom:1px solid var(--line)}.filters input{flex:1;min-width:130px}.record{border-bottom:1px solid var(--line);padding:18px 0}.record:last-child{border:0}.record-title{display:block;text-align:left;border:0;padding:0;min-height:0;background:none;font-size:14px;line-height:1.6;font-weight:650;color:var(--ink);max-width:100%}.record-title:hover:enabled{color:var(--teal);background:none}.record .row{margin-top:8px;flex-wrap:wrap;gap:6px}.record p{margin-top:8px}.excerpt{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;white-space:pre-wrap;font-size:12px;color:#596e7c}.pagination{display:flex;justify-content:space-between;align-items:center;margin-top:16px;padding-top:14px;border-top:1px solid var(--line)}.empty{padding:36px 12px;text-align:center;color:var(--muted);font-size:13px}.empty strong{display:block;font-size:15px;color:var(--ink);margin-bottom:6px}.count{font-size:12px;color:var(--muted)}.detail-head{padding-bottom:18px;border-bottom:1px solid var(--line);margin-bottom:20px}.detail-head h2{font-size:22px;margin:10px 0}.detail-block+.detail-block{margin-top:24px}.cards{display:grid;gap:12px;margin-top:12px}.card{background:#f8fafb;border:1px solid var(--line);border-radius:10px;padding:16px}.card h4{margin-bottom:7px}.card.warn{border-color:#e9d4a7;background:#fffcf4}.card.bad{border-color:#e7b6b6;background:#fff8f8}.citation-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:11px}.citation{font-size:11px;padding:4px 8px;min-height:28px;color:var(--teal);background:#fff;border-color:#cbe2dc;max-width:100%;overflow-wrap:anywhere}.citation:hover:enabled{background:var(--teal-light)}.kv{display:grid;grid-template-columns:minmax(75px,125px) minmax(0,1fr);gap:6px 12px;font-size:12px;margin:12px 0}.kv dt{color:var(--muted)}.kv dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.notice{background:#f1f6f8;border-left:3px solid #a3c0cc;border-radius:4px;padding:11px 13px;font-size:12px;margin:14px 0;color:#536b7b}.notice.warn{background:var(--amber-bg);border-color:#d2ab51;color:var(--amber)}.notice.bad{background:var(--red-bg);border-color:#cf8181;color:var(--red)}.source-row{padding:16px 0;border-top:1px solid var(--line)}.source-row:first-child{border-top:0}.source-row .row{justify-content:space-between;margin-bottom:5px;flex-wrap:wrap}.source-row p{font-size:12px;color:var(--muted)}.status-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px;align-items:start}.asset-editor{display:grid;gap:12px;margin:18px 0}.asset-form{border:1px solid var(--line);border-radius:12px;padding:19px;background:#fafcfd}.form-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.field{display:grid;gap:7px;font-size:12px;font-weight:600}.field input,.field select{width:100%;font-weight:400}.field small{font-weight:400;color:var(--muted)}.asset-form .row{justify-content:space-between;flex-wrap:wrap;margin-bottom:15px}.asset-form details{margin-top:15px}.import-box{margin-top:21px;padding-top:18px;border-top:1px solid var(--line)}summary{cursor:pointer;font-size:12px;color:#466275}summary:hover{color:var(--teal)}.help{font-size:12px;color:var(--muted);margin:9px 0}.import-box textarea{width:100%;font-size:12px;margin:8px 0;min-height:100px}.import-box .row{flex-wrap:wrap}.table-wrap{overflow-x:auto;margin-top:18px}table{border-collapse:collapse;text-align:left;width:100%;font-size:12px;min-width:600px}th{color:var(--muted);font-weight:600;background:#f5f8fa}th,td{padding:13px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}td:nth-child(1){max-width:170px}td small{display:block;color:var(--muted)}.chat-layout{display:grid;grid-template-columns:minmax(0,1fr) 318px;gap:20px;align-items:start}.chat-panel{padding:0;display:flex;flex-direction:column;height:calc(100vh - 195px);min-height:620px}.chat-top{padding:17px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px;flex-wrap:wrap}.chat-top .chat-heading{margin-right:auto}.chat-top .chat-heading strong{display:block;font-size:14px}.chat-top select{max-width:240px;flex:1;font-size:12px}.transcript{padding:26px;flex:1;min-height:260px;overflow:auto;overscroll-behavior:contain}.chat-intro{max-width:640px;margin:clamp(20px,4vh,58px) auto 25px;padding:0 4px}.intro-symbol{width:44px;height:44px;border:1px solid #c7e3dc;background:#edf8f4;border-radius:12px;display:grid;place-items:center;color:var(--teal);font-size:20px;font-weight:600;margin-bottom:22px}.chat-intro h3{font-size:28px;line-height:1.4;letter-spacing:-.6px;margin-bottom:12px}.chat-intro>.muted{font-size:13px;line-height:1.9;max-width:540px}.prompts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:27px}.prompts button{text-align:left;font-size:12px;padding:15px 16px;line-height:1.75;background:#fafcfd;border-radius:10px}.prompts button strong{display:block;color:#214958;font-size:13px;margin-bottom:5px}.prompts button span{display:block;color:var(--muted)}.message{margin:0 0 23px}.message.user{margin-left:18%;background:#eaf3f3;border:1px solid #d7e7e7;padding:13px 17px;border-radius:12px 12px 3px 12px;font-size:13px}.message.assistant{border:1px solid var(--line);border-radius:12px;padding:21px;background:#fff}.message .meta{display:flex;flex-wrap:wrap;gap:7px;align-items:center;margin-bottom:17px}.answer-text{white-space:pre-wrap;overflow-wrap:anywhere;font-size:14px}.answer-heading{font-size:14px;margin:19px 0 4px}.answer-subtitle{font-size:11px;color:var(--muted)}.claim{margin-top:14px;padding:15px 0 0;border-top:1px solid var(--line)}.claim p{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;line-height:1.9}.claim-number{font-size:10px;color:var(--teal);font-weight:700;margin-bottom:6px}.analysis-section{background:#f1f6f8;border:1px solid #d7e5eb;border-left:3px solid #618896;border-radius:8px;padding:14px 16px;margin-top:11px}.analysis-section p{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}.analysis-section.uncertainty{background:#fffcf5;border-color:#e6d7b8;border-left-color:#c09c54}.analysis-label{font-size:10px;font-weight:700;color:#466879;margin-bottom:7px}.analysis-section.uncertainty .analysis-label{color:var(--amber)}.message details{margin-top:17px;padding-top:13px;border-top:1px solid #e7edf0}.trace-step{padding:10px 0;border-bottom:1px solid var(--line);font-size:12px}.compose{padding:18px 24px;border-top:1px solid var(--line);background:#fafcfd;border-radius:0 0 var(--radius) var(--radius)}.compose textarea{width:100%;min-height:78px;display:block;border-color:#c2d5dc}.compose .row{justify-content:space-between;margin-top:12px;flex-wrap:wrap}.compose .muted{max-width:70%;font-size:11px}.chat-context{display:grid;gap:16px}.chat-context .panel{margin:0;padding:20px}.context-heading{display:flex;gap:9px;align-items:center;margin-bottom:13px}.context-heading .eyebrow{margin:0}.context-stats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.context-stat{padding:10px 0;border-bottom:1px solid #e7edf0}.context-stat strong{font-size:24px;font-weight:650;display:block;line-height:1.4;font-variant-numeric:tabular-nums}.context-stat span{font-size:11px;color:var(--muted)}.context-item{border-top:1px solid var(--line);padding:11px 0}.context-item:first-child{border:0}.context-item button{font-size:12px;text-align:left;display:block;background:none;border:0;padding:0;min-height:0;font-weight:600;max-width:100%;overflow-wrap:anywhere}.context-item button:hover{background:none}.context-item .muted{font-size:11px;margin-top:5px}.context-link{margin-top:13px;color:var(--teal);border:0;background:#eff7f4;font-size:12px;width:100%}.chat-context p{font-size:12px;color:var(--muted)}.checkbox{display:flex;align-items:flex-start;gap:9px;font-size:12px;color:var(--muted);font-weight:400}.checkbox input{accent-color:var(--teal);margin-top:5px;flex-shrink:0}.sync{margin-top:20px;font-size:10px;color:var(--muted);display:flex;gap:14px;flex-wrap:wrap;align-items:center}.sync .divider{margin-left:auto}.sync .checkbox{font-size:10px;align-items:center;gap:5px}.sync .checkbox input{margin:0}.inline-status{font-size:12px;min-height:0;margin-top:10px;color:var(--muted);overflow-wrap:anywhere}.inline-status:empty{display:none}dialog{border:1px solid var(--line);border-radius:16px;width:min(860px,94vw);max-height:88vh;padding:0;color:var(--ink);box-shadow:0 20px 80px #102f4140}dialog::backdrop{background:#142f4c70}.dialog-head{padding:22px 26px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:15px;align-items:flex-start}.dialog-head h2{font-size:18px}.dialog-body{padding:22px 26px}.evidence-section{padding:18px 0;border-bottom:1px solid var(--line)}.evidence-section:last-child{border:0}.history{padding:14px;border:1px solid var(--line);border-radius:9px;margin:10px 0}.history summary{font-weight:600}.history p{white-space:pre-wrap;margin-top:9px;font-size:13px}.code-data{white-space:pre-wrap;font:12px/1.7 ui-monospace,monospace;overflow-wrap:anywhere;background:#f4f7f9;border-radius:8px;padding:14px}.footer-note{margin-top:14px;font-size:10px;color:var(--muted)}.settings-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(300px,.8fr);gap:20px;align-items:start}.settings-form{display:grid;gap:20px}.settings-form .form-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.provider-fields{display:grid;gap:17px;padding:18px;border:1px solid var(--line);border-radius:10px;background:#fafcfd}.provider-fields .notice{margin:0}.settings-actions{display:flex;gap:9px;flex-wrap:wrap;padding-top:6px}.model-summary{margin-bottom:19px}.model-summary .row{flex-wrap:wrap;margin-bottom:11px}.model-facts{padding:14px 0;border-top:1px solid var(--line)}.model-facts:first-child{border:0}.model-facts h3{margin-bottom:6px}.model-facts p{font-size:12px;color:var(--muted)}.knowledge-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.knowledge-card{display:flex;flex-direction:column;padding:21px;background:#fff;border:1px solid var(--line);border-radius:13px;min-width:0;overflow-wrap:anywhere}.knowledge-card h3{font-size:15px;line-height:1.6;margin:13px 0 10px}.knowledge-card .summary{font-size:12px;color:#566d7b;white-space:pre-wrap;margin-bottom:14px}.knowledge-card .row{flex-wrap:wrap;gap:5px}.knowledge-card footer{margin-top:auto;padding-top:15px;border-top:1px solid var(--line);font-size:11px;color:var(--muted)}.knowledge-card details{margin-top:12px}.knowledge-card footer a{display:inline-block;margin-top:7px}.knowledge-tools{margin-bottom:19px}.knowledge-tools .filters{padding-bottom:0;border-bottom:0}.sbom-box textarea{min-height:160px;font-family:ui-monospace,monospace}.sbom-box .field{margin:12px 0}.progress-note{padding:14px 16px;border-radius:9px;background:#edf7f3;border:1px solid #cde5dc;color:var(--teal);font-size:12px;margin-top:12px}.section-kicker{font-size:11px;letter-spacing:1px;font-weight:700;color:var(--muted);margin-bottom:8px}
@media(min-width:1700px){.workspace{padding-left:42px;padding-right:42px}.chat-layout{grid-template-columns:minmax(0,1fr) 360px}.chat-panel{min-height:700px}.knowledge-grid{grid-template-columns:repeat(4,minmax(0,1fr))}}
@media(max-width:1200px){.shell{grid-template-columns:202px minmax(0,1fr)}.sidebar{padding:27px 13px}.workspace{padding:24px 20px}.chat-layout{grid-template-columns:minmax(0,1fr) 265px;gap:16px}.chat-context .panel{padding:17px}.chat-top,.compose{padding:16px 20px}.transcript{padding:20px}.grid{grid-template-columns:minmax(0,1fr)}.knowledge-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.settings-grid{grid-template-columns:minmax(0,1fr)}.settings-grid>.panel+.panel{margin-top:0}.actions{max-width:290px}.chat-top select{max-width:170px}}
@media(max-width:980px){.chat-layout{grid-template-columns:minmax(0,1fr)}.chat-context{grid-template-columns:repeat(2,minmax(0,1fr))}.chat-context>.panel:first-child{grid-column:1/-1}.context-stats{grid-template-columns:repeat(4,minmax(0,1fr))}.chat-panel{height:auto;min-height:600px}.transcript{max-height:680px}.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.status-grid{grid-template-columns:minmax(0,1fr)}.pipeline{grid-template-columns:repeat(2,minmax(0,1fr))}.stage:nth-child(2){border-right:0}.stage:nth-child(-n+2){border-bottom:1px solid var(--line)}}
@media(max-width:740px){.shell{display:block}.sidebar{padding:15px 16px;gap:16px;position:static;height:auto}.brand{font-size:20px;padding:0}.brand-mark{width:30px;height:32px}.brand-mark svg{width:30px;height:30px}.brand small{font-size:8px}.sidebar-footer,.nav-label{display:none}.nav{display:flex;gap:5px;overflow:auto}.nav button{padding:9px 11px;white-space:nowrap;font-size:12px;gap:7px}.nav button svg{width:16px;height:16px}.nav button[aria-current="page"]::after{display:none}.nav-settings{margin:0;padding:0;border:0}.workspace{padding:22px 14px}.topbar{display:block;margin-bottom:18px}.actions{max-width:none;justify-content:flex-start;margin-top:11px;padding:0}h1{font-size:24px}.stats{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.stat{padding:14px}.stat strong{font-size:27px}.stage{padding:11px}.panel{padding:18px}.chat-panel{padding:0;min-height:560px}.chat-context{display:block}.chat-context>.panel+.panel{margin-top:16px}.chat-context .context-stats{grid-template-columns:repeat(4,minmax(0,1fr));gap:7px}.context-stat strong{font-size:21px}.chat-top,.compose{padding:15px}.chat-top .chat-heading{width:100%}.chat-top select{max-width:none}.transcript{padding:16px}.chat-intro{margin:16px 0}.chat-intro h3{font-size:23px}.intro-symbol{margin-bottom:16px}.prompts{grid-template-columns:minmax(0,1fr);margin-top:21px}.prompts button{padding:12px 14px}.message.assistant{padding:16px}.message.user{margin-left:8%}.compose .muted{max-width:100%}.form-grid,.settings-form .form-grid{grid-template-columns:minmax(0,1fr)}.banner{align-items:flex-start;flex-direction:column}.sync .divider{margin-left:0}.kv{grid-template-columns:85px minmax(0,1fr)}.knowledge-grid{grid-template-columns:minmax(0,1fr)}.section-head{gap:10px;flex-wrap:wrap}.settings-actions button{flex:1}.dialog-head,.dialog-body{padding:18px}.filters input{min-width:140px}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
</style>
</head>
<body>
<a class="skip" href="#main">跳到工作区</a>
<div class="shell"><aside class="sidebar" aria-label="工作台导航">
 <div class="brand"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M20 3 34 9v12c0 8-14 16-14 16S6 29 6 21V9L20 3Z"/><path d="m13 20 5 5 10-12"/></svg></span><div>知安<small>AI INTELLIGENCE</small></div></div>
 <div><p class="nav-label">安全情报工作台</p><nav class="nav" aria-label="工作区"><button type="button" data-view="chat" aria-current="page" aria-controls="view-chat"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 4h16v12H9l-5 4V4Z"/><path d="M8 8h8M8 12h5"/></svg>证据问答</button>
<button type="button" data-view="overview" aria-controls="view-overview"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 13h4l3-8 4 14 3-6h4"/></svg>情报动态</button>
<button type="button" data-view="knowledge" aria-controls="view-knowledge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 4h7v16H4V4ZM13 4h7v16h-7V4ZM7 8h1M16 8h1M7 12h1M16 12h1"/></svg>知识底座</button>
<button type="button" data-view="assets" aria-controls="view-assets"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="3" width="16" height="8" rx="2"/><rect x="4" y="13" width="16" height="8" rx="2"/><path d="M8 7h1M8 17h1M13 7h4M13 17h4"/></svg>授权资产</button>
<button type="button" data-view="status" aria-controls="view-status"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 19V9M10 19V4M16 19v-7M22 19H2"/></svg>运行状态</button>
<button type="button" class="nav-settings" data-view="model" aria-controls="view-model"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3 8 5v8l-8 5-8-5V8l8-5Z"/><path d="m4 8 8 5 8-5M12 13v8M8 6l8 5"/></svg>模型设置</button>
</nav></div>
 <div class="sidebar-footer"><strong>每个判断，都有出处</strong>汇聚情报 · 核验影响 · 追溯证据<br><span id="sidebar-mode">正在连接本机工作台</span></div>
</aside><main id="main" class="workspace" tabindex="-1">
 <header class="topbar"><div><div class="eyebrow">SECURITY INTELLIGENCE / WORKSPACE</div><h1 id="page-title">证据驱动的安全研判</h1><p id="page-subtitle">理解影响，厘清条件，把每个判断追溯到来源。</p></div><div class="actions"><span id="mode-badge" class="pill">连接中</span><span id="model-badge" class="pill">读取模型状态</span><button type="button" id="refresh">刷新数据</button></div></header>
 <div id="demo-banner" class="banner" hidden><div><strong>离线虚构演示</strong> · 演示漏洞、研究记录和资产为虚构示例；演示库不联网采集。知识目录为官方元数据，按卡片单独标注。</div><button type="button" id="withdraw" class="danger">演示来源撤回</button></div>
 <div id="connection-banner" class="banner error" role="status" hidden></div>
 <div id="global-message" class="inline-status" role="status" aria-live="polite"></div>
 <section id="view-chat" aria-label="证据问答">
  <div class="chat-layout"><section class="panel chat-panel"><div class="chat-top"><div class="chat-heading"><strong>情报研究助手</strong><span class="muted">当前来源 · 逐条核验 · 多轮追问</span></div><select id="sessions" aria-label="选择会话"><option value="">新的会话</option></select><button type="button" id="new-session">新建会话</button></div><div id="transcript" class="transcript" aria-label="问答记录" aria-busy="false"></div><form id="ask-form" class="compose"><label class="field" for="question">描述你要判断的问题<textarea id="question" maxlength="2000" rows="3" placeholder="询问影响范围、修复步骤、预防 / 调查建议，或要求展示证据链…" required></textarea></label><div class="row"><span id="ask-status" class="muted" role="status" aria-live="polite">核验事实、模型分析和条件未知分别呈现。</span><button type="submit" id="ask" class="primary">发送问题</button></div></form></section>
  <aside class="chat-context" aria-label="问答上下文"><section class="panel"><div class="context-heading"><h3>当前知识上下文</h3></div><div id="context-summary" class="context-stats"><div class="context-stat"><strong>—</strong><span>等待同步</span></div></div><p id="context-freshness" class="help">正在读取当前有效证据。</p></section><section class="panel"><div class="context-heading"><h3>与你有关的情报</h3></div><div id="context-events"></div><button type="button" id="browse-events" class="context-link">查看全部情报</button></section><section class="panel"><div class="context-heading"><h3>当前回答能力</h3></div><p id="chat-capability">正在读取模型状态。</p><button type="button" id="configure-model" class="context-link">配置回答模型</button><div class="notice">来源或清单变化后，历史回答保留并提示重新核验。条件未知会明确显示。</div></section></aside></div>
 </section>
 <section id="view-overview" aria-label="情报概览" hidden>
 <div class="pipeline" aria-label="情报处理流程"><div class="stage"><span class="number">01</span><div><strong>监测发现</strong><span id="stage-monitor">汇聚来源与修订</span></div></div><div class="stage"><span class="number">02</span><div><strong>关联富化</strong><span id="stage-enrich">整理范围与修复依据</span></div></div><div class="stage"><span class="number">03</span><div><strong>资产影响</strong><span id="stage-assets">匹配授权清单</span></div></div><div class="stage"><span class="number">04</span><div><strong>证据问答</strong><span id="stage-chat">逐条引用，可回溯</span></div></div></div>

  <div class="stats"><div class="stat"><span>情报事件</span><strong id="stat-events">—</strong><div class="note">去重后的知识条目</div></div><div class="stat"><span>可供当前问答</span><strong id="stat-ready">—</strong><div class="note">已完成当前证据核验</div></div><div class="stat"><span>待关注的资产判断</span><strong id="stat-impact">—</strong><div class="note">可能受影响或待调查</div></div><div class="stat"><span>正在更新</span><strong id="stat-pending">—</strong><div class="note">旧结果暂不作为当前依据</div></div></div>
  <div class="grid"><section class="panel"><div class="section-head"><div><h2>情报动态</h2><p class="muted">选择条目，查看范围、资产与证据。</p></div><span id="event-count" class="count"></span></div><form id="filters" class="filters"><input id="search" type="search" maxlength="200" aria-label="搜索情报" placeholder="搜索编号、组件或标题"><select id="event-state" aria-label="筛选事件状态"><option value="">全部状态</option><option value="ready">可用</option><option value="dirty">更新中</option><option value="quarantined">待核对</option></select><button type="submit">查找</button></form><div id="events"></div><div class="pagination"><button type="button" id="prev">上一页</button><span id="page-number" class="muted"></span><button type="button" id="next">下一页</button></div></section><section class="panel" id="event-detail" aria-label="当前情报详情"><div class="empty"><strong>从一条情报开始</strong>选择左侧条目，查看依据和与你的资产有关的判断。</div></section></div>
 </section>
 <section id="view-assets" aria-label="授权资产" hidden>
  <section class="panel"><div class="section-head"><div><h2>我的授权清单</h2><p class="muted">以组件和清单时间判断适用性；缺失信息会保留为未知。</p></div><button type="button" id="edit-assets">编辑当前清单</button></div><div id="inventory-summary" class="notice">正在读取当前清单。</div><div id="inventory-table" class="table-wrap"></div><div id="asset-impacts" class="cards"></div></section>
  <section class="panel"><div class="section-head"><div><h2>导入新的清单快照</h2><p class="muted">提交的是整份授权清单，将替换当前快照并重新计算影响。填写组件身份即可。</p></div><button type="button" id="example-assets">载入虚构示例</button></div><form id="asset-submit"><div id="asset-editor" class="asset-editor"></div><div class="row"><button type="button" id="add-asset">＋ 添加资产</button><button type="submit" id="save-assets" class="primary">提交整份清单</button></div><div id="asset-message" class="inline-status" role="status"></div></form><details class="import-box"><summary>从 CSV / TSV 导入</summary><p class="help">使用下方表头；时间填写带时区的 ISO 时间。版本留空为未知；暴露与认证可填“是 / 否 / 未知”。最多 100 条、64 KB。导入只读取文本表格。</p><pre class="code-data">资产ID,名称,生态,组件,版本,暴露,认证,清单时间
demo-api,虚构推理服务,pip,vllm,99.1.0,是,未知,2026-10-03T00:00:00Z</pre><label class="field" for="import-text">粘贴表格<textarea id="import-text" maxlength="65536" rows="4" placeholder="粘贴 CSV，或从表格软件复制包含表头的 TSV"></textarea></label><div class="row"><label class="field" for="import-file">读取文本文件<input id="import-file" type="file" accept=".csv,.tsv,text/csv,text/tab-separated-values"></label><button type="button" id="parse-import">放入表单检查</button></div></details></section>

  <section class="panel sbom-box"><div class="section-head"><div><div class="section-kicker">SOFTWARE BILL OF MATERIALS</div><h2>从 SBOM 导入组件清单</h2><p class="muted">读取已授权的 CycloneDX / SPDX JSON，生成新的被动组件快照。</p></div><span class="pill">本机解析</span></div><p class="help">提交后替换整份当前清单。仅识别文档已声明的组件身份与版本；不访问目标或文档中的链接，缺失版本和部署条件保留为未知。请求最多 1 MB（含封装字段），请先确认文档属于你的授权范围。</p><form id="sbom-form"><label class="field" for="sbom-text">SBOM JSON<textarea id="sbom-text" maxlength="1000000" rows="6" spellcheck="false" placeholder="粘贴 CycloneDX 或 SPDX 的 JSON 文档"></textarea></label><div class="row"><label class="field" for="sbom-file">读取 JSON 文件<input id="sbom-file" type="file" accept=".json,application/json"></label><button id="save-sbom" type="submit" class="primary">导入并替换当前清单</button></div><div id="sbom-status" class="inline-status" role="status" aria-live="polite"></div><div id="sbom-warnings"></div></form></section>
 </section>

 <section id="view-knowledge" aria-label="知识底座" hidden><div class="section-head"><div><h2>AI 安全知识底座</h2><p class="muted">技术标准、政策法规与安全指南的官方元数据；研究资料保留在来源证据中。</p></div><button type="button" id="reload-knowledge">刷新目录</button></div><div id="knowledge-coverage" class="notice">正在读取覆盖范围。</div><div class="panel knowledge-tools"><form id="knowledge-filters" class="filters"><input id="knowledge-search" type="search" maxlength="200" aria-label="搜索知识底座" placeholder="搜索标题、主题或官方来源"><select id="knowledge-kind" aria-label="筛选资料类型"><option value="">全部类型</option><option value="standard">技术标准</option><option value="policy">政策法规</option><option value="guide">安全指南</option></select><button type="submit">查找</button></form></div><div id="knowledge-items" class="knowledge-grid"></div><div id="knowledge-status" class="inline-status" role="status" aria-live="polite"></div></section>
 <section id="view-model" aria-label="模型设置" hidden><div class="settings-grid"><section class="panel"><div class="section-head"><div><div class="section-kicker">ANSWER ENGINE</div><h2>选择回答方式</h2><p class="muted">事实模式可直接使用。保存模型设置后，每次回答都会标明实际模式。</p></div><button type="button" id="reload-model">刷新状态</button></div><div id="model-summary" class="model-summary"></div><form id="model-form" class="settings-form"><label class="field" for="model-provider">回答提供方<select id="model-provider"><option value="facts">结构化事实 · 本机</option><option value="mock">Mock · 离线流程演示（无需 Key）</option><option value="deepseek">DeepSeek V4 Pro · 官方云 API</option><option value="ollama">Ollama · 本机模型</option></select></label><div id="deepseek-fields" class="provider-fields" hidden><div><strong>DeepSeek V4 Pro</strong><p class="muted">固定官方模型 deepseek-v4-pro</p><p class="muted">https://api.deepseek.com/chat/completions</p></div><label class="field" for="model-key">API Key<input id="model-key" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="512" placeholder="本机输入，保存后清空"><small id="model-key-help">Key 仅保存在本机服务内存，重启后需重新配置。不会返回页面，也不会写入数据库或浏览器存储。</small></label><label class="checkbox" for="cloud-consent"><input id="cloud-consent" type="checkbox">我同意启用官方云端推理，发送最少必要的公开证据与匿名化资产事实。原始清单和内部资产名称留在本机。</label></div><div id="ollama-fields" class="provider-fields" hidden><label class="field" for="local-model">本机模型名称<input id="local-model" maxlength="100" placeholder="填写已在本机配置的模型名称"><small>使用本机现有 Ollama 服务，模型可用性以实际测试结果为准。</small></label></div><div id="reasoning-fields" hidden><label class="field" for="reasoning-effort">模型分析强度<select id="reasoning-effort"><option value="none">默认 · 不启用思考模式</option><option value="low">低</option><option value="high">高</option><option value="max">最高</option></select><small>更高强度可能增加等待时间。页面展示有证据支持的分析，不展示模型内部思考。</small></label></div><div class="settings-actions"><button type="submit" id="save-model" class="primary">保存设置</button><button type="button" id="test-model">测试连接</button><button type="button" id="clear-model" class="danger">清除 Key 并停用模型</button></div><div id="model-status" class="inline-status" role="status" aria-live="polite"></div></form></section><aside class="panel"><div class="section-head"><h2>从证据到回答</h2></div><div class="model-facts"><h3>已核验事实</h3><p>组件范围、来源评分、资产适用性和修复依据来自主机校验后的事实卡，逐条保留引用。</p></div><div class="model-facts"><h3>模型分析与建议</h3><p>跨资料归纳、建议和不确定性单独标注，并链接到支持它们的事实与证据。资料不足时明确保留未知。</p></div><div class="model-facts"><h3>主动测试才会发起连接</h3><p>读取状态不会调用云端模型。点击“测试连接”发起一次有界测试；保存之后提问使用所选提供方，失败会显示降级原因。</p></div><div class="notice">API Key 只在此密码框输入。请勿把凭据粘贴到问句、清单或 SBOM。</div></aside></div></section>
 <section id="view-status" aria-label="运行状态" hidden>
  <div class="status-grid"><section class="panel"><div class="section-head"><div><h2>持续监测来源</h2><p class="muted">保留署名、许可范围与采集状态。</p></div><button type="button" id="collect">检查到期来源</button></div><div id="monitor-summary" class="notice"></div><div id="sources"></div></section><section class="panel"><div class="section-head"><div><h2>处理任务</h2><p class="muted">查看完成、重试与等待核对的任务。</p></div><button type="button" id="process">继续处理</button></div><div id="job-summary" class="notice"></div><div id="jobs"></div></section></div>
 </section>
 <footer class="sync"><span id="last-sync">尚未同步</span><span id="snapshot-time"></span><label class="checkbox divider"><input id="auto-refresh" type="checkbox">每 20 秒刷新状态（最多 30 次）</label><span id="poll-status"></span></footer><p class="footer-note">影响判断以授权清单和当前有效来源为依据。未知、更新中与来源冲突均会保留，不表示已经发生入侵。</p>
</main></div>
<dialog id="evidence-dialog" aria-labelledby="evidence-title"><div class="dialog-head"><div><span class="eyebrow">EVIDENCE & REVISION</span><h2 id="evidence-title">证据修订</h2></div><button type="button" id="close-evidence">关闭</button></div><div id="evidence-body" class="dialog-body"></div></dialog>
<script nonce="__NONCE__">
'use strict';
const $ = id => document.getElementById(id);
const TOKEN = '__TOKEN__';
const PAGE_SIZE = 10, MAX_ASSETS = 256, MAX_IMPORT_ASSETS = 100, MAX_TEXT = 24000, MAX_SBOM_BYTES = 1000000;
const capabilityLabels = {external_documents:'外部文档输入',rag:'检索增强（RAG）',tools:'工具调用',network:'网络访问',write_access:'写入权限'};
const state = {view:'chat', model:null, modelBusy:false, modelLoading:false, modelSequence:0, modelFormDirty:false, modelFormReady:false, knowledge:null, knowledgeLoading:false, knowledgeError:'', knowledgeSequence:0, sbomSaving:false, sbomReading:false, sbomFileSequence:0, snapshot:null, system:null, connected:false, lastSync:null, page:0, selected:null, detail:null, refreshBusy:false, refreshPromise:null, refreshQueued:false, requiredEpoch:0, requiredAssetSnapshot:0, pendingCurrent:false, snapshotBarrier:0, detailSequence:0, evidenceSequence:0, draft:[], saving:false, asking:false, sessionId:'', sessionSequence:0, sessionLoading:false, sessionLoadError:'', chats:new Map(), pollTimer:null, polls:0};
const eventLabels = {ready:'可用',dirty:'更新中',quarantined:'待核对'};
const assessmentLabels = {potentially_affected:'可能受影响',not_affected_with_reason:'有依据的不受影响',under_investigation:'待调查',resolved:'已解决'};
const matchLabels = {affected:'版本范围命中',not_in_range:'版本不在已知范围',unknown:'版本适用性未知'};
const factLabels = {source_metadata:'资料元数据',affected_component:'受影响组件',affected_range:'版本范围',cvss:'CVSS 评分',weakness:'弱点分类',condition:'适用前提',fix:'修复建议',impact:'影响说明',related_material:'关联资料',poc_reference:'POC 线索',risk_pattern:'风险模式'};
const fieldLabels = {title:'资料标题',source_reported_time:'来源报告时间',monitoring:'更新方式',source_kind:'资料类别',event:'处理步骤',stage:'处理阶段',tool:'读取工具',tools:'获准工具',number:'模型调用次数',depth:'编排层级',events:'检索到的事件',cards:'候选事实卡',name:'工具名称',retry_after:'重试等待秒数',code:'公开错误类别',generation_count:'模型调用次数',tool_call_count:'工具读取次数',ecosystem:'生态',name:'名称',component:'组件',package:'软件包',range:'范围',ranges:'范围',exact_versions:'明确版本',vulnerable_version_range:'受影响范围',patched_versions:'修复版本',patched_version:'修复版本',fixed_version:'修复版本',version:'版本',score:'评分',vector:'向量',severity:'等级',description:'说明',text:'说明',summary:'摘要',type:'类型',condition:'前提',conditions:'适用条件',field:'前提项',equals:'要求值',required:'所需条件',action:'建议',source:'来源',source_id:'来源',upstream_id:'上游编号',evidence_id:'证据编号',revision_number:'修订版本',collected_at:'采集时间',published_at:'发布时间',updated_at:'更新时间',cwe:'弱点',cwe_id:'弱点编号',id:'编号',relation:'关联性质',target_evidence_id:'关联证据',verified:'已验证',license:'许可',license_url:'许可',terms_url:'使用条件',url:'原始来源',method:'方法',status:'状态',content_scope:'内容范围',attribution:'署名',disclaimer:'来源声明',local_processing:'处理方式',available:'可用性',reason:'依据',scheme:'版本方案',kind:'建议类型',verification:'验证情况',supported:'条件可判断',confirmed_exploitation:'确认利用',confirmed_vulnerability:'确认存在漏洞',identity_precision:'身份核对',conflict:'来源冲突',pattern:'风险模式',basis:'判断依据',asset_id:'关联资产',capabilities:'声明能力',asset_snapshot_id:'清单快照',observed_at:'清单时间',stale:'清单已过期'};
function list(value, limit=100) { return Array.isArray(value) ? value.slice(0,limit) : []; }
function text(value, limit=MAX_TEXT) {
 if(value===null || value===undefined) return '未知';
 let out;
 if(typeof value==='object') { try {out=JSON.stringify(value,null,2);} catch {out='无法显示';} }
 else out=String(value);
 return out.length>limit ? out.slice(0,limit)+'…（内容已截断）' : out;
}
function el(tag, value, cls) {const node=document.createElement(tag); if(value!==undefined) node.textContent=text(value); if(cls) node.className=cls; return node;}
function button(label, handler, cls='') {const n=el('button',label,cls); n.type='button'; n.addEventListener('click',handler); return n;}
function empty(root, title, body='') {root.replaceChildren(); const n=el('div',undefined,'empty'); n.append(el('strong',title),el('p',body)); root.append(n);}
function badge(label, kind='') {return el('span',label,'pill '+kind);}
function date(value) {if(!value) return '时间未知'; const d=new Date(value); return Number.isNaN(d.getTime())?'时间无效':d.toLocaleString('zh-CN',{hour12:false});}
function age(value, now=Date.now()) {const t=Date.parse(value); if(!Number.isFinite(t)) return '清单时间未知'; const days=Math.floor((now-t)/86400000); return days<0?'清单时间晚于当前时间':days===0?'清单不足 1 天':`清单已过去 ${days} 天`;}
function triLabel(value) {return value===true?'是':value===false?'否':'未知';}
function versionLabel(value) {return !value||['unknown','未知'].includes(String(value).toLowerCase())?'版本未知':text(value,120);}
function validEventId(value) {return Number.isSafeInteger(Number(value)) && Number(value)>0;}
function validEvidenceId(value) {return typeof value==='string' && /^obs:[1-9]\d{0,14}:r:[1-9]\d{0,8}$/.test(value);}
function validSessionId(value) {return typeof value==='string'&&/^[a-f0-9]{32}$/.test(value);}
// URL is normalized before literal-address checks: decimal/octal/hex IPv4 is
// canonicalized by the browser. DNS resolution remains the server's concern.
function publicURL(value) {
 if(typeof value!=='string' || value.length>2048 || /[\x00-\x20\x7f\\]/.test(value) || !/^https?:\/\//i.test(value)) return null;
 try {
  const u=new URL(value); if(!['http:','https:'].includes(u.protocol) || u.username || u.password) return null;
  const sensitive=/^(?:token|authtoken|apitoken|accesstoken|refreshtoken|key|apikey|xapikey|accesskey|password|passwd|secret|clientsecret|auth|authorization|credential|credentials|signature|sig|session|sessionid|xamzcredential|xamzsignature)$/;
  for(const params of [u.searchParams,new URLSearchParams(u.hash.slice(1))])for(const key of params.keys())if(sensitive.test(key.toLowerCase().replace(/[_-]/g,'')))return null;
  const h=u.hostname.toLowerCase().replace(/\.$/,'');
  if(!h || h.includes(':') || h.startsWith('[')) return null; // Conservatively block all IPv6 literals.
  if(/^[0-9.]+$/.test(h)) {
   const a=h.split('.').map(Number); if(a.length!==4 || a.some(n=>!Number.isInteger(n)||n<0||n>255)) return null;
   const [x,y,z]=a;
   if(x===0||x===10||x===127||x>=224||x===169&&y===254||x===172&&y>=16&&y<=31||x===192&&y===168||x===100&&y>=64&&y<=127||x===192&&y===0||x===192&&y===2||x===192&&y===88&&z===99||x===198&&(y===18||y===19||y===51&&z===100)||x===203&&y===0&&z===113) return null;
  } else {
   if(!/^[a-z0-9.-]+$/.test(h) || h.split('.').some(p=>!p||p.length>63||p.startsWith('-')||p.endsWith('-')) || !h.includes('.') || !/[a-z]/.test(h.split('.').pop())) return null;
   const suffixes=['localhost','local','localdomain','internal','intranet','private','corp','lan','home','home.arpa','test','invalid','example','onion'];
   if(suffixes.some(s=>h===s||h.endsWith('.'+s))) return null;
  }
  return u.href;
 } catch {return null;}
}
function link(value, label='查看原始来源 ↗') {const href=publicURL(value); if(!href) return el('span',label+'（链接不可打开）','muted'); const n=el('a',label); n.href=href; n.target='_blank'; n.rel='noopener noreferrer'; n.referrerPolicy='no-referrer'; return n;}
function notice(value, kind='') {return el('div',value,'notice '+kind);}
function setMessage(id,value) {$(id).textContent=value;}
async function api(path, body, timeout=20000) {
 const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),timeout);
 try {
  const options={signal:controller.signal,credentials:'same-origin',cache:'no-store',redirect:'error',headers:{Accept:'application/json'}};
  if(body!==undefined) {options.method='POST'; options.headers['Content-Type']='application/json'; options.headers['X-Monitor-Token']=TOKEN; options.body=JSON.stringify(body);}
  const response=await fetch(path,options);
  if(!response.ok) throw Error(response.status===409?'资料正在更新，请刷新后重试。':`请求未完成（${response.status}），请重试。`);
  const raw=await response.text(); if(raw.length>2000000) throw Error('数据过多，请缩小范围后重试。');
  try {return JSON.parse(raw);} catch {throw Error('服务返回的数据无法读取。');}
 } catch(error) {if(error.name==='AbortError') throw Error('等待超时，输入已保留，请稍后重试。'); if(error instanceof TypeError) throw Error('无法连接本机服务，请检查运行状态。'); throw error;} finally {clearTimeout(timer);}
}
function evidenceMap(snapshot=state.snapshot) {return new Map(list(snapshot?.evidence,5000).map(e=>[e.id,e]));}
function citationButtons(ids, citations=[],limit=40) {
 const root=el('div',undefined,'citation-row'), known=new Map(list(citations,256).map(c=>[c.evidence_id,c])), current=evidenceMap(), unique=[...new Set(list(ids,256))];
 for(const id of unique.slice(0,limit)) {
  if(!validEvidenceId(id)) {root.append(badge('引用编号无效','bad')); continue;}
  const c=known.get(id)||current.get(id), source=c?.source_id || '证据', revision=c?.revision_number || id.split(':r:')[1];
  const b=button(`${source} · r${revision}`,()=>openEvidence(id).catch(error=>setMessage('global-message',error.message)),'citation');
  b.title=`${text(c?.title||'证据修订',200)} · ${id} · 采集 ${date(c?.collected_at)}`;
  root.append(b);
 }
 if(unique.length>limit)root.append(button(`展开其余 ${unique.length-limit} 份引用`,()=>{const full=citationButtons(ids,citations,256);root.replaceChildren(...full.childNodes);},'citation'));
 if(!root.childNodes.length) root.append(badge('暂无支持证据','warn'));
 return root;
}
function fields(value) {
 if(value===null || typeof value!=='object' || Array.isArray(value)) return el('p',text(value),'prewrap');
 const dl=el('dl',undefined,'kv');
 for(const [key,item] of Object.entries(value).slice(0,18)) {
  dl.append(el('dt',fieldLabels[key]||key)); const dd=el('dd');
  if(key==='url'||key.endsWith('_url')) dd.append(link(item,fieldLabels[key]||'查看链接 ↗'));
  else if(key==='target_evidence_id'&&validEvidenceId(item)) dd.append(citationButtons([item]));
  else if(key==='monitoring')dd.textContent=item==='curated'?'人工精选 · 官方元数据':item==='feed'?'订阅观察':text(item);
  else if(key==='relation') dd.textContent=item==='direct'?'直接关联':item==='background'?'技术背景':text(item);
  else if(key==='field') dd.textContent=conditionName(item);
  else if(key==='conditions'&&Array.isArray(item))dd.textContent=list(item,64).map(c=>`${conditionName(c.field)}：${triLabel(c.equals)}${c.supported===false?'（尚不能判断）':''}`).join('；')||'来源未声明额外前提';
  else if(key==='capabilities'&&item&&typeof item==='object')dd.textContent=Object.entries(item).map(([k,v])=>(capabilityLabels[k]||k)+'：'+triLabel(v)).join('；')||'未知';
  else if(key==='observed_at')dd.textContent=date(item);
  else if(key==='basis')dd.textContent=item==='asset_declared_capabilities'?'授权清单声明的能力组合':text(item);
  else if(key==='pattern')dd.textContent=({prompt_injection_tool_abuse:'提示注入与工具滥用',retrieval_content_poisoning:'检索内容投毒',tool_network_egress:'工具网络外发',tool_write_abuse:'工具写入滥用',sensitive_data_exposure:'敏感数据暴露',untrusted_model_loading:'不可信模型加载'}[item]||text(item));
  else if(key==='verification') dd.textContent=({not_tested:'来源报告，尚未验证',unverified:'未验证'}[item]||text(item));
  else if(key==='availability')dd.textContent=item==='not_checked'?'尚未检查':text(item);
  else if(key==='kind') dd.textContent=({source_reported_patch:'来源报告的修复版本',patch:'补丁',mitigation:'缓解措施',workaround:'临时规避',paper:'研究论文',article:'分析资料',vulnerability:'漏洞公告',policy:'政策',standard:'标准'}[item]||text(item));
  else if(key==='identity_precision') dd.textContent=({package:'明确软件包身份',unmapped:'产品身份尚未映射',cpe_unmapped:'产品标识尚未映射到软件包'}[item]||text(item));
  else if(Array.isArray(item)&&item.every(v=>typeof v!=='object')) dd.textContent=item.map(v=>text(v,600)).join('、')||'暂无';
  else if(typeof item==='boolean') dd.textContent=triLabel(item);
  else dd.textContent=text(item,3000);
  dl.append(dd);
 }
 return dl;
}
function conditionName(value){const names={exposed:'互联网暴露',authenticated:'启用认证',source_conditions:'来源额外前提',version_or_component_mapping:'组件身份、安装版本与适用范围','inventory.observed_at':'清单记录时间与时效性'};return Object.hasOwn(names,value)?names[value]:String(value).startsWith('capabilities.')?capabilityLabels[String(value).slice(13)]||text(value):text(value);}
function warningText(value){
 const general={
  'SBOM is passive component inventory; deployment, exposure, authentication and capabilities are not inferred.':'SBOM 仅提供组件清单；部署情况、互联网暴露、认证状态和其他能力均未据此推断。',
  'observed_at is import time, not SBOM creation time or proof of current installation.':'清单记录时间采用本次导入时间，不是 SBOM 创建时间，也不能证明当前实际安装状态。'
 },component={
  'purl has an invalid category; not mapped.':'软件包标识（purl）的引用类别不符合要求，未用于组件映射。',
  'malformed or conflicting purl identity; ecosystem is unknown.':'软件包标识（purl）格式错误或身份冲突，组件生态保留为未知。',
  'name/group conflicts with purl; ecosystem is unknown.':'组件名称或分组与软件包标识不一致，组件生态保留为未知。',
  'purl type has no supported package ecosystem mapping.':'该软件包类型暂无受支持的生态映射。',
  'case-sensitive legacy npm identity is not mapped by the current matcher.':'此 npm 组件身份包含大小写差异，当前匹配规则无法可靠映射。',
  'version fields conflict; version is unknown.':'版本字段不一致，安装版本保留为未知。',
  'purl qualifiers/subpath are omitted; artifact/platform differences are not represented.':'软件包标识的附加限定条件或子路径未纳入清单，无法区分相关构建产物或平台差异。',
  'no usable purl; ecosystem and client/server identity are unknown.':'没有可用的软件包标识（purl），组件生态以及客户端 / 服务端身份保留为未知。',
  'installed version is unknown.':'安装版本未知，请补充确认。',
  'duplicate projected package identity merged; occurrences are not deployment instances.':'重复的组件身份已合并；文档中的重复条目不代表多个部署实例。'
 };
 if(typeof value!=='string')return value;if(Object.hasOwn(general,value))return general[value];const match=value.match(/^component\[([1-9]\d{0,5})\]: (.+)$/);return match&&Object.hasOwn(component,match[2])?`组件 ${match[1]}：${component[match[2]]}`:value;
}
function warnings(root,items){const rows=list(items,128);for(const item of rows.slice(0,12))root.append(notice(warningText(item),'warn'));if(rows.length>12){const more=el('details');more.append(el('summary',`另有 ${rows.length-12} 条核验提示`));for(const item of rows.slice(12))more.append(notice(warningText(item),'warn'));root.append(more);}}
function factCard(fact) {
 const n=el('article',undefined,'card'); n.append(el('h4',factLabels[fact.predicate]||fact.predicate));
 if(fact.status!=='valid') n.append(badge('待核实候选','warn'));
 if(fact.predicate==='source_metadata'){n.append(notice('这是来源元数据与摘要，不代表已经核验全文或实验结论。'));if(fact.value?.monitoring==='curated')n.append(badge('人工精选 · 官方元数据'));}
 if(fact.predicate==='risk_pattern')n.append(notice('这是清单能力组合的风险提示，不代表已经确认漏洞或发生利用。','warn'));
 if(fact.predicate==='poc_reference') n.append(notice('仅显示未验证线索与来源元数据。','warn'));
 const value=fact.value, hiddenKeys=['locators','locator','rule_version','validation','metrics','evidence_role','score_recomputed','version_consistent','scope','asset_snapshot_id','basis','advisory_evidence_id','material_evidence_id','locator_evidence_id','target_evidence_id','target_evidence_ids','confirmed_vulnerability','confirmed_exploitation','downloaded','executed'];
 if(value&&typeof value==='object'&&!Array.isArray(value)){
  const visible={}, audit={};
  if(fact.predicate==='risk_pattern'){
   const asset=list(state.snapshot?.assets,MAX_ASSETS).find(a=>a.asset_id===value.asset_id);n.append(el('p',asset?.name||value.asset_id||'未关联资产'));n.append(el('p','基于授权清单声明的能力组合','muted'));
   for(const key of ['pattern','capabilities','observed_at'])if(value[key]!==undefined)visible[key]=value[key];if(value.stale===true)n.append(notice('清单时间已经过期，此提示需要通过新清单重新核对。','warn'));
   for(const [key,item] of Object.entries(value))if(!Object.hasOwn(visible,key))audit[key]=item;
  }else for(const [key,item] of Object.entries(value))(hiddenKeys.includes(key)?audit:visible)[key]=item;
  if(fact.predicate==='impact'&&value.metrics&&typeof value.metrics==='object'){const labels={C:'机密性',I:'完整性',A:'可用性',VC:'系统机密性',VI:'系统完整性',VA:'系统可用性',SC:'后续系统机密性',SI:'后续系统完整性',SA:'后续系统可用性'}, impacts={};for(const [key,label] of Object.entries(labels))if(Object.hasOwn(value.metrics,key))impacts[label]=({H:'高',L:'低',N:'无',P:'部分',C:'完全'}[value.metrics[key]]||text(value.metrics[key]));if(Object.keys(impacts).length)n.append(el('p','来源 CVSS 描述的影响等级','muted'),fields(impacts));n.append(notice('评分口径的影响不等于已证明资产被利用。'));}
  n.append(fields(visible));if(Object.keys(audit).length){const details=el('details');details.append(el('summary','查看核验信息'),fields(audit));n.append(details);}
 }else n.append(fields(value));
 n.append(citationButtons(fact.evidence_ids)); return n;
}
function assessmentCard(assessment, event) {
 const asset=list(state.snapshot?.assets,MAX_ASSETS).find(a=>a.asset_id===assessment.asset_id), warn=['potentially_affected','under_investigation'].includes(assessment.status), n=el('article',undefined,'card'+(warn?' warn':''));
 n.append(el('h4',asset?.name||assessment.asset_id),badge(assessmentLabels[assessment.status]||'状态未知',warn?'warn':'ok'));
 if(event) n.append(el('p',event.title,'muted'));
 n.append(el('p',`${matchLabels[assessment.version_match]||'版本适用性未知'} · ${asset?.component||'组件未知'} ${versionLabel(asset?.version)}`,'muted'));
 if(asset) n.append(el('p',`${age(asset.observed_at)} · ${date(asset.observed_at)}`,'muted'));
 for(const reason of list(assessment.reasons,12)) n.append(el('p',reason,'prewrap'));
 if(list(assessment.missing_conditions).length) n.append(notice('仍需核对：'+list(assessment.missing_conditions,12).map(x=>text(x==='authenticated'?'是否启用认证':x==='exposed'?'是否暴露于互联网':conditionName(x),300)).join('；'),'warn'));
 n.append(citationButtons(assessment.evidence_ids)); return n;
}
function showView(view) {
 const titles={chat:['证据驱动的安全研判','理解影响，厘清条件，把每个判断追溯到来源。'],overview:['把变化，转化为可核验情报','按当前状态查看来源、组件范围、资产适用性与修复依据。'],knowledge:['让安全知识有据可查','官方标准、政策与指南的元数据，明确区分人工精选和订阅观察。'],assets:['从授权清单，看见资产影响','保留组件身份、记录时间和未知项，支持文本表格与被动 SBOM 导入。'],status:['跟踪来源与处理进度','来源数量、覆盖类别和处理状态均来自本机记录。'],model:['为研判选择回答引擎','配置本机事实模式、离线 Mock、Ollama，或明确启用官方 DeepSeek 云端推理。']};
 if(!titles[view])return;state.view=view;
 for(const key of Object.keys(titles))$('view-'+key).hidden=key!==view;
 for(const n of document.querySelectorAll('[data-view]')){if(n.dataset.view===view)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current');}
 $('page-title').textContent=titles[view][0];$('page-subtitle').textContent=titles[view][1];
 if(view==='model'&&!state.modelFormReady&&!state.modelLoading)loadModel();
 if(view==='knowledge'&&!state.knowledge&&!state.knowledgeLoading)loadKnowledge();
}
function filteredEvents() {const query=$('search').value.trim().toLocaleLowerCase(), wanted=$('event-state').value; return list(state.snapshot?.events,5000).filter(e=>(!wanted||e.status===wanted)&&(!query||[e.title,...list(e.aliases,30)].some(v=>text(v,2000).toLocaleLowerCase().includes(query))));}
function renderEvents() {
 const all=filteredEvents(), pages=Math.max(1,Math.ceil(all.length/PAGE_SIZE)); state.page=Math.min(state.page,pages-1); const root=$('events'); root.replaceChildren();
 $('event-count').textContent=`${all.length} 条`; $('page-number').textContent=`第 ${state.page+1} / ${pages} 页`; $('prev').disabled=state.page===0; $('next').disabled=state.page>=pages-1;
 for(const e of all.slice(state.page*PAGE_SIZE,(state.page+1)*PAGE_SIZE)) {
  const n=el('article',undefined,'record'); n.append(button(e.title,()=>selectEvent(e.id).catch(error=>setMessage('global-message',error.message)),'record-title'));
  const row=el('div',undefined,'row'); row.append(badge(eventLabels[e.status]||'状态未知',e.status==='ready'?'ok':'warn'));
  for(const alias of list(e.aliases,3)) row.append(badge(alias));
  row.append(el('span',`${list(e.evidence_ids).length} 份证据`,'muted')); n.append(row);
  const ev=evidenceMap().get(list(e.evidence_ids)[0]); if(ev?.summary) n.append(el('p',ev.summary,'excerpt'));
  const impacts=e.status==='ready'?list(e.assessments).filter(a=>['potentially_affected','under_investigation'].includes(a.status)).length:0;
  n.append(el('p',e.status==='ready'?`${list(e.facts,256).length} 项富化 · ${impacts} 项资产待关注`:'当前判断正在重新核验，历史证据仍可追溯。','muted')); root.append(n);
 }
 if(!all.length) empty(root,state.snapshot?'暂无匹配情报':'等待首次同步',state.snapshot?'调整关键词或筛选条件，或到运行状态查看来源。':'连接成功后会显示来源和处理结果。');
}
function renderStats() {
 const events=list(state.snapshot?.events,5000), ready=events.filter(e=>e.status==='ready');
 if(!state.snapshot){for(const id of ['stat-events','stat-ready','stat-impact','stat-pending'])$(id).textContent='—';$('stage-monitor').textContent='等待来源状态';$('stage-enrich').textContent='等待当前证据';$('stage-assets').textContent='等待授权清单';renderContext();return;}
 $('stat-events').textContent=events.length; $('stat-ready').textContent=ready.length;
 $('stat-impact').textContent=ready.flatMap(e=>list(e.assessments)).filter(a=>['potentially_affected','under_investigation'].includes(a.status)).length;
 $('stat-pending').textContent=events.filter(e=>e.status!=='ready').length;
 const sources=list(state.system?.monitoring?.sources,100),categories=new Set(sources.map(s=>s.category).filter(v=>typeof v==='string'&&v));
 $('stage-monitor').textContent=`${sources.length} 个来源 · ${categories.size} 类覆盖`;
 $('stage-enrich').textContent=`${ready.length} 条可用 · ${events.length-ready.length} 条待更新`;
 $('stage-assets').textContent=`${list(state.snapshot?.assets,MAX_ASSETS).length} 项授权资产`;
 $('stage-chat').textContent=state.system?.model?.enabled?(state.system.model.provider==='deepseek'?'云端推理 · 逐条核验':state.system.model.provider==='mock'?'Mock 离线流程 · 逐条核验':'本机模型 · 逐条核验'):'结构化事实与关键词问答';renderContext();
}
function renderDetail(event) {
 const root=$('event-detail'); root.replaceChildren();
 if(!event) {empty(root,'从一条情报开始','选择条目，查看依据和与你的资产有关的判断。'); return;}
 const head=el('div',undefined,'detail-head'), row=el('div',undefined,'row'); row.append(badge(eventLabels[event.status]||'状态未知',event.status==='ready'?'ok':'warn')); if(state.snapshot?.demo) row.append(badge('虚构演示','warn'));
 head.append(row,el('h2',event.title),el('p',list(event.aliases,10).join(' · '),'muted')); root.append(head);
 if(event.status!=='ready') root.append(notice(event.status==='quarantined'?'实体关联需要核对。当前事实、资产判断和问答已暂停使用此条目。':'来源或清单已变化，当前事实与资产判断暂不可用。可在运行状态继续处理。','warn'));
 warnings(root,event.warnings);
 if(event.status==='ready') {
  const facts=list(event.facts,256), sections=[['范围与评分',['affected_component','affected_range','cvss','weakness','condition','impact','risk_pattern']],['修复与缓解',['fix']],['关联资料与线索',['related_material','poc_reference']],['资料元数据',['source_metadata']]];
  for(const [title,predicates] of sections) {const block=el('section',undefined,'detail-block'), cards=el('div',undefined,'cards'); block.append(el('h3',title)); const chosen=facts.filter(f=>predicates.includes(f.predicate)); for(const fact of chosen)cards.append(factCard(fact)); if(!chosen.length)cards.append(notice(title==='修复与缓解'?'当前有效来源未提供可核验修复建议。':'当前尚无对应证据。')); block.append(cards); root.append(block);}
  const known=sections.flatMap(s=>s[1]), other=facts.filter(f=>!known.includes(f.predicate));if(other.length){const block=el('section',undefined,'detail-block');block.append(el('h3','其他富化信息'));for(const fact of other)block.append(factCard(fact));root.append(block);}
  const impacts=el('section',undefined,'detail-block'); impacts.append(el('h3','授权资产影响')); const cards=el('div',undefined,'cards'); for(const a of list(event.assessments,MAX_ASSETS))cards.append(assessmentCard(a)); if(!cards.childNodes.length)cards.append(notice('暂无资产匹配结果。导入授权清单后可继续判断。')); impacts.append(cards); root.append(impacts);
 }
 const support=el('section',undefined,'detail-block'); support.append(el('h3','来源与修订'),citationButtons(event.evidence_ids)); root.append(support);
 if(event.status==='quarantined')root.append(entityConfirmation(event));
 const ask=button('询问这条情报',()=>{showView('chat'); $('question').value=`${list(event.aliases)[0]||event.title} 的影响范围、资产适用条件和修复依据是什么？`; $('question').focus();},'primary'); ask.disabled=event.status!=='ready'; root.append(el('p','', 'help'),ask);
}
function partitionPayload(event,assignments,reason) {
 if(event.status!=='quarantined'||!validEventId(event.id)||!Number.isSafeInteger(event.generation)||event.generation<1)throw Error('此条目需要重新读取后再核对。');
 const ids=list(event.evidence_ids,200), known=evidenceMap();if(!Array.isArray(event.evidence_ids)||!ids.length||ids.length!==event.evidence_ids.length||ids.some(id=>!validEvidenceId(id)||!known.has(id)||!Number.isSafeInteger(known.get(id).observation_id)||known.get(id).observation_id<1))throw Error('可见证据不完整，请刷新后再核对。');
 const observations=[...new Set(ids.map(id=>known.get(id).observation_id))];
 if(!observations.length||observations.length>50||Object.keys(assignments).length!==observations.length)throw Error('可见证据不足以形成完整分区，请刷新后重试。');
 const groups=new Map();for(const id of observations){const chosen=Number(assignments[id]);if(!Number.isInteger(chosen)||chosen<1||chosen>observations.length)throw Error('请为每份来源选择实体归属。');if(!groups.has(chosen))groups.set(chosen,[]);groups.get(chosen).push(id);}
 const explanation=String(reason||'').trim();if(!explanation||explanation.length>1000)throw Error('请填写不超过 1000 字的核对理由。');
 return {event_id:Number(event.id),groups:[...groups.values()],reason:explanation,expected_generation:event.generation};
}
function entityConfirmation(event) {
 const advanced=el('details',undefined,'detail-block');advanced.append(el('summary','核对实体归属（高级）'),notice('将确属同一事件的来源分到同一组。请先查看原始修订；若证据不全，保留待核对状态。','warn'));
 if(event.quarantine_reason)advanced.append(el('p',event.quarantine_reason,'help'));
 const form=el('form'), assignments={}, observations=[...new Map(list(event.evidence_ids,200).map(id=>evidenceMap().get(id)).filter(Boolean).map(e=>[e.observation_id,e])).values()];
 if(!observations.length||observations.length>50){advanced.append(notice('可见来源不足或超过本页核对上限，请由管理员核对。'));return advanced;}
 for(const evidence of observations){const row=el('label',undefined,'field'), select=el('select');row.append(el('span',`${evidence.source_id} · 观察 ${evidence.observation_id} · ${text(evidence.title,180)}`));const blank=el('option','请选择实体组');blank.value='';select.append(blank);for(let i=1;i<=observations.length;i++){const option=el('option','实体组 '+i);option.value=String(i);select.append(option);}assignments[evidence.observation_id]='';select.addEventListener('change',()=>assignments[evidence.observation_id]=select.value);row.append(select);form.append(row);}
 const reason=el('textarea');reason.rows=3;reason.maxLength=1000;const label=el('label',undefined,'field');label.append(el('span','核对理由'),reason);form.append(label);const submit=el('button','确认分区并重新核验','primary');submit.type='submit';const message=el('p','核对期间如果来源再次更新，提交会被拒绝并要求刷新。','help');message.setAttribute('role','status');form.append(submit,message);
 let busy=false;form.addEventListener('submit',async e=>{e.preventDefault();if(busy)return;let payload;try{payload=partitionPayload(event,assignments,reason.value);}catch(error){message.textContent=error.message;return;}const baselineEpoch=state.snapshot?.knowledge_epoch;busy=true;submit.disabled=true;try{const result=await api('/api/entities/confirm',payload);invalidateCurrent(result,baselineEpoch);setMessage('global-message','实体分区已确认，当前影响与回答等待重新核验。');await refresh();}catch(error){message.textContent=error.message;}finally{busy=false;submit.disabled=false;}});advanced.append(form);return advanced;
}
async function selectEvent(id) {
 if(!validEventId(id)) throw Error('情报编号无效。');
 state.selected=Number(id); const sequence=++state.detailSequence,baselineEpoch=state.snapshot?.knowledge_epoch; empty($('event-detail'),'正在读取证据…');
 try {const event=await api('/api/events/'+Number(id)); if(sequence!==state.detailSequence || state.selected!==Number(id)) return; const current=list(state.snapshot?.events,5000).find(e=>e.id===Number(id));const newer=current&&Number(event.generation)>Number(current.generation)||event.stale===true||Number(event.knowledge_epoch)>Number(state.snapshot?.knowledge_epoch);state.detail=event;
  if(newer){invalidateCurrent(event,baselineEpoch);const pending={...event,status:event.status==='quarantined'?'quarantined':'dirty',facts:[],assessments:[]};if(state.snapshot)state.snapshot.events=state.snapshot.events.map(e=>e.id===Number(id)?pending:e);renderEvents();renderChat();renderDetail(pending);await refresh();}
  else renderDetail(current?{...event,...current}:event);
 } catch(error){if(sequence===state.detailSequence)empty($('event-detail'),'详情未读取成功',error.message); throw error;}
}
function renderInventory() {
 const assets=list(state.snapshot?.assets,MAX_ASSETS), root=$('inventory-table'); root.replaceChildren();
 $('inventory-summary').textContent=assets.length?`当前快照包含 ${assets.length} 项资产。清单记录时间分别保留，旧清单可能与实际配置不同；SBOM 记录时间可为导入时间，不代表安装状态已被探测验证。`:'还没有授权清单。可以在下方填写，或载入虚构示例体验流程。';
 if(assets.length) {const table=el('table'), head=el('tr'); for(const label of ['资产 / 组件','版本 / 生态','暴露 / 认证','清单时间'])head.append(el('th',label)); const thead=el('thead');thead.append(head);table.append(thead); const tbody=el('tbody'); for(const a of assets){const tr=el('tr'), identity=el('td',a.name); identity.append(el('small',a.asset_id),el('small',a.component)); const version=el('td',versionLabel(a.version));version.append(el('small',a.ecosystem));const timestamp=el('td',date(a.observed_at));timestamp.append(el('small',age(a.observed_at)));tr.append(identity,version,el('td',`${triLabel(a.exposed)} / ${triLabel(a.authenticated)}`),timestamp);tbody.append(tr);}table.append(tbody);root.append(table);}
 const impacts=$('asset-impacts'); impacts.replaceChildren();
 const events=list(state.snapshot?.events,5000); for(const event of events.filter(e=>e.status==='ready')) for(const a of list(event.assessments,MAX_ASSETS)) impacts.append(assessmentCard(a,event));
 if(events.some(e=>e.status!=='ready')) impacts.prepend(notice('部分情报正在更新或核对，相关旧资产判断暂不显示。','warn'));
}
function blankAsset() {return {asset_id:'',name:'',ecosystem:'PyPI',component:'',version:'',exposed:null,authenticated:null,observed_at:'',capabilities:{}};}
function localTime(iso) {if(!iso) return ''; const d=new Date(iso);if(!Number.isFinite(d.getTime()))return '';const adjusted=new Date(d.getTime()-d.getTimezoneOffset()*60000);return adjusted.toISOString().slice(0,19);}
function triSelect(value, change, label) {const n=el('select');n.setAttribute('aria-label',label);for(const [v,label] of [['','未知'],['true','是'],['false','否']]){const opt=el('option',label);opt.value=v;n.append(opt);}n.value=value===true?'true':value===false?'false':'';n.addEventListener('change',()=>change(n.value===''?null:n.value==='true'));return n;}
function assetField(row,key,label,placeholder='',maxlength=160) {const wrap=el('label',undefined,'field');wrap.append(el('span',label));const input=el('input');input.value=row[key]||'';input.placeholder=placeholder;input.maxLength=maxlength;input.addEventListener('input',()=>row[key]=input.value);wrap.append(input);return wrap;}
function renderDraft() {
 const root=$('asset-editor');root.replaceChildren();
 state.draft.forEach((row,index)=>{
  const n=el('section',undefined,'asset-form'), heading=el('div',undefined,'row');heading.append(el('h3',`资产 ${index+1}`),button('移除',()=>{state.draft.splice(index,1);renderDraft();}));n.append(heading);
  const grid=el('div',undefined,'form-grid');grid.append(assetField(row,'asset_id','资产 ID','例如 inference-prod',64),assetField(row,'name','资产名称','便于识别的名称',120),assetField(row,'ecosystem','组件生态','例如 PyPI / Go / npm',40),assetField(row,'component','组件名称','清单中的准确组件身份',160),assetField(row,'version','安装版本','留空表示未知',120));
  const timestamp=el('label',undefined,'field');timestamp.append(el('span','清单时间（本机时区）'));const time=el('input');time.type='datetime-local';time.step='1';time.value=localTime(row.observed_at);time.addEventListener('input',()=>row.observed_at=time.value?new Date(time.value).toISOString():'');timestamp.append(time,el('small','填写清单实际记录时间，不会自动改成提交时间。'));grid.append(timestamp);
  for(const [key,label] of [['exposed','互联网暴露'],['authenticated','启用认证']]){const wrap=el('label',undefined,'field');wrap.append(el('span',label),triSelect(row[key],value=>row[key]=value,label));grid.append(wrap);}n.append(grid);
  const advanced=el('details');advanced.append(el('summary','可确认的其他前提（可选）'),el('p','仅记录清单已经确认的布尔能力。未知前提不会被认作“否”。','help'));const caps=el('div',undefined,'form-grid');
  for(const [key,label] of Object.entries(capabilityLabels)){const field=el('label',undefined,'field');field.append(el('span',label),triSelect(row.capabilities[key],value=>{if(value===null)delete row.capabilities[key];else row.capabilities[key]=value;},label));caps.append(field);}
  advanced.append(caps);n.append(advanced);if(state.saving||state.sbomSaving)for(const control of n.querySelectorAll('input,select,button'))control.disabled=true;root.append(n);
 });
 $('add-asset').disabled=state.draft.length>=MAX_ASSETS||state.saving||state.sbomSaving; $('save-assets').disabled=state.saving||state.sbomSaving||!state.draft.length;
 for(const id of ['edit-assets','example-assets','parse-import','import-file','import-text'])$(id).disabled=state.saving||state.sbomSaving;syncSBOMControls();
}
function parseTri(value) {const s=String(value??'').trim().toLowerCase();if(['','未知','unknown','null'].includes(s))return null;if(['true','是','1'].includes(s))return true;if(['false','否','0'].includes(s))return false;throw Error('暴露与认证请填写“是 / 否 / 未知”。');}
function isoTime(value) {const s=String(value||'').trim(), pattern=/^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})$/;const match=s.match(pattern);if(!match)throw Error('清单时间必须是带时区的 ISO 时间。');const [year,month,day]=match.slice(1,4).map(Number), days=new Date(Date.UTC(year,month,0)).getUTCDate();if(month<1||month>12||day<1||day>days||!Number.isFinite(Date.parse(s)))throw Error('清单时间无效。');return new Date(s).toISOString();}
function validateAssets(rows) {
 if(!Array.isArray(rows)||rows.length<1||rows.length>MAX_ASSETS)throw Error('请填写 1–256 项授权资产；文本表格单次最多读取 100 项。');const ids=new Set();
 return rows.map((row,index)=>{
  const allowed=['asset_id','name','ecosystem','component','version','exposed','authenticated','observed_at','capabilities'];if(Object.keys(row).some(k=>!allowed.includes(k)))throw Error(`第 ${index+1} 项包含不支持的字段。`);
  const result={};for(const [key,max] of [['asset_id',64],['name',120],['ecosystem',40],['component',160],['version',120]]){if(typeof row[key]!=='string')throw Error(`第 ${index+1} 项的字段格式不正确。`);result[key]=row[key].trim();if(result[key].length>max||/[\x00-\x1f\x7f]/.test(result[key]))throw Error(`第 ${index+1} 项的字段过长或包含控制字符。`);if(/bearer\s+\S+|(?:password|api[_-]?key|secret|token)\s*[:=]|https?:\/\/\S+@/i.test(result[key]))throw Error('清单字段不能包含凭据。');}
  if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(result.asset_id)||!result.name||!result.ecosystem||!result.component)throw Error(`第 ${index+1} 项需要资产 ID、名称、生态和组件；ID 使用字母、数字、点或短横线。`);
  if(!result.version)result.version='unknown';
  if(ids.has(result.asset_id))throw Error('资产 ID 重复，请先核对。');ids.add(result.asset_id);
  for(const key of ['exposed','authenticated']){if(row[key]!==null&&typeof row[key]!=='boolean')throw Error('暴露与认证状态格式无效。');result[key]=row[key];}
  result.observed_at=isoTime(row.observed_at);if(Date.parse(result.observed_at)>Date.now()+300000)throw Error('清单时间晚于当前时间，请核对。');
  const caps=row.capabilities;if(!caps||Array.isArray(caps)||typeof caps!=='object'||Object.keys(caps).length>12)throw Error('前提能力格式无效。');result.capabilities={};
  for(const [key,value] of Object.entries(caps)){if(!Object.hasOwn(capabilityLabels,key)||typeof value!=='boolean')throw Error('前提仅支持外部文档、RAG、工具、网络和写入权限，并且值须为是 / 否。');result.capabilities[key]=value;}
  return result;
 });
}
function parseTable(raw) {
 if(typeof raw!=='string'||new TextEncoder().encode(raw).length>65536)throw Error('表格应为不超过 64 KB 的文本。');raw=raw.replace(/^\uFEFF/,'');const delimiter=raw.split(/\r?\n/)[0].includes('\t')?'\t':',';
 const rows=[];let row=[],cell='',quoted=false,closed=false;
 for(let i=0;i<=raw.length;i++){const ch=i===raw.length?'\n':raw[i];if(quoted){if(ch==='"'){if(raw[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else{if(i===raw.length)throw Error('表格中的引号未闭合。');cell+=ch;}continue;}if(ch==='"'){if(cell||closed)throw Error('表格中的引号格式无效。');quoted=true;continue;}if(ch===delimiter||ch==='\n'||ch==='\r'){row.push(cell.trim());cell='';closed=false;if(ch!==delimiter){if(ch==='\r'&&raw[i+1]==='\n')i++;if(row.some(v=>v!==''))rows.push(row);row=[];if(rows.length>MAX_IMPORT_ASSETS+1)throw Error('一次最多导入 100 项资产。');}continue;}if(closed&&ch!==' '&&ch!=='\t')throw Error('引号后的表格字符无效。');if(!closed)cell+=ch;}
 if(rows.length<2)throw Error('表格需要表头和至少一行资产。');
 const headers={资产ID:'asset_id',资产编号:'asset_id',名称:'name',资产名称:'name',生态:'ecosystem',组件:'component',版本:'version',暴露:'exposed',认证:'authenticated',清单时间:'observed_at',能力:'capabilities'};
 const columns=rows.shift().map(h=>headers[h]||h);const allowed=['asset_id','name','ecosystem','component','version','exposed','authenticated','observed_at','capabilities'];if(columns.some(c=>!allowed.includes(c))||new Set(columns).size!==columns.length||['asset_id','name','ecosystem','component','observed_at'].some(c=>!columns.includes(c)))throw Error('表头不完整或含不支持的字段，请使用导入示例。');
 const assets=rows.map(values=>{if(values.length!==columns.length)throw Error('表格列数与表头不同，请核对。');const asset=blankAsset();columns.forEach((key,i)=>{if(['exposed','authenticated'].includes(key))asset[key]=parseTri(values[i]);else if(key==='capabilities'){const caps={};for(const part of values[i].split(';').filter(Boolean)){const pair=part.split('='),name=pair[0].trim();if(pair.length!==2||!Object.hasOwn(capabilityLabels,name))throw Error('能力列仅支持 external_documents、rag、tools、network、write_access 的布尔值。');if(Object.hasOwn(caps,name))throw Error('能力列包含重复项。');const v=parseTri(pair[1]);if(v!==null)caps[name]=v;}asset.capabilities=caps;}else asset[key]=values[i];});return asset;});return validateAssets(assets);
}
async function saveAssets(event) {
 event.preventDefault();if(state.saving||state.sbomSaving)return;let assets;try{assets=validateAssets(state.draft);}catch(error){setMessage('asset-message',error.message);return;}
 const baselineEpoch=state.snapshot?.knowledge_epoch;state.saving=true;renderDraft();setMessage('asset-message','正在提交清单…');
 try{const response=await api('/api/assets',{assets});invalidateCurrent(response,baselineEpoch);setMessage('asset-message',`已保存 ${response.count} 项资产，正在重新核验影响。`);await refresh();}catch(error){setMessage('asset-message',error.message);}finally{state.saving=false;renderDraft();}
}
function answerFreshness(answer,snapshot=state.snapshot) {
 if(answer.mode==='pending')return {label:'资料更新中 · 旧结论未发布',kind:'warn'};
 if(answer.history_stale===true)return {label:'历史记录 · 待重新核验',kind:'warn'};
 if(!snapshot)return {label:'尚未核对当前状态',kind:'warn'};
 const cited=new Set([...list(answer.citations,256).map(c=>c.evidence_id),...list(answer.claims,100).flatMap(c=>list(c.evidence_ids,256))]);const evidence=list(snapshot.evidence,5000);
 for(const id of cited){const original=evidence.find(e=>e.id===id);const match=String(id).match(/^obs:(\d+):r:(\d+)$/);if(original?.withdrawn||match&&evidence.some(e=>e.observation_id===Number(match[1])&&e.revision_number>Number(match[2])))return {label:'引用已撤回或修订 · 历史回答',kind:'bad'};}
 if(list(answer.entities,100).some(id=>list(snapshot.events,5000).some(e=>e.id===id&&e.status!=='ready')))return {label:'相关情报正在更新 · 待重新核验',kind:'warn'};
 if(answer.knowledge_epoch!==snapshot.knowledge_epoch||answer.asset_snapshot_id!==undefined&&answer.asset_snapshot_id!==snapshot.asset_snapshot_id||answer.policy_generation!==undefined&&answer.policy_generation!==snapshot.policy_generation)return {label:'资料已更新 · 待重新核验',kind:'warn'};
 if([...cited].some(id=>!evidence.some(e=>e.id===id&&!e.withdrawn)))return {label:'引用未在当前快照核对 · 历史回答',kind:'warn'};
 return {label:'已核验回答快照',kind:'ok'};
}
const traceLabels={retrieval:'检索当前证据',start:'开始有界编排',generation:'整理检索规划或回答',tool:'只读工具取证',finish:'结束本次编排',model_error:'模型请求未完成',planning:'理解问题与检索规划',synthesis:'组织有依据的回答',schema_validation:'核对输出结构',grounding:'核验事实与引用'};
function renderTrace(trace) {
 const root=el('div'), allowed=['action','tool','kind','stage','event','method','status','name','number','depth','events','cards','tools','code','retry_after','generation_count','tool_call_count'];
 for(const [index,step] of list(trace,128).entries()){const n=el('div',undefined,'trace-step');n.append(el('strong',`${index+1}. ${typeof step==='string'?text(step,2000):text(traceLabels[step?.stage||step?.event]||step?.action||step?.tool||step?.kind||'证据核验',200)}`));if(typeof step==='object'&&step!==null)n.append(fields(Object.fromEntries(allowed.filter(k=>Object.hasOwn(step,k)).map(k=>[k,['event','stage'].includes(k)?traceLabels[step[k]]||text(step[k],100):k==='status'?({ok:'完成',complete:'完成',failed:'未完成',error:'失败',repeated:'重复调用已限制'}[step[k]]||text(step[k],100)):k==='method'?({llm_semantic:'模型语义检索',mock_plan:'Mock 检索规划',keywords:'关键词检索',exact:'精确检索'}[step[k]]||text(step[k],100)):step[k]]))));root.append(n);}
 if(!root.childNodes.length)root.append(el('p','此次回答没有额外工具路径。','help'));return root;
}
function chatIntro(root) {
 const n=el('div',undefined,'chat-intro');n.append(el('div','AI','intro-symbol'),el('div','EVIDENCE-DRIVEN RESEARCH','eyebrow'),el('h3','把安全问题，问到证据上'),el('p','从影响范围到修复步骤，结合授权清单与当前来源。核验事实、模型分析和条件未知分别呈现，支持继续追问。','muted'));
 if(state.sessionId){n.append(notice(state.sessionLoading?'正在恢复已有会话的历史消息…':state.sessionLoadError||'此会话当前没有可显示的历史消息。可以继续提问，或重新读取。',state.sessionLoadError?'warn':''));if(!state.sessionLoading)n.append(button('重新读取历史',()=>loadSession(state.sessionId,true)));}
 const prompts=el('div',undefined,'prompts');for(const [title,summary,q] of [['影响范围','定位组件与授权资产的适用条件','哪些授权资产可能受影响，判断依据是什么？'],['修复步骤','梳理来源支持的修复与验证顺序','有哪些修复建议？哪些条件还需要核对？'],['预防与调查','区分可采取的建议与仍然未知的前提','基于已有证据，有哪些预防和调查建议？哪些结论还不能确认？'],['证据链','追溯公告、研究背景与来源修订','展示相关资料的证据链：哪些是直接证据，哪些是技术背景？']]){const b=button('',()=>{$('question').value=q;$('question').focus();});b.append(el('strong',title),el('span',summary));prompts.append(b);}n.append(prompts);root.append(n);
}
function supportedAnalysis(answer) {
 if(!Array.isArray(answer.analysis_sections)||answer.analysis_sections.length>8)return [];
 const claims=new Map(list(answer.claims,100).filter(c=>typeof c.id==='string').map(c=>[c.id,c])),result=[];let length=0;
 for(const section of answer.analysis_sections){if(!section||typeof section!=='object'||Array.isArray(section)||Object.keys(section).sort().join(',')!=='claim_ids,evidence_ids,kind,text'||!['analysis','recommendation','uncertainty'].includes(section.kind)||typeof section.text!=='string'||!section.text.trim()||section.text.length>1200||!Array.isArray(section.claim_ids)||!section.claim_ids.length||section.claim_ids.length>64||new Set(section.claim_ids).size!==section.claim_ids.length||section.claim_ids.some(id=>!claims.has(id))||!Array.isArray(section.evidence_ids)||section.evidence_ids.length>128||section.evidence_ids.some(id=>!validEvidenceId(id)))continue;
  const expected=[...new Set(section.claim_ids.flatMap(id=>list(claims.get(id).evidence_ids,256)))].sort(),refs=[...new Set(section.evidence_ids)].sort();if(refs.length!==section.evidence_ids.length||expected.length!==refs.length||expected.some((id,i)=>id!==refs[i]))continue;
  length+=section.text.length;if(length>6000)return [];result.push({kind:section.kind,text:section.text,claim_ids:section.claim_ids.slice(),evidence_ids:refs});
 }return result;
}
function renderChat() {
 const root=$('transcript'),messages=state.chats.get(state.sessionId)||[];root.replaceChildren();root.setAttribute('aria-busy',String(state.asking||state.sessionLoading));if(!messages.length)chatIntro(root);
 for(const item of messages){const user=el('div',undefined,'message user');user.append(el('p',item.question,'prewrap'));root.append(user);const n=el('article',undefined,'message assistant'),answer=item.answer;let freshness=answerFreshness(answer);if(freshness.kind!=='bad'&&state.pendingCurrent&&answer.mode!=='pending')freshness={label:'资料已变化 · 历史回答待重新核验',kind:'warn'};else if(freshness.kind==='ok'&&!state.connected)freshness={label:'连接中断 · 历史回答待重新核验',kind:'warn'};
  const meta=el('div',undefined,'meta');meta.append(badge({facts:'结构化事实',local_model:'本机模型辅助',mock_model:'Mock 离线生成 · 演示',cloud_model:'DeepSeek 云端研判',degraded:'降级回答',pending:'等待重新核验',history:'历史记录'}[answer.mode]||'回答方式未知',['degraded','pending','history','mock_model'].includes(answer.mode)?'warn':''),badge(freshness.label,freshness.kind));if(state.snapshot?.demo)meta.append(badge('虚构演示','warn'));if(answer.mode==='cloud_model'&&answer.model==='deepseek-v4-pro')meta.append(badge('V4 Pro'));if(answer.retrieval==='llm_semantic')meta.append(badge('模型语义检索'));if(answer.retrieval==='mock_plan')meta.append(badge('Mock 检索规划 · 非真实模型','warn'));meta.append(el('span','回答快照 '+date(answer.as_of),'muted'));n.append(meta);if(answer.mode==='mock_model')n.append(notice('Mock 离线流程演示：检索规划、工具读取、结构校验与引用核验在本机运行。没有连接 DeepSeek，也不表示真实模型已通过验收。','warn'));
  const claims=list(answer.claims,100),nodes=new Map();if(!claims.length)n.append(el('p',answer.answer,'answer-text'));else n.append(el('h3','已核验事实','answer-heading'),el('p','以下事实来自当前回答所引用的来源；修订状态见上方快照标记。','answer-subtitle'));
  for(const [index,claim] of claims.entries()){const c=el('div',undefined,'claim');c.setAttribute('tabindex','-1');c.append(el('div',`事实 ${index+1}`,'claim-number'),el('p',claim.text),citationButtons(claim.evidence_ids,answer.citations));n.append(c);if(typeof claim.id==='string')nodes.set(claim.id,{node:c,index});}
  const sections=supportedAnalysis(answer);if(sections.length){n.append(el('h3',answer.mode==='mock_model'?'Mock 分析与建议 · 离线演示':'模型分析与建议','answer-heading'),el('p',answer.mode==='mock_model'?'以下为 Mock 根据已核验事实生成的流程演示，不能证明真实模型的理解与推理质量。':'以下为模型基于已核验事实的归纳与建议，仍需核对适用条件。','answer-subtitle'));for(const section of sections){const c=el('section',undefined,'analysis-section'+(section.kind==='uncertainty'?' uncertainty':''));c.append(el('div',{analysis:'分析 · 模型推断',recommendation:'建议 · 需核对适用条件',uncertainty:'条件未知 · 仍需调查'}[section.kind],'analysis-label'),el('p',section.text));const links=el('div',undefined,'citation-row');for(const id of section.claim_ids){const target=nodes.get(id);if(target)links.append(button('依据事实 '+(target.index+1),()=>{target.node.scrollIntoView({block:'center'});target.node.focus();},'citation'));}c.append(links,citationButtons(section.evidence_ids,answer.citations));n.append(c);}n.append(el('p','分析段字段与引用结构已核对；结构校验不证明语义正确。','help'));}
  if(claims.length){const combined=el('details');combined.append(el('summary','展开合并全文'),el('p',answer.answer,'answer-text'));n.append(combined);}
  if(!claims.length)n.append(notice(answer.mode==='pending'?'请等待处理完成后，用当前证据重新提问。':'此回答没有逐条支持的事实，请结合未知项和引用核对。','warn'));
  warnings(n,answer.warnings);
  const citations=el('details');citations.append(el('summary','来源、修订与采集时间'));for(const c of list(answer.citations,256)){const entry=el('section',undefined,'evidence-section');entry.append(el('h4',c.title),fields({source_id:c.source_id,id:c.upstream_id,version:'r'+c.revision_number,collected_at:date(c.collected_at)}),citationButtons([c.evidence_id],answer.citations),link(c.url));citations.append(entry);}n.append(citations);
  const path=el('details');path.append(el('summary','查看证据路径与处理记录'),renderTrace(answer.trace));n.append(path);if(freshness.kind!=='ok')n.append(button('用当前证据重新提问',()=>{$('question').value=item.question;$('question').focus();}));root.append(n);
 }
 if(state.asking)root.append(el('div','正在检索当前证据、整理回答并核验引用…','progress-note'));root.scrollTop=root.scrollHeight;
}
function renderSessions() {
 const select=$('sessions');select.replaceChildren();const first=el('option','新的会话');first.value='';select.append(first);const seen=new Set(['']);
 for(const s of list(state.system?.sessions,50)){if(!validSessionId(s.id)||seen.has(s.id))continue;const option=el('option',s.title||'已有会话');option.value=s.id;select.append(option);seen.add(s.id);}
 for(const [id,messages] of state.chats){if(!id||seen.has(id))continue;const option=el('option',messages[0]?.question||'当前会话');option.value=id;select.append(option);seen.add(id);}
 if(validSessionId(state.sessionId)&&!seen.has(state.sessionId)){const option=el('option','当前会话');option.value=state.sessionId;select.append(option);}
 select.value=state.sessionId;select.disabled=state.asking;
}
function restoredMessages(data) {
 if(!data||!Array.isArray(data.messages))throw Error('会话历史格式无法读取。');const result=[];let question='';
 for(const message of list(data.messages,128)){
  if(message?.role==='user'){question=text(message.content,2000);continue;}
  if(message?.role!=='assistant'||!question)continue;
  const saved=message.payload&&typeof message.payload==='object'&&!Array.isArray(message.payload)?message.payload:null;
  const answer=saved?{...saved}:{answer:text(message.content||'此历史回答当前无法显示。'),claims:[],citations:[],warnings:[],trace:[],entities:[],mode:'history'};
  answer.knowledge_epoch=Number.isSafeInteger(message.knowledge_epoch)?message.knowledge_epoch:answer.knowledge_epoch;answer.as_of=answer.as_of||message.created_at;answer.history_stale=message.stale===true;result.push({question,answer});question='';
 }
 return result.slice(-30);
}
async function loadSession(id,force=false) {
 if(state.asking)return;if(!id){state.sessionSequence++;state.sessionId='';state.sessionLoading=false;state.sessionLoadError='';$('ask').disabled=false;renderChat();return;}
 if(!validSessionId(id)){setMessage('ask-status','会话编号无效，请新建会话。');return;}
 const sequence=++state.sessionSequence;state.sessionId=id;state.sessionLoadError='';if(state.chats.has(id)&&!force){state.sessionLoading=false;$('ask').disabled=false;renderChat();return;}
 state.sessionLoading=true;$('ask').disabled=true;renderChat();setMessage('ask-status','正在恢复会话历史…');
 try{const data=await api('/api/sessions/'+id);if(sequence!==state.sessionSequence||id!==state.sessionId)return;if(data.id!==id)throw Error('会话编号不一致，请重试。');state.chats.set(id,restoredMessages(data));if(Number.isSafeInteger(data.knowledge_epoch))state.requiredEpoch=Math.max(state.requiredEpoch,data.knowledge_epoch);setMessage('ask-status','会话历史已恢复。旧记录会按当前证据重新核验。');if((state.snapshot?.knowledge_epoch||0)<state.requiredEpoch)await refresh();}
 catch(error){if(sequence===state.sessionSequence){state.sessionLoadError=error.message;setMessage('ask-status',error.message);}}
 finally{if(sequence===state.sessionSequence){state.sessionLoading=false;$('ask').disabled=false;renderSessions();renderChat();}}
}
async function askQuestion(event) {
 event.preventDefault();if(state.asking||state.sessionLoading)return;const question=$('question').value.trim();if(!question||question.length>2000){setMessage('ask-status','请输入不超过 2000 字的问题。');return;}const originalSession=state.sessionId;state.asking=true;$('ask').disabled=true;$('new-session').disabled=true;$('sessions').disabled=true;setMessage('ask-status','正在读取当前证据并核验引用…');renderChat();
 try{const body={question};if(originalSession){if(!validSessionId(originalSession))throw Error('会话编号无效，请新建会话。');body.session_id=originalSession;}const answer=await api('/api/ask',body,45000);if(typeof answer.answer!=='string'||!validSessionId(answer.session_id))throw Error('回答格式无法读取，问题已保留。');if(Number.isSafeInteger(answer.knowledge_epoch))state.requiredEpoch=Math.max(state.requiredEpoch,answer.knowledge_epoch);const session=answer.session_id, existing=state.chats.get(originalSession)||state.chats.get(session)||[];existing.push({question,answer});state.chats.set(session,existing.slice(-30));state.sessionId=session;if($('question').value.trim()===question)$('question').value='';renderSessions();renderChat();setMessage('ask-status',answer.mode==='pending'?'资料正在更新，请处理完成后重新提问。':'回答已显示，可逐条查看引用。');await refresh();}catch(error){setMessage('ask-status',error.message);}finally{state.asking=false;renderChat();$('ask').disabled=state.sessionLoading;$('new-session').disabled=false;renderSessions();if(state.sessionLoadError&&validSessionId(state.sessionId)&&!state.chats.has(state.sessionId))loadSession(state.sessionId,true);}
}
function renderSystem() {
 const s=state.system,snapshot=state.snapshot,demo=Boolean(snapshot?.demo),model=publicModel(s?.model||state.model||{});state.model=model;
 $('demo-banner').hidden=!demo;$('withdraw').disabled=!demo;$('mode-badge').textContent=demo?'离线虚构演示':'本机情报工作台';$('mode-badge').className='pill'+(demo?' warn':' ok');
 $('sidebar-mode').textContent=demo?'虚构数据 · 演示库':'本机运行 · 授权清单';
 $('model-badge').textContent=model.provider==='deepseek'?(model.enabled&&model.configured?'DeepSeek V4 Pro · 已配置':'DeepSeek · 待配置'):model.provider==='ollama'?(model.enabled?'Ollama · 已配置':'Ollama · 待配置'):model.provider==='mock'?'Mock · 离线演示':'事实模式 · 本机';$('model-badge').className='pill'+(model.provider==='mock'||model.provider!=='facts'&&!model.configured?' warn':'');
 $('chat-capability').textContent=model.provider==='deepseek'?(model.enabled&&model.configured?'已启用官方 DeepSeek V4 Pro。模型可规划检索与整理分析，事实及引用仍由主机核验。实际模式与降级原因随回答显示。':'DeepSeek 尚未完成配置；当前可使用本机事实卡。'):model.provider==='ollama'?(model.enabled?'已配置本机 Ollama 模型。实际回答模式与降级情况随回答显示。':'Ollama 尚未启用；当前可使用本机事实卡。'):model.provider==='mock'?'当前为 Mock 离线流程演示，无需 API Key，不连接 DeepSeek。检索规划、工具读取和结构校验可演练；模型理解与推理质量仍需真实模型验收。':'使用本机结构化事实与关键词检索。启用模型后可进行语义研判，资料不足时仍保留未知。';renderModel();
 const monitoring=s?.monitoring||{},sourceRows=list(monitoring.sources,100),categoryCount=new Set(sourceRows.map(s=>s.category).filter(v=>typeof v==='string'&&v)).size; $('collect').disabled=demo||!monitoring.collect||Boolean(monitoring.busy);$('monitor-summary').textContent=demo?'离线演示未联网采集。':monitoring.busy?'正在采集，完成后会同步修订。':monitoring.collect?'按来源允许的节奏增量采集；未到期或退避中的来源继续等待。':'当前只读取已保存数据，网络采集未启用。';
 $('monitor-summary').textContent+=` 配置 ${sourceRows.length} 个来源，覆盖 ${categoryCount} 类；类别数量不等于来源数量。`;
 const sources=$('sources');sources.replaceChildren();for(const source of sourceRows){const n=el('article',undefined,'source-row'), row=el('div',undefined,'row');const label=demo?'演示未联网':!source.enabled?'未启用':source.last_error?'等待重试':source.last_result?.complete===false?'等待接续':source.last_success_at?'监测中':'等待首次采集';row.append(el('h3',source.name||source.id),badge(label,source.last_error?'warn':''));n.append(row,el('p',(sourceCategories[source.category]||'类别未声明')+' · 最近成功：'+date(source.last_success_at)));if(source.next_run_at)n.append(el('p','下次检查：'+date(source.next_run_at)));if(source.last_error)n.append(notice(source.last_error,'warn'));if(source.terms_url)n.append(link(source.terms_url,'来源使用条件 ↗'));if(source.license)n.append(el('p','许可：'+text(source.license,1000)));sources.append(n);}if(!sources.childNodes.length)empty(sources,'暂无配置来源','当前知识仍可从已保存证据核验。');
 const jobs=$('jobs'), rows=list(s?.jobs,100);jobs.replaceChildren();const pending=rows.filter(j=>['pending','queued','running','retry','retry_wait','leased'].includes(j.status));$('job-summary').textContent=`显示 ${rows.length} 项近期任务，${pending.length} 项等待或正在处理。`;$('process').disabled=false;
 const labels={pending:'等待处理',queued:'排队中',running:'处理中',leased:'处理中',completed:'完成',done:'完成',succeeded:'完成',retry:'等待重试',retry_wait:'等待重试',failed:'失败',cancelled:'已取消',stale:'输入已过期',quarantined:'待核对'};
 for(const job of rows){const n=el('article',undefined,'source-row'), row=el('div',undefined,'row'), event=list(snapshot?.events,5000).find(e=>e.id===(job.event_id||job.entity_id));row.append(el('h3',job.title||event?.title||({enrich:'情报富化',backfill:'历史资料整理'}[job.kind||job.type]||'情报处理')+' · '+text(job.event_id||job.entity_id||job.id||'',80)),badge(labels[job.status]||job.status,['failed','retry','retry_wait','stale','quarantined'].includes(job.status)?'warn':''));n.append(row,el('p',`尝试 ${job.attempt??job.attempts??0} · ${date(job.finished_at||job.updated_at||job.created_at)}`));if(job.last_error||job.error)n.append(notice(job.last_error||job.error,'warn'));jobs.append(n);}if(!rows.length)empty(jobs,'当前没有待办任务','新的来源修订或资产快照会触发后续处理。');
 $('snapshot-time').textContent='数据快照：'+date(snapshot?.as_of);
}
function invalidateCurrent(result,baselineEpoch) {
 state.pendingCurrent=true;
 state.snapshotBarrier++;
 const known=Number.isSafeInteger(result.knowledge_epoch)?result.knowledge_epoch:Number.isSafeInteger(baselineEpoch)?baselineEpoch+1:state.requiredEpoch;
 state.requiredEpoch=Math.max(state.requiredEpoch,known);
 if(Number.isSafeInteger(result.snapshot_id))state.requiredAssetSnapshot=Math.max(state.requiredAssetSnapshot,result.snapshot_id);
 if(state.snapshot){state.snapshot={...state.snapshot,events:list(state.snapshot.events,5000).map(e=>e.status==='ready'?{...e,status:'dirty',facts:[],assessments:[]}:e)};renderStats();renderEvents();renderInventory();if(state.selected)renderDetail(state.snapshot.events.find(e=>e.id===state.selected));}
 renderChat();
}
function refresh() {
 if(state.refreshPromise){state.refreshQueued=true;return state.refreshPromise;}
 state.refreshPromise=refreshCycle();return state.refreshPromise;
}
async function refreshCycle() {
 state.refreshBusy=true;$('refresh').disabled=true;let attempts=0;
 try{do{state.refreshQueued=false;attempts++;
  try{const barrier=state.snapshotBarrier,modelSequence=state.modelSequence,system=await api('/api/system');const snapshot=system.snapshot;if(!snapshot||!Array.isArray(snapshot.events)||!Array.isArray(snapshot.evidence))throw Error('工作台数据不完整。');
   if(barrier!==state.snapshotBarrier||(snapshot.knowledge_epoch||0)<state.requiredEpoch||(snapshot.asset_snapshot_id||0)<state.requiredAssetSnapshot){state.refreshQueued=attempts<3;throw Error('等待最新数据，旧快照暂不作为当前依据。');}
   const policyChanged=Number.isSafeInteger(state.snapshot?.policy_generation)&&snapshot.policy_generation!==state.snapshot.policy_generation;
   if(policyChanged){state.chats.clear();state.sessionSequence++;state.sessionLoading=false;state.sessionLoadError='来源权限已变化，历史内容需要按当前权限重新读取。';}
   state.requiredEpoch=Math.max(state.requiredEpoch,snapshot.knowledge_epoch||0);state.requiredAssetSnapshot=Math.max(state.requiredAssetSnapshot,snapshot.asset_snapshot_id||0);state.pendingCurrent=false;state.system={...system,model:publicModel(modelSequence===state.modelSequence?system.model||{}:state.model||system.model||{})};state.snapshot=snapshot;state.connected=true;state.lastSync=new Date().toISOString();$('connection-banner').hidden=true;$('last-sync').textContent='最后同步：'+date(state.lastSync);renderSystem();renderStats();renderEvents();renderInventory();renderSessions();renderChat();if(state.selected){const current=list(state.snapshot.events,5000).find(e=>e.id===state.selected);if(current)renderDetail(current);else{state.selected=null;state.detailSequence++;renderDetail(null);}}if(policyChanged&&validSessionId(state.sessionId)&&!state.asking)loadSession(state.sessionId,true);
  }catch(error){state.connected=false;$('connection-banner').hidden=false;$('connection-banner').textContent=error.message+(state.lastSync?' 当前保留上次同步的数据，请在重新连接后核验。':' 尚未读取本机数据。');$('last-sync').textContent=state.lastSync?'尚未核验最新状态 · 最后同步 '+date(state.lastSync):'尚未同步';renderChat();renderContext();}
 }while(state.refreshQueued&&attempts<3);}finally{state.refreshBusy=false;state.refreshPromise=null;$('refresh').disabled=false;}
}
function appendEvidence(root,evidence,historical=false) {
 const n=el('section',undefined,'evidence-section');n.append(el('h3',evidence.title));const row=el('div',undefined,'row');row.append(badge(evidence.withdrawn?'该修订标记撤回':historical?'历史修订':'来源修订',evidence.withdrawn?'bad':historical?'warn':''));if(state.snapshot?.demo)row.append(badge('虚构演示','warn'));n.append(row,fields({source_id:evidence.source_id,upstream_id:evidence.upstream_id,evidence_id:evidence.id,revision_number:evidence.revision_number,collected_at:date(evidence.collected_at),published_at:date(evidence.published_at),updated_at:date(evidence.updated_at)}),link(evidence.url),el('p',evidence.summary,'prewrap'));
 if(evidence.withdrawn)n.append(notice('此修订不能支持当前判断；保留用于历史追溯。','bad'));
 const metadata=evidence.metadata||{}, terms={};for(const key of ['content_scope','license','license_url','terms_url','attribution','local_processing','disclaimer'])if(metadata[key]!==undefined)terms[key]=metadata[key];if(metadata.usage_conditions&&typeof metadata.usage_conditions==='object'){for(const [key,label] of [['scope','content_scope'],['attribution','attribution'],['license','license'],['license_url','license_url'],['terms_url','terms_url']])if(terms[label]===undefined&&metadata.usage_conditions[key]!==undefined)terms[label]=metadata.usage_conditions[key];}if(Object.keys(terms).length){n.append(el('h4','署名与使用范围'),fields(terms));}
 const references=list(evidence.references,20);if(references.length){n.append(el('h4','参考链接'));for(const [i,url] of references.entries()){const p=el('p');p.append(link(url,`参考来源 ${i+1} ↗`));n.append(p);}}
 const details=el('details');details.append(el('summary','查看结构化来源信息'),el('pre',metadata,'code-data'));n.append(details);root.append(n);
}
function evidenceHistory(evidence){const own=list(evidence.history||evidence.revisions,30).filter(Boolean);if(own.length)return own;const cached=list(state.detail?.evidence,256).find(e=>e.observation_id===evidence.observation_id);return list(cached?.history,30).filter(Boolean);}
async function openEvidence(id) {
 if(!validEvidenceId(id))throw Error('证据编号无效。');const sequence=++state.evidenceSequence, root=$('evidence-body');empty(root,'正在读取证据…');$('evidence-title').textContent='证据修订';if(!$('evidence-dialog').open)$('evidence-dialog').showModal();
 try{const evidence=await api('/api/evidence/'+encodeURIComponent(id));if(sequence!==state.evidenceSequence)return;if(evidence.id!==id)throw Error('证据修订不一致，请刷新后重试。');root.replaceChildren();$('evidence-title').textContent=evidence.title||'证据修订';const latest=list(state.snapshot?.evidence,5000).filter(e=>e.observation_id===evidence.observation_id).sort((a,b)=>b.revision_number-a.revision_number)[0], historical=Boolean(evidence.current===false||evidence.historical||evidence.history_status==='historical'||latest&&latest.revision_number>evidence.revision_number);if(historical)root.append(notice('正在查看历史修订，不作为当前结论依据。','warn'));appendEvidence(root,evidence,historical);const navigation=el('div',undefined,'citation-row');if(evidence.revision_number>1)navigation.append(citationButtons([`obs:${evidence.observation_id}:r:${evidence.revision_number-1}`]));const currentRevision=evidence.current_revision_number||latest?.revision_number;if(currentRevision>evidence.revision_number)navigation.append(button('查看最新修订 r'+currentRevision,()=>openEvidence(`obs:${evidence.observation_id}:r:${currentRevision}`).catch(error=>setMessage('global-message',error.message)),'citation'));if(navigation.childNodes.length){root.append(el('h3','切换已记录修订'),navigation);}const history=evidenceHistory(evidence);if(history.length){root.append(el('h3','已记录的修订历史'));for(const revision of history.slice().sort((a,b)=>b.revision_number-a.revision_number)){const d=el('details',undefined,'history');d.append(el('summary',`r${revision.revision_number} · ${date(revision.collected_at)}${revision.withdrawn?' · 已撤回':''}`),el('p',revision.summary||revision.title||''));if(validEvidenceId(revision.id))d.append(citationButtons([revision.id]));root.append(d);}}}catch(error){if(sequence===state.evidenceSequence)empty(root,'证据未读取成功',error.message);throw error;}
}
async function action(id,path,success) {
 const b=$(id);if(b.disabled)return;const baselineEpoch=state.snapshot?.knowledge_epoch;b.disabled=true;setMessage('global-message','正在处理…');try{const result=await api(path,{});if(id==='withdraw'&&result.updated||id==='process'&&result.processed>0)invalidateCurrent(result,baselineEpoch);setMessage('global-message',success(result));await refresh();}catch(error){setMessage('global-message',error.message);}finally{if(id==='collect')b.disabled=Boolean(state.snapshot?.demo||!state.system?.monitoring?.collect||state.system?.monitoring?.busy);else if(id==='withdraw')b.disabled=!state.snapshot?.demo;else b.disabled=false;}
}
function stopPolling(message='') {if(state.pollTimer!==null)clearTimeout(state.pollTimer);state.pollTimer=null;$('auto-refresh').checked=false;$('poll-status').textContent=message;}
function schedulePoll() {if(!$('auto-refresh').checked)return;if(state.polls>=30){stopPolling('已达到本次刷新上限');return;}state.pollTimer=setTimeout(async()=>{state.pollTimer=null;if(!$('auto-refresh').checked)return;if(!document.hidden){state.polls++;await refresh();$('poll-status').textContent=`${state.polls} / 30 次`;}schedulePoll();},20000);}

const sourceCategories={vulnerability_database:'漏洞数据库',vendor_advisory:'厂商公告',research_paper:'学术研究',security_community:'安全社区',security_blog:'安全博客',technical_standard:'技术标准',policy_regulation:'政策法规'};
function renderContext() {
 const root=$('context-summary');root.replaceChildren();if(!state.snapshot){root.append(el('p','等待首次同步','muted'));empty($('context-events'),'正在读取情报');return;}
 const events=list(state.snapshot.events,5000),ready=events.filter(e=>e.status==='ready'),assets=list(state.snapshot.assets,MAX_ASSETS),evidence=list(state.snapshot.evidence,5000).filter(e=>!e.withdrawn),sources=list(state.system?.monitoring?.sources,100);
 for(const [value,label] of [[ready.length,'可用情报'],[evidence.length,'有效来源修订'],[assets.length,'授权资产'],[sources.length,'配置来源']]){const n=el('div',undefined,'context-stat');n.append(el('strong',value),el('span',label));root.append(n);}
 $('context-freshness').textContent=state.pendingCurrent?'资料正在更新，旧判断暂不作为当前依据。':state.connected?`${events.length-ready.length} 条情报待更新 / 核对；未知条件保留。`:'连接中断，以上为上次同步的上下文。';
 const related=$('context-events');related.replaceChildren();const prioritized=events.slice().sort((a,b)=>Number(b.status==='ready'&&list(b.assessments,MAX_ASSETS).some(a=>['potentially_affected','under_investigation'].includes(a.status)))-Number(a.status==='ready'&&list(a.assessments,MAX_ASSETS).some(a=>['potentially_affected','under_investigation'].includes(a.status))));
 for(const event of prioritized.slice(0,3)){const n=el('div',undefined,'context-item');n.append(button(event.title,()=>{showView('overview');selectEvent(event.id).catch(error=>setMessage('global-message',error.message));}),el('p',(eventLabels[event.status]||'状态未知')+' · '+list(event.evidence_ids,256).length+' 份证据','muted'));related.append(n);}if(!related.childNodes.length)empty(related,'当前没有情报','可先导入清单，或查看来源状态。');
}
function publicModel(value) {
 const m=value&&typeof value==='object'&&!Array.isArray(value)?value:{},provider=['facts','ollama','deepseek','mock'].includes(m.provider)?m.provider:m.enabled?'ollama':'facts',last=m.last_test&&typeof m.last_test==='object'?m.last_test:null;
 const statuses=['ok','success','passed','configured','failed','error','auth','authentication','rate_limit','rate_limited','timeout','unavailable','disabled','not_tested','unsupported'];
 return {provider,enabled:m.enabled===true,configured:m.configured===true||m.enabled===true,credential_configured:m.credential_configured===true,model:provider==='deepseek'?'deepseek-v4-pro':provider==='mock'?'mock-deepseek-v4-pro':provider==='ollama'&&typeof m.model==='string'&&!/sk[-_]|bearer\s|(?:key|token|password)\s*[:=]/i.test(m.model)?m.model.slice(0,100):'',reasoning_effort:['none','low','high','max'].includes(m.reasoning_effort)?m.reasoning_effort:'none',semantic_mode:['llm_semantic','mock_plan','local_embedding','local_semantic','facts','keyword','disabled','unavailable'].includes(m.semantic_mode)?m.semantic_mode:'unknown',embedding_enabled:m.embedding_enabled===true,endpoint:provider==='deepseek'?'https://api.deepseek.com/chat/completions':provider==='ollama'?'本机 Ollama':provider==='mock'?'离线 Mock · 无网络请求':'本机事实库',last_test:last?{status:statuses.includes(last.status)?last.status:last.ok===true?'ok':last.ok===false?'failed':'unknown',at:typeof(last.at||last.tested_at||last.checked_at)==='string'&&Number.isFinite(Date.parse(last.at||last.tested_at||last.checked_at))?new Date(last.at||last.tested_at||last.checked_at).toISOString():null}:null};
}
function modelFieldsChanged() {
 const provider=$('model-provider').value;$('deepseek-fields').hidden=provider!=='deepseek';$('ollama-fields').hidden=provider!=='ollama';$('reasoning-fields').hidden=provider!=='deepseek';if(provider!=='deepseek'){$('model-key').value='';$('cloud-consent').checked=false;}syncModelControls();
}
function syncModelControls() {
 const busy=state.modelBusy||state.modelLoading;for(const id of ['model-provider','model-key','cloud-consent','local-model','reasoning-effort','save-model','test-model','clear-model','reload-model'])$(id).disabled=busy;
 $('test-model').textContent=state.model?.provider==='mock'?'测试离线流程':'测试已保存的连接';
 if(!busy)$('test-model').disabled=!state.model||state.model.provider==='facts'||!state.model.configured||!state.model.enabled;
}
function fillModelForm() {
 if(state.modelFormDirty||!state.model)return;const m=state.model;$('model-provider').value=m.provider;$('local-model').value=m.provider==='ollama'?m.model:'';$('reasoning-effort').value=m.reasoning_effort;$('model-key').value='';$('cloud-consent').checked=m.provider==='deepseek'&&m.enabled&&m.configured;state.modelFormReady=true;modelFieldsChanged();
}
function renderModel() {
 const root=$('model-summary');root.replaceChildren();const m=state.model;if(!m){root.append(notice('正在读取当前回答引擎状态。'));syncModelControls();return;}
 const row=el('div',undefined,'row');row.append(badge(m.provider==='deepseek'?'官方 DeepSeek V4 Pro':m.provider==='ollama'?'Ollama 本机模型':m.provider==='mock'?'Mock 离线流程演示':'本机事实模式',m.provider==='mock'?'warn':m.provider==='facts'||m.configured?'ok':'warn'),badge(m.provider==='facts'?'无需连接':m.provider==='mock'?'无需 Key · 不连接云端':m.configured?'配置已保存 · 连接待测试':'尚未配置',m.provider!=='facts'&&!m.configured?'warn':''));root.append(row);
 const statusLabels={ok:'连接测试成功',success:'连接测试成功',passed:'连接测试成功',configured:'配置已保存',failed:'连接测试失败',error:'连接测试失败',auth:'认证未通过',authentication:'认证未通过',rate_limit:'提供方限流',rate_limited:'提供方限流',timeout:'连接测试超时',unavailable:'提供方暂不可用',disabled:'模型已停用',not_tested:'尚未测试',unsupported:'当前模式不支持连接测试',unknown:'测试状态未知'};
 root.append(fields({source:m.endpoint,status:m.provider==='facts'?'正常 · 结构化事实模式':m.provider==='mock'?'Mock 离线流程已启用':m.enabled?'模型推理已启用':'模型推理未启用',available:m.provider==='deepseek'?(m.credential_configured?'Key 已在本机服务配置':'尚无可用 Key'):'无需云端 Key'}));
 if(m.last_test)root.append(notice((m.provider==='mock'&&['ok','success','passed'].includes(m.last_test.status)?'Mock 离线流程测试成功 · 非云端连接':statusLabels[m.last_test.status]||'测试状态未知')+(m.last_test.at?' · '+date(m.last_test.at):''),['ok','success','passed'].includes(m.last_test.status)?'':m.last_test.status==='disabled'?'':'warn'));else root.append(el('p',m.provider==='facts'?'事实模式正常可用，不需要外部连接。':'尚无连接测试记录；读取状态不会调用模型。','help'));
 $('model-key-help').textContent=(m.provider==='deepseek'&&m.credential_configured?'Key 已配置；留空可继续使用服务内存中的 Key。 ':'')+'Key 仅保存在本机服务内存，重启后需重新配置。保存后输入框立即清空，不返回页面或写入浏览器存储。';syncModelControls();
}
function acceptModel(data) {
 const raw=data?.model&&typeof data.model==='object'?data.model:data;if(!raw||typeof raw!=='object'||!['facts','ollama','deepseek','mock'].includes(raw.provider))throw Error('模型状态格式无效');const m=publicModel(raw);state.model=m;state.system={...(state.system||{}),model:m};renderModel();renderSystem();renderStats();
}
async function loadModel() {
 if(state.modelBusy||state.modelLoading)return;const sequence=++state.modelSequence;state.modelLoading=true;syncModelControls();setMessage('model-status','正在读取公开模型状态…');
 try{const data=await api('/api/model');if(sequence!==state.modelSequence)return;acceptModel(data);fillModelForm();setMessage('model-status','状态已更新。读取状态没有调用模型。');}catch{setMessage('model-status','模型状态未读取成功，请刷新重试。');}finally{if(sequence===state.modelSequence){state.modelLoading=false;syncModelControls();}}
}
function modelSettings() {
 const provider=$('model-provider').value;if(!['facts','ollama','deepseek','mock'].includes(provider))throw Error('请选择受支持的回答方式。');const result={provider};
 if(provider==='deepseek'){if(!$('cloud-consent').checked)throw Error('启用云端推理前，请确认最少必要证据的发送范围。');const key=$('model-key').value.trim();if(key&&(!/^[\x21-\x7e]+$/.test(key)||key.length>512))throw Error('API Key 格式无效，请在密码框重新输入。');if(!key&&!state.model?.credential_configured)throw Error('请在本机密码框输入 API Key。');const effort=$('reasoning-effort').value;if(!['none','low','high','max'].includes(effort))throw Error('请选择受支持的分析强度。');result.model='deepseek-v4-pro';result.reasoning_effort=effort;if(key)result.api_key=key;}
 if(provider==='ollama'){const model=$('local-model').value.trim();if(model.length>100||/[\x00-\x20\x7f]|sk[-_]|bearer|(?:password|token|key)\s*[:=]/i.test(model))throw Error('本机模型名称格式无效。');if(model)result.model=model;}
 return result;
}
async function saveModel(event) {
 event.preventDefault();if(state.modelBusy||state.modelLoading)return;let settings;try{settings=modelSettings();}catch(error){$('model-key').value='';setMessage('model-status',error.message);return;}
 $('model-key').value='';state.modelBusy=true;++state.modelSequence;syncModelControls();setMessage('model-status','正在保存设置；密码框已清空。');
 try{const data=await api('/api/model',settings);delete settings.api_key;++state.modelSequence;acceptModel(data);state.modelFormDirty=false;fillModelForm();setMessage('model-status',settings.provider==='deepseek'?'设置已保存。Key 仅保存在本机服务内存；可主动测试连接。':settings.provider==='mock'?'Mock 离线流程已启用，无需 Key，也没有连接 DeepSeek。':settings.provider==='facts'?'本机事实模式已启用，无需模型连接。':'本机模型设置已保存；可主动测试连接。');}catch{setMessage('model-status','设置未保存成功，密码框已清空。请检查服务；需要时重新输入 Key。');}finally{delete settings.api_key;state.modelBusy=false;syncModelControls();}
}
async function testModel() {
 if(state.modelBusy||state.modelLoading)return;if(state.modelFormDirty){setMessage('model-status','请先保存当前设置，再测试已保存的连接。');return;}if(!state.model||state.model.provider==='facts'){setMessage('model-status','事实模式正常可用，无需连接测试。');return;}
 $('model-key').value='';state.modelBusy=true;++state.modelSequence;syncModelControls();setMessage('model-status',state.model.provider==='mock'?'正在测试 Mock 离线流程，无云端请求…':'正在发起一次连接测试，可能需要等待…');
 try{const result=await api('/api/model/test',{},35000);++state.modelSequence;if(result.model&&typeof result.model==='object')acceptModel({model:{...result.model,last_test:result.last_test||result.model.last_test}});else{state.model={...state.model,last_test:publicModel({last_test:result.last_test||result}).last_test};state.system={...(state.system||{}),model:state.model};renderModel();}const ok=['ok','success','passed'].includes(state.model.last_test?.status);setMessage('model-status',ok?(state.model.provider==='mock'?'Mock 离线流程测试成功；真实模型的理解与推理质量仍待验收。':'连接测试成功。实际回答仍需逐条核验事实与引用。'):'连接测试未成功。请查看公开测试状态并检查配置。');}catch{setMessage('model-status','连接测试未完成，请稍后重试。');}finally{state.modelBusy=false;syncModelControls();}
}
async function clearModel() {
 if(state.modelBusy||state.modelLoading)return;$('model-key').value='';$('cloud-consent').checked=false;state.modelBusy=true;++state.modelSequence;syncModelControls();setMessage('model-status','正在清除服务内存中的 Key 并停用模型…');
 try{const result=await api('/api/model/clear',{});++state.modelSequence;acceptModel(result);state.modelFormDirty=false;fillModelForm();setMessage('model-status','Key 已清除，模型已停用。继续使用本机事实模式。');}catch{setMessage('model-status','清除请求未完成。密码框已清空，请重试以确认服务 Key 已清除。');}finally{state.modelBusy=false;syncModelControls();}
}
function renderKnowledge() {
 const root=$('knowledge-items');root.replaceChildren();if(!state.knowledge){empty(root,state.knowledgeLoading?'正在读取知识目录…':state.knowledgeError?'知识目录未读取成功':'当前没有知识目录',state.knowledgeError?'点击“刷新目录”重试。':'官方元数据会在此展示。');return;}
 const data=state.knowledge,items=list(data.items,256),curated=items.filter(i=>i.monitoring==='curated').length,feed=items.filter(i=>i.monitoring==='feed').length,kinds={standard:0,policy:0,guide:0};for(const item of items)if(Object.hasOwn(kinds,item.kind))kinds[item.kind]++;
 $('knowledge-coverage').textContent=`目录 ${items.length} 项：技术标准 ${kinds.standard} · 政策法规 ${kinds.policy} · 安全指南 ${kinds.guide}。人工精选 ${curated} 项，订阅观察 ${feed} 项。`+(curated?' 人工精选是官方元数据目录，不代表持续监测或已追踪最新修订。':'')+(typeof data.coverage?.scope==='string'?' '+text(data.coverage.scope,500):'');
 const query=$('knowledge-search').value.trim().toLocaleLowerCase(),kind=$('knowledge-kind').value,chosen=items.filter(i=>(!kind||i.kind===kind)&&(!query||[i.title,i.source,...list(i.topics,16)].some(t=>text(t,1000).toLocaleLowerCase().includes(query))));
 for(const item of chosen){const n=el('article',undefined,'knowledge-card'),row=el('div',undefined,'row');row.append(badge({standard:'技术标准',policy:'政策法规',guide:'安全指南'}[item.kind]||'资料类型未知'),badge(item.monitoring==='curated'?'人工精选 · 官方元数据':item.monitoring==='feed'?'订阅观察':'更新方式未知',item.monitoring==='curated'?'':item.monitoring==='feed'?'ok':'warn'));n.append(row,el('h3',item.title),el('p',item.summary,'summary'));const topics=el('div',undefined,'row');for(const topic of list(item.topics,8))topics.append(badge(topic));n.append(topics);const details=el('details');details.append(el('summary','署名与使用条件'),el('p',item.attribution,'help'),el('p',item.usage_conditions,'help'));n.append(details);const foot=el('footer');foot.append(el('p',item.source),el('p','来源标示时间：'+date(item.updated_at)),link(item.url,'查看官方资料 ↗'));n.append(foot);root.append(n);}
 if(!chosen.length)empty(root,items.length?'没有匹配的资料':'目录当前为空',items.length?'调整关键词或资料类型。':'当前 API 尚未提供官方元数据条目。');
 if(list(data.coverage?.gaps,20).length){const gaps=el('details',undefined,'panel');gaps.append(el('summary','查看当前覆盖限制'));for(const gap of list(data.coverage.gaps,20))gaps.append(el('p',gap,'help'));root.append(gaps);}
}
async function loadKnowledge() {
 if(state.knowledgeLoading)return;const sequence=++state.knowledgeSequence;state.knowledgeLoading=true;state.knowledgeError='';$('reload-knowledge').disabled=true;setMessage('knowledge-status','正在读取官方知识元数据…');renderKnowledge();
 try{const data=await api('/api/knowledge');if(sequence!==state.knowledgeSequence)return;if(!data||!Array.isArray(data.items)||data.items.length>256||data.items.some(i=>!i||typeof i!=='object'||Array.isArray(i)))throw Error('目录格式无效');state.knowledge={items:data.items,coverage:data.coverage||{}};setMessage('knowledge-status',`已读取 ${data.items.length} 项元数据。目录更新方式以每张卡片标注为准。`);}catch{state.knowledgeError='知识目录读取失败';setMessage('knowledge-status',state.knowledge?'读取失败，当前显示上次读取的目录；可再次刷新。':'知识目录未读取成功，请点击“刷新目录”重试。');if(!state.knowledge)$('knowledge-coverage').textContent='覆盖范围尚未读取，暂不能确认目录数量。';}finally{state.knowledgeLoading=false;$('reload-knowledge').disabled=false;renderKnowledge();}
}
function syncSBOMControls() {$('sbom-file').disabled=state.sbomSaving||state.saving;for(const id of ['save-sbom','sbom-text'])$(id).disabled=state.sbomSaving||state.saving||state.sbomReading;}
function sbomDocument(raw) {
 if(typeof raw!=='string'||!raw.trim()||new TextEncoder().encode(raw).length>MAX_SBOM_BYTES)throw Error('请输入不超过 1 MB 的 SBOM JSON。');let document;try{document=JSON.parse(raw);}catch{throw Error('JSON 无法解析，请核对括号与字段格式。');}
 if(!document||typeof document!=='object'||Array.isArray(document))throw Error('SBOM 顶层应为 JSON 对象。');if(document.bomFormat!=='CycloneDX'&&!(typeof document.spdxVersion==='string'&&document.spdxVersion.startsWith('SPDX-')))throw Error('仅支持 CycloneDX 或 SPDX JSON 文档。');if(new TextEncoder().encode(JSON.stringify({document})).length>MAX_SBOM_BYTES)throw Error('SBOM 请求超过 1 MB，请缩小文档。');return document;
}
async function saveSBOM(event) {
 event.preventDefault();if(state.sbomSaving||state.saving)return;if(state.sbomReading){setMessage('sbom-status','文件仍在读取，请等待完成后再提交。');return;}let document;try{document=sbomDocument($('sbom-text').value);}catch(error){setMessage('sbom-status',error.message);return;}
 const baselineEpoch=state.snapshot?.knowledge_epoch;state.sbomSaving=true;renderDraft();$('sbom-warnings').replaceChildren();setMessage('sbom-status','正在本机解析组件并提交授权清单…');
 try{const result=await api('/api/assets/sbom',{document});invalidateCurrent(result,baselineEpoch);setMessage('sbom-status',Number.isSafeInteger(result.count)?`已导入 ${result.count} 项组件，正在重新核验影响。`:'组件清单已导入，正在重新核验影响。');warnings($('sbom-warnings'),result.warnings);await refresh();}catch{setMessage('sbom-status','SBOM 未导入成功，原文已保留。请检查格式、组件数量或本机服务后重试。');}finally{state.sbomSaving=false;renderDraft();}
}
async function readSBOMFile() {
 if(state.sbomSaving||state.saving)return;const sequence=++state.sbomFileSequence,file=$('sbom-file').files?.[0];
 if(!file){state.sbomReading=false;syncSBOMControls();return;}
 if(file.size>MAX_SBOM_BYTES){state.sbomReading=false;syncSBOMControls();setMessage('sbom-status','文件超过 1 MB，请缩小文档。');return;}
 state.sbomReading=true;syncSBOMControls();setMessage('sbom-status','正在读取新文件，完成后才能提交…');
 try{const raw=await file.text();if(new TextEncoder().encode(raw).length>MAX_SBOM_BYTES)throw Error();if(sequence!==state.sbomFileSequence||state.sbomSaving||state.saving)return;$('sbom-text').value=raw;setMessage('sbom-status','文档已读入。确认授权范围后点击“导入并替换当前清单”。');}
 catch{if(sequence===state.sbomFileSequence)setMessage('sbom-status','文件无法读取，或超出文本大小限制。');}
 finally{if(sequence===state.sbomFileSequence){state.sbomReading=false;syncSBOMControls();}}
}

function bindUI() {
 for(const n of document.querySelectorAll('[data-view]'))n.addEventListener('click',()=>showView(n.dataset.view));
 $('browse-events').addEventListener('click',()=>showView('overview'));$('configure-model').addEventListener('click',()=>showView('model'));
 $('model-form').addEventListener('submit',saveModel);$('reload-model').addEventListener('click',loadModel);$('test-model').addEventListener('click',testModel);$('clear-model').addEventListener('click',clearModel);$('model-provider').addEventListener('change',()=>{state.modelFormDirty=true;modelFieldsChanged();});for(const id of ['model-key','local-model','reasoning-effort','cloud-consent'])$(id).addEventListener('input',()=>state.modelFormDirty=true);
 $('reload-knowledge').addEventListener('click',loadKnowledge);$('knowledge-filters').addEventListener('submit',e=>{e.preventDefault();renderKnowledge();});$('knowledge-kind').addEventListener('change',renderKnowledge);$('sbom-form').addEventListener('submit',saveSBOM);$('sbom-file').addEventListener('change',readSBOMFile);
 $('refresh').addEventListener('click',()=>refresh());$('filters').addEventListener('submit',e=>{e.preventDefault();state.page=0;renderEvents();});$('event-state').addEventListener('change',()=>{state.page=0;renderEvents();});$('prev').addEventListener('click',()=>{state.page=Math.max(0,state.page-1);renderEvents();});$('next').addEventListener('click',()=>{state.page++;renderEvents();});
 $('collect').addEventListener('click',()=>action('collect','/api/collect',r=>r.queued?'已检查到期来源，采集完成后刷新可见。':'当前没有可唤醒的采集，来源可能未到期或正在退避。'));
 $('process').addEventListener('click',()=>action('process','/api/process',r=>`本次处理 ${r.processed??0} 项，剩余 ${r.remaining??0} 项。`));
 $('withdraw').addEventListener('click',()=>action('withdraw','/api/demo/withdraw',r=>r.updated?'虚构来源已撤回。旧引用会标记为历史，当前判断等待重新核验。':'演示来源已处于撤回状态。'));
 $('close-evidence').addEventListener('click',()=>{$('evidence-dialog').close();state.evidenceSequence++;});$('evidence-dialog').addEventListener('close',()=>state.evidenceSequence++);
 $('add-asset').addEventListener('click',()=>{if(state.draft.length<MAX_ASSETS){state.draft.push(blankAsset());renderDraft();}});
 $('example-assets').addEventListener('click',()=>{const observed_at=new Date().toISOString();state.draft=[{asset_id:'demo-inference',name:'虚构推理服务',ecosystem:'pip',component:'vllm',version:'99.1.0',exposed:true,authenticated:false,observed_at,capabilities:{external_documents:true,rag:true}},{asset_id:'demo-patched',name:'虚构修补服务',ecosystem:'pip',component:'vllm',version:'99.2.0',exposed:null,authenticated:null,observed_at,capabilities:{}}];renderDraft();setMessage('asset-message','已载入与离线演示对应的虚构清单；时间设为当前演示时刻。请检查后提交。');});
 $('edit-assets').addEventListener('click',()=>{state.draft=list(state.snapshot?.assets,MAX_ASSETS).map(a=>({asset_id:a.asset_id,name:a.name,ecosystem:a.ecosystem,component:a.component,version:a.version||'',exposed:a.exposed??null,authenticated:a.authenticated??null,observed_at:a.observed_at,capabilities:Object.fromEntries(Object.entries(a.capabilities||{}).filter(([key,value])=>Object.hasOwn(capabilityLabels,key)&&typeof value==='boolean'))}));if(!state.draft.length)state.draft=[blankAsset()];renderDraft();setMessage('asset-message','已保留当前清单时间与未知项。修改后提交整份新快照。');$('asset-editor').scrollIntoView({block:'start'});});
 $('asset-submit').addEventListener('submit',saveAssets);$('parse-import').addEventListener('click',()=>{try{const rows=parseTable($('import-text').value);state.draft=rows;renderDraft();setMessage('asset-message',`已读取 ${rows.length} 项，请在表单中检查后提交。`);}catch(error){setMessage('asset-message',error.message);}});
 $('import-file').addEventListener('change',async()=>{const file=$('import-file').files?.[0];if(!file)return;if(file.size>65536){setMessage('asset-message','文件超过 64 KB，请拆分清单。');return;}try{$('import-text').value=await file.text();setMessage('asset-message','文本已读入，点击“放入表单检查”继续。');}catch{setMessage('asset-message','文件无法读取，请粘贴表格文本。');}});
 $('ask-form').addEventListener('submit',askQuestion);$('new-session').addEventListener('click',()=>{if(state.asking)return;state.sessionSequence++;state.sessionLoading=false;state.sessionLoadError='';state.sessionId='';state.chats.delete('');$('ask').disabled=false;renderSessions();renderChat();setMessage('ask-status','已开始新的会话。');});$('sessions').addEventListener('change',()=>loadSession($('sessions').value));
 $('auto-refresh').addEventListener('change',()=>{if(!$('auto-refresh').checked){stopPolling();return;}state.polls=0;$('poll-status').textContent='0 / 30 次';schedulePoll();});window.addEventListener('pagehide',()=>{stopPolling();$('model-key').value='';});
 state.draft=[blankAsset()];renderDraft();renderChat();renderContext();refresh();
}
bindUI();
</script>
</body>
</html>'''
