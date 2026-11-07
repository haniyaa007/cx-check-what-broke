"""Local web interface. Bind to localhost only: there is no login."""
import json
import os
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory

from . import history
from .integrations import EXAMPLE, run_integrations
from .sitecheck import DESCRIPTIONS, PRESETS, run_site_check

app = Flask(__name__)
RUNS = Path(os.environ.get("WHATBROKE_RUNS", "runs")).resolve()


@app.get("/")
def index():
    return PAGE


@app.get("/api/meta")
def meta():
    return jsonify(checks=DESCRIPTIONS, presets=PRESETS, example=EXAMPLE)


@app.get("/api/suggestions")
def sugg():
    return jsonify(suggestions=history.suggestions(), top=history.top_checks())


@app.post("/api/site")
def api_site():
    d = request.get_json()  # JSON only: blocks cross-site form posts
    if not (d.get("url") or "").strip():
        return jsonify(error="Enter a URL"), 400
    try:
        res = run_site_check(d["url"], d.get("checks"), RUNS)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    history.record("site", res["url"], res["checks"], res["severity"], res["reproduced"],
                   json.dumps({"url": res["url"], "checks": res["checks"]}))
    return jsonify(res)


@app.post("/api/integrations")
def api_integrations():
    text = request.get_json().get("config", "")
    try:
        res = run_integrations(text)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    history.record("integrations", "web config", [i["name"] for i in res["integrations"]],
                   res["severity"], res["reproduced"], text)
    return jsonify(res)


@app.get("/runs/<path:p>")
def runs(p):
    if not p.endswith(".png"):
        abort(404)
    return send_from_directory(RUNS, p)


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CX Check What Broke</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--card:#f4f4f5;--bd:#d8d8dc;--acc:#2f6fed}
@media(prefers-color-scheme:dark){:root{--bg:#161618;--fg:#eee;--mut:#9a9aa0;--card:#222226;--bd:#38383d;--acc:#6e9bff}}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:860px;margin:0 auto;padding:20px}
h1{margin:0 0 4px}.mut{color:var(--mut)}button,input,textarea{font:inherit;color:inherit;background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:8px 12px}
button{cursor:pointer}button.pri{background:var(--acc);color:#fff;border-color:var(--acc)}button.on{border-color:var(--acc);color:var(--acc)}
input[type=text]{width:100%;box-sizing:border-box}textarea{width:100%;box-sizing:border-box;min-height:220px;font-family:ui-monospace,monospace;font-size:13px}
.row{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.card{background:var(--card);border-left:4px solid var(--mut);border-radius:8px;padding:10px 14px;margin:8px 0}
.critical{border-color:#d33}.high{border-color:#e67e22}.medium{border-color:#d4a017}.low{border-color:#888}
.chip{border-radius:99px;padding:2px 10px;border:1px solid var(--bd);font-size:13px}.pass{color:#2a9d4a}.issues{color:#d33}.warn{color:#d4a017}
code{display:block;font-size:12px;color:var(--mut);word-break:break-all}img{max-width:100%;border:1px solid var(--bd);border-radius:8px}.err{color:#d33}
</style></head><body>
<h1>CX Check What Broke</h1><p class="mut">Find out why a website or an integration is broken, with evidence and a next step.</p>
<div id="sug"></div>
<div class="row"><button id="t1" class="on">Website check</button><button id="t2">Integration check</button></div>
<section id="s1"><input id="url" type="text" placeholder="https://customer-site.com">
<div class="row" id="presets"></div><div class="row" id="checks"></div>
<button class="pri" id="go1">Run check</button></section>
<section id="s2" hidden><p class="mut">Tokens are read from environment variables on the machine running CX Check What Broke (token_env). Never paste secrets here.</p>
<textarea id="cfg"></textarea><div class="row"><button class="pri" id="go2">Run integration check</button></div></section>
<p id="busy" class="mut" hidden>Running checks...</p><div id="out"></div>
<script>
const $=s=>document.querySelector(s);
function el(t,x,c){const e=document.createElement(t);if(x!=null)e.textContent=x;if(c)e.className=c;return e}
async function post(u,b){const r=await fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});return r.json()}
function chips(st){const d=el('div',null,'row');for(const[k,v]of Object.entries(st))d.append(el('span',k+': '+v,'chip '+v));return d}
function findings(l){const b=el('div');if(!l.length){b.append(el('p','No issues found.','pass'));return b}
 l.forEach(f=>{const c=el('div',null,'card '+f.severity);c.append(el('b',f.title+' ['+f.severity+']'));
 (f.evidence||[]).slice(0,3).forEach(x=>c.append(el('code',String(x))));c.append(el('div','Next step: '+f.next_step));b.append(c)});return b}
function show(r){const o=$('#out');o.replaceChildren();if(r.error){o.append(el('p',r.error,'err'));return}
 if(r.integrations){r.integrations.forEach(i=>{o.append(el('h3',i.name+' - '+i.likely_cause));o.append(chips(i.checks));o.append(findings(i.findings))})}
 else{o.append(el('h3','Severity: '+r.severity));o.append(chips(r.status));o.append(findings(r.findings));
  if(r.screenshot){const i=el('img');i.src='/runs/'+r.screenshot;o.append(i)}}
 loadSug()}
async function run(f){$('#busy').hidden=false;try{show(await f())}catch(e){show({error:'Request failed: '+e})}$('#busy').hidden=true}
const site=(url,checks)=>()=>post('/api/site',{url,checks}),integ=t=>()=>post('/api/integrations',{config:t});
async function loadSug(){const d=await (await fetch('/api/suggestions')).json(),s=$('#sug');s.replaceChildren();
 d.suggestions.forEach(x=>{const r=el('div',null,'card');r.append(el('span',x.message+' '));const b=el('button','Run again');
  b.onclick=()=>x.kind==='site'?(()=>{const p=JSON.parse(x.payload);run(site(p.url,p.checks))})():run(integ(x.payload));r.append(b);s.append(r)});
 if(d.top.length)s.append(el('p','Your most-run checks: '+d.top.map(t=>t[0]+' ('+t[1]+'x)').join(', '),'mut'))}
(async()=>{const m=await (await fetch('/api/meta')).json();$('#cfg').value=m.example;
 const boxes={};for(const[k,v]of Object.entries(m.checks)){const l=el('label',' '+k);l.title=v;const c=document.createElement('input');c.type='checkbox';c.checked=true;boxes[k]=c;l.prepend(c);$('#checks').append(l)}
 for(const[n,list]of Object.entries(m.presets)){const b=el('button',n);b.onclick=()=>{for(const k in boxes)boxes[k].checked=list.includes(k)};$('#presets').append(b)}
 $('#go1').onclick=()=>run(site($('#url').value,Object.keys(boxes).filter(k=>boxes[k].checked)));
 $('#go2').onclick=()=>run(integ($('#cfg').value));
 $('#t1').onclick=()=>{$('#s1').hidden=false;$('#s2').hidden=true;$('#t1').className='on';$('#t2').className=''};
 $('#t2').onclick=()=>{$('#s2').hidden=false;$('#s1').hidden=true;$('#t2').className='on';$('#t1').className=''};
 loadSug()})();
</script></body></html>"""
