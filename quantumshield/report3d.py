"""Interactive 3D HTML report (single offline file, no network requests)."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

CSS = r"""
:root{--ink:#060c1d;--panel:#0d1833;--panel2:#12214a;--line:#1f3470;--teal:#2fe0c8;--gold:#f2b84b;--coral:#ff6b7a;--blue:#4f8cff;--green:#5fe38f;--text:#eaf0ff;--mute:#9db0dc;
--sans:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color-scheme:dark}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--ink);color:var(--text);font:400 15px/1.55 var(--sans);padding:0 max(16px,env(safe-area-inset-left,0px))}
.wrap{max-width:1080px;margin:0 auto;padding:22px 0 64px}
.badge{display:inline-flex;gap:8px;align-items:center;border:1px solid var(--teal);color:var(--teal);border-radius:99px;padding:5px 13px;font:600 11px var(--mono);letter-spacing:.12em}
.badge i{width:7px;height:7px;border-radius:50%;background:var(--teal);box-shadow:0 0 10px var(--teal)}
.hero{display:grid;grid-template-columns:1.05fr 1fr;gap:12px;align-items:center;min-height:430px}
h1{font:800 clamp(34px,6vw,58px)/1.04 var(--sans);letter-spacing:-.02em;margin:16px 0 14px;text-wrap:balance}
h1 em{font-style:normal;background:linear-gradient(90deg,var(--teal),var(--blue));-webkit-background-clip:text;background-clip:text;color:transparent}
.lead{color:var(--mute);font-size:16px;max-width:52ch;margin:0}
.meta{margin-top:14px;font:500 12px var(--mono);color:var(--mute);word-break:break-word}
.verdict{display:inline-block;margin-top:16px;padding:7px 14px;border-radius:10px;font:700 13px var(--sans);border:1px solid}
#cv{width:100%;aspect-ratio:1/1;max-height:480px;display:block;cursor:grab;touch-action:pan-y}#cv:active{cursor:grabbing}
.hint{font:600 11px var(--mono);color:var(--mute);text-align:center;letter-spacing:.08em}
.note{margin-top:16px;border:1px solid var(--gold);background:rgba(242,184,75,.08);border-radius:10px;padding:11px 14px;color:#f6dfa8;font-size:13.5px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:20px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}
.stat b{display:block;font:800 34px var(--sans);font-variant-numeric:tabular-nums}.stat span{font:600 10.5px var(--mono);letter-spacing:.1em;color:var(--mute);text-transform:uppercase}
h2{font:800 26px var(--sans);letter-spacing:-.01em;margin:46px 0 14px}h2 small{display:block;font:600 11px var(--mono);letter-spacing:.14em;color:var(--teal);margin-bottom:6px}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.tools input{flex:1 1 220px;min-width:0;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:99px;padding:8px 14px;font:500 13px var(--mono)}
.tools button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:99px;padding:7px 14px;font:600 12px var(--mono);cursor:pointer}
.tools button[aria-pressed=true]{background:var(--teal);color:#032;border-color:var(--teal)}
button:focus-visible,input:focus-visible,#cv:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
.tbl{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}
table{width:100%;border-collapse:collapse;min-width:640px;font-size:13.5px}
th{text-align:left;font:600 10.5px var(--mono);letter-spacing:.1em;color:var(--mute);padding:11px 14px;border-bottom:1px solid var(--line)}
td{padding:12px 14px;border-bottom:1px solid #162755;vertical-align:top}tr:last-child td{border:0}
tbody tr{cursor:pointer}tr.sel td{background:var(--panel2)}
code{font:600 12px var(--mono);color:var(--teal);word-break:break-word}
.sev{font:800 10.5px var(--mono);padding:3px 9px;border-radius:99px;letter-spacing:.06em;white-space:nowrap}
.sev.critical{background:#c06bff;color:#1b0030}.sev.high{background:var(--coral);color:#2a0008}.sev.medium{background:var(--gold);color:#2b1c00}.sev.low{background:var(--blue);color:#021233}.sev.info{background:var(--green);color:#022412}
.det{display:none;margin-top:8px;font-size:12.5px;color:var(--mute)}tr.sel .det{display:block}.det pre{margin:6px 0;background:#08112a;border:1px solid var(--line);border-radius:8px;padding:8px 10px;overflow-x:auto;color:var(--text);font:500 12px var(--mono)}.det b{color:var(--text)}
.empty{padding:22px;color:var(--mute);text-align:center}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;perspective:900px}
.card{background:linear-gradient(160deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:14px;padding:18px;transform-style:preserve-3d;transition:transform .15s ease-out,border-color .2s;min-width:0}
.card:hover{border-color:var(--teal)}.card h3{font:800 17px var(--sans);margin:0 0 6px;color:var(--teal)}.card p,.card li{margin:0;color:var(--mute);font-size:14px}.card ul{padding-left:18px;margin:0;display:grid;gap:5px}
.card.gap{border-color:var(--gold);background:rgba(242,184,75,.07)}.card.gap h3{color:var(--gold)}.card.no h3{color:var(--coral)}.full{grid-column:1/-1}
.cnt{float:right;font:700 11px var(--mono);color:var(--mute)}
footer{margin-top:40px;color:var(--mute);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
@media(max-width:800px){.hero{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){.card{transition:none}}
"""

BODY = r"""
<div class="wrap">
<span class="badge"><i></i><span id="badge"></span></span>
<section class="hero">
<div>
<h1>Where is your <em>quantum-vulnerable</em> cryptography?</h1>
<p class="lead" id="lead"></p>
<div class="verdict" id="verdict"></div>
<div class="meta" id="meta"></div>
<div class="note" id="samplenote" hidden><b>Read first.</b> This report comes from a made-up project built to show the format. It is not a client's code and names no real company.</div>
</div>
<div><canvas id="cv" tabindex="0" aria-label="Interactive 3D shield with finding markers. Drag to rotate, arrow keys also rotate."></canvas><div class="hint">DRAG TO ROTATE · TAP A MARKER</div></div>
</section>
<div class="stats" id="stats"></div>
<h2><small>FINDINGS</small>What the scan found</h2>
<div class="tools"><input id="q" type="search" placeholder="Search findings" aria-label="Search findings"><span id="flt" role="group" aria-label="Filter by severity"></span></div>
<div class="tbl"><table><thead><tr><th>RULE</th><th>FINDING</th><th>LOCATION</th><th>SEVERITY</th></tr></thead><tbody id="rows"></tbody></table><div class="empty" id="none" hidden>No findings match.</div></div>
<h2><small>NEXT STEPS</small>What to plan first</h2>
<div class="grid" id="plan"></div>
<h2><small>SCOPE</small>What this is, and is not</h2>
<div class="grid">
<div class="card"><h3>What this is</h3><ul><li>A pattern-based, line-by-line source scan</li><li>Covers Python, JS/TS, Java, Go, Ruby, PHP, C#, C/C++, Rust, Terraform, YAML, JSON and more</li><li>Offline: this report makes no network requests and your code is not uploaded anywhere</li><li>A starting point for a cryptographic inventory</li></ul></div>
<div class="card no"><h3>What this is not</h3><ul><li>Not a full security audit</li><li>Not a compliance certificate</li><li>Not a complete post-quantum migration plan</li><li>A clean result does not prove code is quantum-safe</li></ul></div>
<div class="card gap full" id="gapcard" hidden><h3>A gap found while testing the tool</h3><p>QuantumShield did not flag an <code>ssh-rsa</code> key in a file named <code>authorized_keys</code>, or a <code>TLS-1-0</code> policy name in Terraform, although rules for both exist. This is why a human review should follow any scan.</p></div>
<div class="card full" id="aboutcard" hidden><h3>About the author</h3><p>Komarapu Jordan Ephraim, an independent AI security engineer from India working on AI application security, post-quantum cryptography readiness and security tooling in Python. QuantumShield is an open-source project, currently v0.1. There are no published client case studies yet. This sample and the public code are the proof you can check.</p><p style="margin-top:8px"><code>github.com/komarapujordanephraim-creator/quantumshield</code></p></div>
</div>
<footer id="disc"></footer>
</div>
"""

JS = r"""
const D=JSON.parse(document.getElementById('qs-data').textContent);
const SEV=['critical','high','medium','low','info'];
const COL={critical:'#c06bff',high:'#ff6b7a',medium:'#f2b84b',low:'#4f8cff',info:'#5fe38f'};
const $=id=>document.getElementById(id);
const F=D.findings.slice().sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||a.file.localeCompare(b.file)||a.line-b.line);
const cnt=s=>F.filter(f=>f.severity===s).length;
$('badge').textContent=D.sample?'SAMPLE REPORT · SYNTHETIC DEMO APP':'CRYPTOGRAPHIC EXPOSURE REPORT';
$('lead').textContent=D.files_scanned+' files scanned, '+F.length+' findings. Results are pattern-based, so review each one before acting. Drag the shield to explore.';
const vc=D.verdict==='Action needed'?'#ff6b7a':(D.verdict==='Review recommended'?'#f2b84b':'#5fe38f');
const v=$('verdict');v.textContent=D.verdict;v.style.color=vc;v.style.borderColor=vc;v.style.background=vc+'1a';
$('meta').textContent=D.root+' · QuantumShield v'+D.version+' · '+D.generated+(D.files_skipped?' · '+D.files_skipped+' file(s) not scanned (binary, too large or excluded)':'');
if(D.sample){$('samplenote').hidden=false;$('gapcard').hidden=false;$('aboutcard').hidden=false}
$('disc').textContent=D.disclaimer;
$('stats').innerHTML=SEV.map(s=>'<div class="stat"><b style="color:'+COL[s]+'">'+cnt(s)+'</b><span>'+(s==='info'?'PQC references':s)+'</span></div>').join('');
let cur='all',sel=-1,query='';
$('flt').innerHTML=['all'].concat(SEV).map(s=>'<button data-f="'+s+'" aria-pressed="'+(s==='all')+'">'+(s==='all'?'ALL':s.toUpperCase())+'</button>').join(' ');
document.querySelectorAll('#flt button').forEach(b=>b.onclick=()=>{cur=b.dataset.f;syncF();render()});
function syncF(){document.querySelectorAll('#flt button').forEach(x=>x.setAttribute('aria-pressed',x.dataset.f===cur))}
$('q').oninput=e=>{query=e.target.value.toLowerCase();render()};
function render(){const rows=$('rows');rows.innerHTML='';let shown=0;
F.forEach((f,i)=>{if(cur!=='all'&&f.severity!==cur)return;if(query&&!(f.rule_id+' '+f.title+' '+f.file+' '+f.snippet).toLowerCase().includes(query))return;shown++;
const tr=document.createElement('tr');if(i===sel)tr.className='sel';
tr.innerHTML='<td><code>'+f.rule_id+'</code></td><td>'+f.title+'<div class="det"><pre>'+f.snippet+'</pre><b>Why:</b> '+f.why+'<br><b>Fix:</b> '+f.fix+'</div></td><td><code>'+f.file+':'+f.line+'</code></td><td><span class="sev '+f.severity+'">'+f.severity.toUpperCase()+'</span></td>';
tr.onclick=()=>{sel=sel===i?-1:i;render()};rows.appendChild(tr)});$('none').hidden=shown>0}
render();
/* plan: top rules by severity then count */
const groups={};F.forEach(f=>{(groups[f.rule_id]=groups[f.rule_id]||{f:f,n:0}).n++});
const plan=Object.values(groups).sort((a,b)=>SEV.indexOf(a.f.severity)-SEV.indexOf(b.f.severity)||b.n-a.n).slice(0,6);
$('plan').innerHTML=plan.length?plan.map(g=>'<div class="card"><h3>'+g.f.rule_id+' · '+g.f.title+'<span class="cnt">'+g.n+'×</span></h3><p>'+g.f.fix+'</p></div>').join(''):'<div class="card full"><h3>No findings from this rule set</h3><p>This does not prove the code is safe. Review dependencies, wrappers and runtime configuration separately.</p></div>';
/* 3D */
const cv=$('cv'),cx=cv.getContext('2d');let W=0,H=0;const dpr=Math.min(devicePixelRatio||1,2);
function size(){const r=cv.getBoundingClientRect();W=r.width;H=r.height;cv.width=W*dpr;cv.height=H*dpr;cx.setTransform(dpr,0,0,dpr,0,0)}
size();addEventListener('resize',size);
const KP=[[-.85,-.8],[-.45,-.93],[0,-.78],[.45,-.93],[.85,-.8],[.86,-.05],[.7,.38],[.36,.76],[0,1],[-.36,.76],[-.7,.38],[-.86,-.05]];
function cr(p0,p1,p2,p3,t){const t2=t*t,t3=t2*t;return[0,1].map(k=>.5*((2*p1[k])+(-p0[k]+p2[k])*t+(2*p0[k]-5*p1[k]+4*p2[k]-p3[k])*t2+(-p0[k]+3*p1[k]-3*p2[k]+p3[k])*t3))}
const OUT=[];for(let i=0;i<KP.length;i++){for(let s=0;s<6;s++)OUT.push(cr(KP[(i+11)%12],KP[i],KP[(i+1)%12],KP[(i+2)%12],s/6))}
const N=OUT.length,L=9,ZH=.24;
function layer(l){const z=(l/(L-1)*2-1)*ZH,k=1-.07*Math.pow(z/ZH,2);return OUT.map(p=>({x:p[0]*k,y:p[1]*k,z}))}
const LAY=[];for(let l=0;l<L;l++)LAY.push(layer(l));
const dust=[];for(let i=0;i<220;i++){const a=Math.random()*6.283,r=Math.sqrt(Math.random());dust.push({x:Math.cos(a)*r*.8,y:Math.sin(a)*r*.95,z:(Math.random()*2-1)*ZH})}
/* markers on the front face, spread with a golden-angle spiral */
const shown=F.slice(0,14);
const nodes=shown.map((f,i)=>{const r=Math.sqrt((i+.6)/(shown.length+.6))*.62,a=i*2.399;return{f,i:F.indexOf(f),x:Math.cos(a)*r,y:Math.sin(a)*r*1.05-.05,z:ZH}});
let yaw=.55,pitch=-.12,vy=0,drag=false,lx=0,ly=0,hover=-1;const calm=matchMedia('(prefers-reduced-motion:reduce)').matches;
cv.addEventListener('pointerdown',e=>{drag=true;lx=e.clientX;ly=e.clientY;cv.setPointerCapture(e.pointerId)});
cv.addEventListener('pointerup',()=>drag=false);
cv.addEventListener('pointermove',e=>{if(drag){yaw+=(e.clientX-lx)*.01;pitch=Math.max(-1,Math.min(1,pitch+(e.clientY-ly)*.006));vy=(e.clientX-lx)*.0008;lx=e.clientX;ly=e.clientY}const r=cv.getBoundingClientRect();hover=pick(e.clientX-r.left,e.clientY-r.top)});
cv.addEventListener('click',e=>{const r=cv.getBoundingClientRect(),k=pick(e.clientX-r.left,e.clientY-r.top);if(k>=0){sel=k;cur='all';query='';$('q').value='';syncF();render();$('rows').scrollIntoView({behavior:calm?'auto':'smooth',block:'center'})}});
cv.addEventListener('keydown',e=>{if(e.key==='ArrowLeft')yaw-=.15;if(e.key==='ArrowRight')yaw+=.15});
function proj(p){const cy=Math.cos(yaw),sy=Math.sin(yaw),cp=Math.cos(pitch),sp=Math.sin(pitch);let x=p.x*cy+p.z*sy,z=-p.x*sy+p.z*cy,y=p.y*cp-z*sp;z=p.y*sp+z*cp;const d=3.2,s=Math.min(W,H)*.34*d/(d+z);return{x:W/2+x*s,y:H/2+y*s,z:z}}
let scr=[];function pick(mx,my){let b=-1,bd=24;scr.forEach(n=>{const d=Math.hypot(n.x-mx,n.y-my);if(d<bd){bd=d;b=n.i}});return b}
function poly(P,fill,stroke,lw){cx.beginPath();P.forEach((q,i)=>i?cx.lineTo(q.x,q.y):cx.moveTo(q.x,q.y));cx.closePath();if(fill){cx.fillStyle=fill;cx.fill()}if(stroke){cx.strokeStyle=stroke;cx.lineWidth=lw||1;cx.stroke()}}
function frame(t){if(!drag)yaw+=vy+(calm?0:.0035);vy*=.97;cx.clearRect(0,0,W,H);
const g=cx.createRadialGradient(W/2,H/2,10,W/2,H/2,Math.min(W,H)*.52);g.addColorStop(0,'rgba(47,224,200,.2)');g.addColorStop(.6,'rgba(79,140,255,.06)');g.addColorStop(1,'rgba(79,140,255,0)');cx.fillStyle=g;cx.fillRect(0,0,W,H);
const sweep=calm?0:Math.sin(t*.0012)*.9;
for(let r=0;r<3;r++){cx.beginPath();for(let i=0;i<=90;i++){const a=i/90*6.283+r*1.1+(calm?0:t*.0003*(r+1)),R=1.4+r*.14;const p=proj({x:Math.cos(a)*R,y:Math.sin(a)*(.3+r*.1),z:Math.sin(a)*R});i?cx.lineTo(p.x,p.y):cx.moveTo(p.x,p.y)}cx.strokeStyle='rgba(79,140,255,'+(.38-r*.09)+')';cx.lineWidth=1;cx.stroke()}
const P=LAY.map(l=>l.map(proj));
/* back face, side layers, front face */
const fa=proj({x:0,y:0,z:ZH}).z<proj({x:0,y:0,z:-ZH}).z;/* front nearer camera? */
const order=fa?[L-1,...Array.from({length:L-2},(_,i)=>L-2-i),0]:[0,...Array.from({length:L-2},(_,i)=>i+1),L-1];
poly(P[order[0]],'rgba(18,33,74,.55)','rgba(47,224,200,.55)',1.6);
for(let k=1;k<order.length-1;k++){const l=order[k],e=Math.abs(l-(L-1)/2)/((L-1)/2);poly(P[l],null,'rgba(47,224,200,'+(.85-e*.55).toFixed(2)+')',1)}
for(let i=0;i<N;i+=6){cx.beginPath();for(let l=0;l<L;l++){const q=P[l][i];l?cx.lineTo(q.x,q.y):cx.moveTo(q.x,q.y)}cx.strokeStyle='rgba(79,140,255,.3)';cx.lineWidth=1;cx.stroke()}
const topI=order[order.length-1];poly(P[topI],'rgba(47,224,200,.07)','rgba(47,224,200,.95)',2);
/* scan sweep across the front face */
if(!calm){const hw=(sweep<.38?.86:.86*Math.max(0,1-(sweep-.38)/.62))*(sweep<-.8?.9:1),a=proj({x:-hw,y:sweep,z:ZH}),b=proj({x:hw,y:sweep,z:ZH});cx.beginPath();cx.moveTo(a.x,a.y);cx.lineTo(b.x,b.y);cx.strokeStyle='rgba(47,224,200,.9)';cx.lineWidth=2;cx.shadowColor='#2fe0c8';cx.shadowBlur=12;cx.stroke();cx.shadowBlur=0}
dust.forEach(d=>{const q=proj(d);cx.fillStyle='rgba(234,240,255,'+(.15+.25*(1-(q.z+1.5)/3)).toFixed(2)+')';cx.fillRect(q.x,q.y,1.6,1.6)});
/* lock glyph on the front */
const lk=[];for(let i=0;i<=24;i++){const a=Math.PI+i/24*Math.PI;lk.push(proj({x:Math.cos(a)*.11,y:-.02+Math.sin(a)*.13,z:ZH}))}
cx.beginPath();lk.forEach((q,i)=>i?cx.lineTo(q.x,q.y):cx.moveTo(q.x,q.y));cx.strokeStyle='rgba(47,224,200,.45)';cx.lineWidth=2;cx.stroke();
poly([proj({x:-.17,y:-.02,z:ZH}),proj({x:.17,y:-.02,z:ZH}),proj({x:.17,y:.2,z:ZH}),proj({x:-.17,y:.2,z:ZH})],'rgba(47,224,200,.12)','rgba(47,224,200,.45)',1.5);
/* markers */
scr=[];nodes.map(n=>({n,p:proj(n)})).sort((a,b)=>b.p.z-a.p.z).forEach(({n,p})=>{const c=COL[n.f.severity];scr.push({x:p.x,y:p.y,i:n.i});
const on=hover===n.i||sel===n.i,pulse=calm?0:Math.sin(t*.004+n.i)*1.6,r=(on?9:6)+pulse*.5;
cx.beginPath();cx.arc(p.x,p.y,r+6,0,7);cx.fillStyle=c+'30';cx.fill();cx.beginPath();cx.arc(p.x,p.y,r,0,7);cx.fillStyle=c;cx.fill();
if(on){cx.font='600 11px ui-monospace,Menlo,Consolas,monospace';const tx=n.f.rule_id+' '+n.f.title.replace(/&[a-z#0-9]+;/g,'');const w=cx.measureText(tx).width+16,bx=Math.min(Math.max(p.x-w/2,4),W-w-4),by=Math.max(p.y-34,4);cx.fillStyle='#0d1833';cx.fillRect(bx,by,w,22);cx.strokeStyle=c;cx.lineWidth=1;cx.strokeRect(bx,by,w,22);cx.fillStyle='#eaf0ff';cx.fillText(tx,bx+8,by+15)}});
requestAnimationFrame(frame)}
requestAnimationFrame(frame);
if(!calm)document.querySelectorAll('.card').forEach(c=>{c.addEventListener('pointermove',e=>{const r=c.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;c.style.transform='rotateX('+(-y*7)+'deg) rotateY('+(x*9)+'deg) translateZ(6px)'});c.addEventListener('pointerleave',()=>c.style.transform='')});
"""


def _esc(v):
    return html.escape(str(v), quote=True)


def build_data(result, summary, disclaimer, sample=False):
    root = Path(result.root).name or result.root
    return {
        "sample": sample,
        "version": __version__,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "root": _esc(root),
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "verdict": summary["verdict"],
        "disclaimer": _esc(disclaimer),
        "findings": [
            {k: (_esc(v) if isinstance(v, str) else v) for k, v in vars_.items()}
            for vars_ in (f.__dict__ for f in result.findings)
        ],
    }


def html_report_3d(result, summary, disclaimer, sample=False):
    data = json.dumps(build_data(result, summary, disclaimer, sample))
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>QuantumShield report</title><style>" + CSS + "</style></head><body>"
        + BODY
        + "<script id='qs-data' type='application/json'>" + data + "</script>"
        + "<script>" + JS + "</script></body></html>"
    )
