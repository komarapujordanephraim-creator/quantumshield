"""Visual theme shared by the HTML report and the landing page.

Everything is inline and dependency-free (fonts are embedded), so a report is
a single file that works offline. Fonts: Instrument Serif and Inter, SIL OFL.
"""

from . import _fonts


def font_css() -> str:
    return (
        "@font-face{font-family:'Instrument Serif';font-style:normal;font-weight:400;font-display:swap;"
        "src:url(data:font/woff2;base64," + _fonts.FONT_SERIF + ") format('woff2')}"
        "@font-face{font-family:'Instrument Serif';font-style:italic;font-weight:400;font-display:swap;"
        "src:url(data:font/woff2;base64," + _fonts.FONT_SERIF_ITALIC + ") format('woff2')}"
        "@font-face{font-family:'Inter';font-style:normal;font-weight:100 900;font-display:swap;"
        "src:url(data:font/woff2;base64," + _fonts.FONT_SANS + ") format('woff2')}"
    )


HEAD_JS = "<script>document.documentElement.className+=' js'</script>"

AMBIENT_HTML = (
    "<div class='aurora' aria-hidden='true'><i></i><i></i></div>"
    "<div class='floor' aria-hidden='true'><i></i></div>"
    "<div class='progress' aria-hidden='true'><i></i></div>"
)

CSS_CORE = """
:root{--bg:#04050a;--panel:rgba(255,255,255,.04);--panel-b:rgba(255,255,255,.09);
--text:#f4f6fa;--muted:#8b93a3;--ice:#7df9ff;--gold:#c9a54a;--gold2:#e6c878;--line:rgba(255,255,255,.10);
--critical:#ff4d8d;--high:#ff7a59;--medium:#f5b942;--low:#5cc8ff;--info:#4ade80;
--serif:'Instrument Serif',Georgia,'Times New Roman',serif;
--sans:'Inter',ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
html{color-scheme:dark;scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.65 var(--sans);-webkit-font-smoothing:antialiased;
overflow-x:hidden;
background-image:linear-gradient(rgba(255,255,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.022) 1px,transparent 1px);
background-size:56px 56px}
a{color:inherit}
:focus-visible{outline:2px solid var(--ice);outline-offset:3px;border-radius:6px}
.aurora{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.aurora i{position:absolute;width:60vmax;height:60vmax;border-radius:50%;filter:blur(90px);opacity:.34}
.aurora i:nth-child(1){left:-18vmax;top:-24vmax;background:radial-gradient(circle,rgba(201,165,74,.55),transparent 65%);animation:d1 28s ease-in-out infinite alternate}
.aurora i:nth-child(2){right:-22vmax;top:-12vmax;background:radial-gradient(circle,rgba(125,249,255,.42),transparent 65%);animation:d2 32s ease-in-out infinite alternate}
@keyframes d1{to{transform:translate3d(16vmax,12vmax,0) scale(1.15)}}
@keyframes d2{to{transform:translate3d(-14vmax,16vmax,0) scale(1.1)}}
.floor{position:fixed;left:-40%;right:-40%;bottom:-6vh;height:52vh;perspective:520px;pointer-events:none;z-index:0;overflow:hidden;
-webkit-mask-image:linear-gradient(to top,#000 0%,transparent 88%);mask-image:linear-gradient(to top,#000 0%,transparent 88%)}
.floor i{position:absolute;left:0;right:0;bottom:0;height:220%;transform-origin:50% 100%;transform:rotateX(64deg);
background-image:linear-gradient(rgba(125,249,255,.2) 1px,transparent 1px),linear-gradient(90deg,rgba(125,249,255,.2) 1px,transparent 1px);
background-size:64px 64px;animation:fl 2.8s linear infinite}
@keyframes fl{from{background-position:0 0,0 0}to{background-position:0 64px,0 0}}
.progress{position:fixed;left:0;top:0;right:0;height:2px;z-index:60}
.progress i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--gold),var(--ice))}
.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:36px 20px 90px}
.mono{font-family:var(--mono)}
.muted{color:var(--muted)}
.eyebrow,.kicker{font:600 12px/1 var(--mono);letter-spacing:.24em;text-transform:uppercase;color:var(--ice)}
.kicker{margin:78px 0 14px}
.kicker b{color:var(--gold);font-weight:700;margin-right:10px}
.display{font-family:var(--serif);font-weight:400;font-size:clamp(54px,9.4vw,124px);line-height:.93;letter-spacing:-.025em;margin:20px 0 20px}
.display em,h2.sec em{font-style:italic;color:var(--gold2);padding-right:.05em}
.display .ice{font-style:italic;color:var(--ice)}
h2.sec{font-family:var(--serif);font-weight:400;font-size:clamp(34px,5vw,58px);line-height:1.02;letter-spacing:-.02em;margin:0 0 26px;max-width:18ch}
.lead{color:#aab3c2;max-width:52ch;font-size:19px;margin:0 0 20px}
.w{display:inline-block;white-space:nowrap}
.js .ch{display:inline-block;opacity:0;transform:perspective(600px) translateY(.35em) rotateX(-85deg);transform-origin:50% 100%;
animation:chin .95s cubic-bezier(.2,.8,.2,1) forwards;animation-delay:calc(var(--i)*26ms + .15s)}
@keyframes chin{to{opacity:1;transform:none}}
.hero{display:grid;grid-template-columns:1.1fr .9fr;gap:30px;align-items:center;min-height:440px}
.stage{position:relative;height:400px;border-radius:28px;border:1px solid var(--line);overflow:hidden;
background:radial-gradient(circle at 50% 44%,rgba(125,249,255,.13),transparent 62%),rgba(255,255,255,.02);
box-shadow:0 30px 80px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.06)}
.stage canvas{width:100%;height:100%;display:block}
.stage::before{content:"";position:absolute;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(255,255,255,.022) 0 1px,transparent 1px 4px)}
.corner{position:absolute;width:18px;height:18px;border:1px solid var(--ice);opacity:.55}
.corner.tl{top:14px;left:14px;border-right:0;border-bottom:0}.corner.tr{top:14px;right:14px;border-left:0;border-bottom:0}
.corner.bl{bottom:14px;left:14px;border-right:0;border-top:0}.corner.br{bottom:14px;right:14px;border-left:0;border-top:0}
.tag{position:absolute;left:46px;bottom:17px;font:600 10px/1 var(--mono);letter-spacing:.2em;color:rgba(125,249,255,.75);text-transform:uppercase}
.glass{background:var(--panel);border:1px solid var(--panel-b);border-radius:20px;-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px)}
.tilt{position:relative;transform-style:preserve-3d;transition:transform .16s ease-out,border-color .25s,box-shadow .25s;will-change:transform}
.tilt::after{content:"";position:absolute;inset:0;border-radius:inherit;pointer-events:none;opacity:0;transition:opacity .25s;
background:radial-gradient(380px circle at var(--mx,50%) var(--my,50%),rgba(255,255,255,.11),transparent 60%)}
.tilt:hover{border-color:rgba(125,249,255,.5);box-shadow:0 24px 60px rgba(0,0,0,.45),0 0 40px rgba(125,249,255,.07)}
.tilt:hover::after{opacity:1}
.btn{display:inline-block;padding:13px 24px;border-radius:999px;font-weight:600;font-size:15px;text-decoration:none;border:1px solid var(--line);
color:var(--text);transition:border-color .2s,background .2s,box-shadow .2s;will-change:transform}
.btn.p{background:#fff;color:#04050a;border-color:#fff}
.btn.p:hover{box-shadow:0 0 0 6px rgba(125,249,255,.14),0 10px 30px rgba(125,249,255,.18)}
.btn:hover{border-color:var(--ice)}
.chip{display:inline-block;font:700 11px/1 var(--mono);letter-spacing:.12em;padding:5px 9px;border-radius:999px;color:#04050a;background:var(--c,#fff)}
pre{margin:12px 0 0;padding:13px 15px;background:rgba(0,0,0,.5);border:1px solid var(--line);border-radius:12px;
overflow-x:auto;font:13px/1.55 var(--mono);color:#cfe9ff;white-space:pre-wrap;word-break:break-word}
.js .rv{opacity:0;transform:perspective(900px) translateY(46px) rotateX(14deg) scale(.985);transform-origin:50% 100%;
transition:opacity .9s ease,transform .9s cubic-bezier(.2,.8,.2,1);transition-delay:var(--d,0s)}
.js .rv.in{opacity:1;transform:none}
@media(max-width:860px){.hero{grid-template-columns:1fr}.stage{height:320px}.floor{height:34vh}}
@media(prefers-reduced-motion:reduce){
html{scroll-behavior:auto}
.js .rv{opacity:1;transform:none;transition:none}
.js .ch{opacity:1;transform:none;animation:none}
.aurora i,.floor i{animation:none}
}
"""

CSS_REPORT = """
.meta{color:var(--muted);font-size:13px;word-break:break-all;margin-top:6px}
.verdict{display:flex;gap:16px;align-items:center;padding:20px 24px;margin:10px 0 18px;border-left:3px solid var(--vc,var(--gold))}
.verdict .vt{font-family:var(--serif);font-size:34px;line-height:1;letter-spacing:-.01em}
.verdict .vt em{color:var(--vc,var(--gold2))}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.tile{padding:20px 20px 16px}
.tile .n{font-family:var(--serif);font-size:64px;line-height:.95;color:var(--c,#fff);letter-spacing:-.02em}
.tile .l{margin-top:10px;font:600 11px/1 var(--mono);letter-spacing:.18em;text-transform:uppercase;color:var(--muted)}
.toolbar{position:sticky;top:12px;z-index:30;display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:10px 12px;margin:30px 0 6px;border-radius:18px}
.toolbar input{flex:1 1 200px;min-width:0;background:rgba(0,0,0,.35);border:1px solid var(--line);border-radius:999px;color:var(--text);padding:10px 16px;font:14px var(--sans)}
.toolbar input::placeholder{color:#6b7383}
.toolbar input:focus{outline:none;border-color:var(--ice)}
.toolbar .fb{display:flex;flex-wrap:wrap;gap:6px}
.toolbar button{cursor:pointer;background:transparent;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:8px 13px;
font:600 11px/1 var(--mono);letter-spacing:.1em;text-transform:uppercase;transition:all .2s}
.toolbar button:hover{color:var(--text);border-color:rgba(255,255,255,.3)}
.toolbar button.on{color:#04050a;background:#fff;border-color:#fff}
.toolbar .cnt{font:600 11px/1 var(--mono);letter-spacing:.12em;color:var(--muted);padding:0 6px;white-space:nowrap}
.toolbar .cnt b{color:var(--ice)}
.hide{display:none!important}
h2.cat{font-family:var(--serif);font-weight:400;font-size:34px;letter-spacing:-.01em;margin:44px 0 14px}
h2.cat span{font:700 12px/1 var(--mono);letter-spacing:.2em;color:var(--gold);margin-right:12px;vertical-align:middle}
.f{padding:18px 20px;margin-bottom:12px;border-left:3px solid var(--c,#fff)}
.f .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.f .rid{color:var(--muted);font-size:12px}
.f h3{margin:12px 0 4px;font-family:var(--serif);font-weight:400;font-size:26px;letter-spacing:-.01em;line-height:1.1}
.loc{display:flex;align-items:center;gap:10px;flex-wrap:wrap;color:var(--ice);font-size:13px;word-break:break-all}
.copy{cursor:pointer;background:transparent;border:1px solid var(--line);color:var(--muted);border-radius:999px;padding:3px 9px;font:600 10px/1.4 var(--mono);letter-spacing:.1em;text-transform:uppercase}
.copy:hover{color:var(--text);border-color:var(--ice)}
.f details{margin-top:12px}
.f summary{cursor:pointer;list-style:none;color:var(--gold2);font:600 12px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;display:inline-flex;gap:8px;align-items:center}
.f summary::-webkit-details-marker{display:none}
.f summary::before{content:"+";display:inline-block;width:18px;height:18px;line-height:16px;text-align:center;border:1px solid var(--gold);border-radius:50%;transition:transform .25s}
.f details[open] summary::before{content:"\\2212";transform:rotate(180deg)}
.f details p{margin:10px 0 0;color:#c9d1de;font-size:15px}
.f details p i{font-style:normal;color:var(--muted);font:600 11px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;margin-right:8px}
.empty{padding:26px;text-align:center;color:var(--muted)}
.disc{margin-top:44px;padding:16px 18px;border:1px dashed var(--line);border-radius:14px;color:var(--muted);font-size:13px}
.foot{margin-top:28px;color:var(--muted);font:12px/1.4 var(--mono);letter-spacing:.1em;text-align:center}
@media(max-width:520px){.verdict .vt{font-size:28px}.tile .n{font-size:52px}}
"""

JS_3D = """
(function(){
var c=document.getElementById('qs3d');if(!c||!c.getContext)return;
var ctx=c.getContext('2d'),DPR=Math.min(window.devicePixelRatio||1,2),W=0,H=0,live=true;
function size(){var r=c.getBoundingClientRect();W=r.width;H=r.height;c.width=Math.round(W*DPR);c.height=Math.round(H*DPR);ctx.setTransform(DPR,0,0,DPR,0,0);}
size();window.addEventListener('resize',size);
var reduce=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
if('IntersectionObserver' in window){new IntersectionObserver(function(es){live=es[0].isIntersecting;if(live&&!reduce)requestAnimationFrame(loop);}).observe(c);}
var OUT=[[-1,-1.2],[0,-1.38],[1,-1.2],[1,.1],[.9,.65],[.62,1.05],[.28,1.35],[0,1.5],[-.28,1.35],[-.62,1.05],[-.9,.65],[-1,.1]];
var ZF=.3;
function lay(k,z){return OUT.map(function(p){return [p[0]*k,p[1]*k,z];});}
var FO=lay(1,ZF),BO=lay(1,-ZF),FI=lay(.66,ZF);
var OC=[[1,0,0],[-1,0,0],[0,1,0],[0,-1,0],[0,0,1],[0,0,-1]],OE=[[0,2],[0,3],[0,4],[0,5],[1,2],[1,3],[1,4],[1,5],[2,4],[2,5],[3,4],[3,5]];
function ringPts(n,r){var a=[];for(var i=0;i<n;i++){var t=i/n*6.2832;a.push([Math.cos(t)*r,0,Math.sin(t)*r]);}return a;}
var R1=ringPts(84,2.05),R2=ringPts(60,2.55);
function rnd(a,b){return a+Math.random()*(b-a);}
var N=(c.parentNode.clientWidth<520)?44:96,ST=[];for(var i=0;i<N;i++)ST.push([rnd(-5.5,5.5),rnd(-4,4),rnd(-5,3)]);
var COL=['255,122,89','245,185,66','255,77,141'];
var MK=[{x:-.45,y:-.62,c:0,h:-9},{x:.52,y:-.18,c:1,h:-9},{x:-.22,y:.38,c:2,h:-9},{x:.36,y:.86,c:0,h:-9},{x:0,y:-.98,c:1,h:-9}];
var px=0,py=0,tx=0,ty=0;
c.parentNode.addEventListener('pointermove',function(e){var r=c.getBoundingClientRect();tx=((e.clientX-r.left)/r.width-.5);ty=((e.clientY-r.top)/r.height-.5);});
c.parentNode.addEventListener('pointerleave',function(){tx=0;ty=0;});
function rot(p,ax,ay,az){var x=p[0],y=p[1],z=p[2],c1=Math.cos(ay),s1=Math.sin(ay),x1=x*c1+z*s1,z1=-x*s1+z*c1;
var c2=Math.cos(ax),s2=Math.sin(ax),y2=y*c2-z1*s2,z2=y*s2+z1*c2;
var c3=Math.cos(az),s3=Math.sin(az);return [x1*c3-y2*s3,x1*s3+y2*c3,z2];}
var S=1,CX=0,CY=0;
function pr(p){var d=7.5,k=d/(d-p[2]);return [CX+p[0]*S*k,CY+p[1]*S*k,p[2]];}
function line(a,b,col,al,w){ctx.strokeStyle='rgba('+col+','+al.toFixed(3)+')';ctx.lineWidth=w||1;ctx.beginPath();ctx.moveTo(a[0],a[1]);ctx.lineTo(b[0],b[1]);ctx.stroke();}
function da(z){var a=.22+.6*(z+1.6)/3.2;return a<.08?.08:(a>.95?.95:a);}
function poly(P,col,w,boost,by){for(var i=0;i<P.length;i++){var a=P[i],b=P[(i+1)%P.length];line(a,b,col,da((a[2]+b[2])/2),w);}}
function frame(t){
ctx.clearRect(0,0,W,H);S=Math.min(W,H)*.19;CX=W/2;CY=H/2+S*.05;
px+=(tx-px)*.06;py+=(ty-py)*.06;
var yaw=Math.sin(t*.5)*.55+px*.9,pit=-.1+Math.sin(t*.37)*.07+py*.6;
var i,k,p;
for(i=0;i<ST.length;i++){var s=ST[i];s[2]+=.006;if(s[2]>3){s[0]=rnd(-5.5,5.5);s[1]=rnd(-4,4);s[2]=-5;}
p=pr(rot(s,pit*.4,yaw*.35,0));var a=.12+.6*(p[2]+5)/8;ctx.fillStyle='rgba(190,230,255,'+a.toFixed(3)+')';var sz=.6+1.5*(p[2]+5)/8;ctx.fillRect(p[0],p[1],sz,sz);}
var r1=R1.map(function(v){return pr(rot(v,pit+.95,yaw*.3+t*.25,.35));});
var r2=R2.map(function(v){return pr(rot(v,pit-.6,-yaw*.3-t*.18,-.4));});
for(i=0;i<r1.length;i++){p=r1[i];ctx.fillStyle='rgba(125,249,255,'+(.15+.7*(p[2]+3)/6).toFixed(3)+')';ctx.fillRect(p[0]-1,p[1]-1,2,2);}
for(i=0;i<r2.length;i++){p=r2[i];ctx.fillStyle='rgba(201,165,74,'+(.12+.6*(p[2]+3.5)/7).toFixed(3)+')';ctx.fillRect(p[0]-1,p[1]-1,1.8,1.8);}
function tf(P,az){return P.map(function(v){return pr(rot(v,pit,yaw,0));});}
var fo=tf(FO),bo=tf(BO),fi=tf(FI);
poly(bo,'125,249,255',1,0);
for(i=0;i<fo.length;i++)line(fo[i],bo[i],'125,249,255',da((fo[i][2]+bo[i][2])/2)*.7,1);
for(i=0;i<fo.length;i++)line(fo[i],fi[i],'201,165,74',da(fo[i][2])*.9,1);
poly(fi,'201,165,74',1.2,0);
poly(fo,'240,248,255',1.8,0);
var top=tf([[0,-1.38,ZF]])[0],bot=tf([[0,1.5,ZF]])[0];line(top,bot,'125,249,255',.5,1);
var l1=tf([[-1,-.55,ZF]])[0],l2=tf([[1,-.55,ZF]])[0];line(l1,l2,'125,249,255',.32,1);
l1=tf([[-.96,.3,ZF]])[0];l2=tf([[.96,.3,ZF]])[0];line(l1,l2,'125,249,255',.32,1);
for(i=0;i<fo.length;i++){p=fo[i];ctx.fillStyle='rgba(125,249,255,'+da(p[2]).toFixed(3)+')';ctx.beginPath();ctx.arc(p[0],p[1],2.3,0,6.283);ctx.fill();}
var pulse=1+.12*Math.sin(t*2.2),oc=OC.map(function(v){return pr(rot([v[0]*.34*pulse,v[1]*.34*pulse,v[2]*.34*pulse],pit+t*.7,yaw+t*.9,t*.4));});
ctx.shadowColor='rgba(230,200,120,.9)';ctx.shadowBlur=10;
for(i=0;i<OE.length;i++)line(oc[OE[i][0]],oc[OE[i][1]],'230,200,120',.85,1.2);
ctx.shadowBlur=0;
var cyc=(t%5.2)/3.8,by=cyc>1?null:-1.55+3.2*cyc;
if(by!==null){var b1=pr(rot([-1.12,by,ZF+.02],pit,yaw,0)),b2=pr(rot([1.12,by,ZF+.02],pit,yaw,0));
ctx.shadowColor='rgba(125,249,255,.95)';ctx.shadowBlur=14;line(b1,b2,'125,249,255',.95,2);ctx.shadowBlur=0;
var g=ctx.createLinearGradient(0,b1[1]-34,0,b1[1]);g.addColorStop(0,'rgba(125,249,255,0)');g.addColorStop(1,'rgba(125,249,255,.12)');
ctx.fillStyle=g;ctx.beginPath();ctx.moveTo(b1[0],b1[1]-34);ctx.lineTo(b2[0],b2[1]-34);ctx.lineTo(b2[0],b2[1]);ctx.lineTo(b1[0],b1[1]);ctx.closePath();ctx.fill();}
for(i=0;i<MK.length;i++){var m=MK[i];if(by!==null&&Math.abs(by-m.y)<.1)m.h=t;
var age=t-m.h,al=age<0?0:Math.exp(-age*.55);var q=pr(rot([m.x,m.y,ZF+.03],pit,yaw,0));
ctx.fillStyle='rgba('+COL[m.c]+','+(.18+.82*al).toFixed(3)+')';ctx.beginPath();ctx.arc(q[0],q[1],3+2.5*al,0,6.283);ctx.fill();
if(age<1.6&&al>.05){ctx.strokeStyle='rgba('+COL[m.c]+','+(al*.7).toFixed(3)+')';ctx.lineWidth=1;ctx.beginPath();ctx.arc(q[0],q[1],6+age*10,0,6.283);ctx.stroke();}}
ctx.fillStyle='rgba(255,255,255,.95)';ctx.beginPath();ctx.arc(CX,CY,2.2,0,6.283);ctx.fill();
}
var t0=performance.now();
function loop(now){if(!live)return;frame((now-t0)/1000);if(!reduce)requestAnimationFrame(loop);}
if(reduce){frame(1.6);}else{requestAnimationFrame(loop);}
})();
"""

JS_UI = """
(function(){
var d=document,reduce=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
/* split headings into letters for a 3D flip-in */
d.querySelectorAll('[data-split]').forEach(function(el){
el.setAttribute('aria-label',el.textContent.replace(/\\s+/g,' ').trim());
var i=0;(function walk(node){Array.prototype.slice.call(node.childNodes).forEach(function(n){
if(n.nodeType===3){var f=d.createDocumentFragment();n.textContent.split(/(\\s+)/).forEach(function(tok){
if(!tok)return;if(/^\\s+$/.test(tok)){f.appendChild(d.createTextNode(' '));return;}
var w=d.createElement('span');w.className='w';w.setAttribute('aria-hidden','true');
tok.split('').forEach(function(ch){var s=d.createElement('span');s.className='ch';s.style.setProperty('--i',i++);s.textContent=ch;w.appendChild(s);});
f.appendChild(w);});n.parentNode.replaceChild(f,n);}
else if(n.nodeType===1){walk(n);}});})(el);});
/* scroll progress */
var bar=d.querySelector('.progress i');
function prog(){if(!bar)return;var h=d.documentElement.scrollHeight-window.innerHeight;bar.style.width=(h>0?window.scrollY/h*100:0)+'%';}
window.addEventListener('scroll',prog,{passive:true});prog();
/* reveal on scroll + count-up + terminal lines */
function countUp(el){if(el._c)return;el._c=1;var to=parseInt(el.getAttribute('data-to'),10)||0;if(reduce||to===0){el.textContent=to;return;}
var t0=performance.now();(function step(n){var p=Math.min(1,(n-t0)/900),e=1-Math.pow(1-p,3);el.textContent=Math.round(to*e);if(p<1)requestAnimationFrame(step);})(t0);}
d.querySelectorAll('[data-to]').forEach(function(el){el.textContent='0';});
function onIn(el){
if(el.classList.contains('rv')){el.classList.add('in');setTimeout(function(){el.classList.remove('rv');el.classList.remove('in');},1100);}
el.querySelectorAll&&el.querySelectorAll('[data-to]').forEach(countUp);
if(el.hasAttribute&&el.hasAttribute('data-to'))countUp(el);
var ln=el.querySelectorAll?el.querySelectorAll('.ln'):[];
for(var k=0;k<ln.length;k++){(function(l,k){setTimeout(function(){l.classList.add('on');},reduce?0:k*120);})(ln[k],k);}
}
var targets=d.querySelectorAll('.rv,[data-to],.term');
if('IntersectionObserver' in window){
var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){onIn(e.target);io.unobserve(e.target);}});},{threshold:.15,rootMargin:'0px 0px -6% 0px'});
targets.forEach(function(t){io.observe(t);});
}else{targets.forEach(onIn);}
/* 3D tilt with glare, magnetic buttons */
d.querySelectorAll('.tilt').forEach(function(el){
el.addEventListener('pointermove',function(e){var r=el.getBoundingClientRect(),x=(e.clientX-r.left)/r.width,y=(e.clientY-r.top)/r.height;
el.style.setProperty('--mx',(x*100).toFixed(1)+'%');el.style.setProperty('--my',(y*100).toFixed(1)+'%');
if(!reduce)el.style.transform='perspective(800px) rotateX('+((.5-y)*9).toFixed(2)+'deg) rotateY('+((x-.5)*12).toFixed(2)+'deg) translateZ(8px)';});
el.addEventListener('pointerleave',function(){el.style.transform='';});});
d.querySelectorAll('.btn').forEach(function(b){
b.addEventListener('pointermove',function(e){if(reduce)return;var r=b.getBoundingClientRect();b.style.transform='translate('+(((e.clientX-r.left)/r.width-.5)*9).toFixed(1)+'px,'+(((e.clientY-r.top)/r.height-.5)*7).toFixed(1)+'px)';});
b.addEventListener('pointerleave',function(){b.style.transform='';});});
/* report: severity filter + search + copy */
var btns=d.querySelectorAll('[data-filter]'),q=d.getElementById('q'),cnt=d.getElementById('cnt'),cur='all';
function apply(){var term=(q?q.value:'').trim().toLowerCase(),shown=0;
d.querySelectorAll('.f').forEach(function(f){var ok=(cur==='all'||f.getAttribute('data-sev')===cur)&&(!term||f.textContent.toLowerCase().indexOf(term)>-1);f.classList.toggle('hide',!ok);if(ok)shown++;});
d.querySelectorAll('[data-cat]').forEach(function(h){var any=d.querySelector('.f[data-catof="'+h.getAttribute('data-cat')+'"]:not(.hide)');h.classList.toggle('hide',!any);});
if(cnt)cnt.textContent=shown;var em=d.getElementById('empty');if(em)em.classList.toggle('hide',shown>0);}
btns.forEach(function(b){b.addEventListener('click',function(){cur=b.getAttribute('data-filter');btns.forEach(function(x){x.classList.toggle('on',x===b);});apply();});});
if(q){q.addEventListener('input',apply);d.addEventListener('keydown',function(e){if(e.key==='/'&&d.activeElement!==q&&!/input|textarea/i.test(d.activeElement.tagName)){e.preventDefault();q.focus();}});}
d.querySelectorAll('.copy').forEach(function(b){b.addEventListener('click',function(){var v=b.getAttribute('data-copy'),old=b.textContent;
function ok(){b.textContent='Copied';setTimeout(function(){b.textContent=old;},1200);}
try{navigator.clipboard.writeText(v).then(ok,function(){});}catch(e){}});});
})();
"""
