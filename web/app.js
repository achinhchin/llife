// [name, subdomain, icon, description, color]
const A=[
  ['Todo','todo','✓','Daily tasks & time blocks','#b5523b'],
  ['Money','money','฿','Income, spending & budgets','#4f7f5a'],
];
const $=s=>document.querySelector(s),ls=(k,v)=>{try{return v===undefined?localStorage[k]:localStorage[k]=v}catch(e){}};
$('#app').innerHTML=A.map(([n,s,i,d,c])=>`<a class="c" style="--c:${c}" href="https://${s}.achinhchin.com"><i>${i}</i><b>${n}</b><span>${d}</span></a>`).join('');
const th=b=>{document.documentElement.dataset.th=b;ls('th',b);document.querySelectorAll('#th button').forEach(x=>x.classList.toggle('on',x.dataset.th==b))};
$('#th').onclick=e=>e.target.dataset.th&&th(e.target.dataset.th);
th(ls('th')||'auto');
