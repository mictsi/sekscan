'use strict';
(() => {
  const byId = id => document.getElementById(id);
  const text = (tag, value, className) => { const e=document.createElement(tag);e.textContent=String(value);if(className)e.className=className;return e; };
  const svgNode = (name, attributes={}, content) => {const e=document.createElementNS('http://www.w3.org/2000/svg',name);Object.entries(attributes).forEach(([k,v])=>e.setAttribute(k,String(v)));if(content!==undefined)e.textContent=String(content);return e;};
  const safeNumber = n => Number.isFinite(Number(n))?Number(n):0;
  const legend = (parent, names) => {const e=text('div','','legend');names.forEach((name,i)=>{const entry=text('span','');entry.append(text('i','','color-'+i),document.createTextNode(name));e.append(entry);});parent.append(e);};
  function svgBase(parent, title) {
    const s=svgNode('svg',{viewBox:'0 0 600 240',role:'img','aria-label':title});s.append(svgNode('title',{},title));parent.replaceChildren(s);return s;
  }
  function scaleMax(value) {if(value<=0)return 1;const p=Math.pow(10,Math.floor(Math.log10(value)));return Math.ceil(value/p)*p;}
  function lineChart(id, points, series, title, includeIncomplete=false, aggregate=false) {
    const parent=byId(id);if(!parent)return;
    if(!points.length){parent.replaceChildren(text('p','No runs in this period.','empty'));return;}
    const s=svgBase(parent,title),x0=52,x1=581,y0=15,y1=200;
    const times=points.map(p=>new Date(p.started_at).getTime()),minTime=Math.min(...times),maxTime=Math.max(...times);
    const x=t=>minTime===maxTime?(x0+x1)/2:x0+(t-minTime)/(maxTime-minTime)*(x1-x0);
    const maximum=scaleMax(Math.max(0,...points.flatMap(p=>(p.complete||includeIncomplete)?series.map(v=>safeNumber(v.value(p))):[])));
    const y=n=>y1-safeNumber(n)/maximum*(y1-y0);
    for(let i=0;i<=4;i++){const value=maximum*i/4,yy=y(value);s.append(svgNode('line',{x1:x0,x2:x1,y1:yy,y2:yy,class:'grid'}),svgNode('text',{x:x0-8,y:yy+3,'text-anchor':'end'},Number(value.toFixed(2))));}
    const ticks=minTime===maxTime?[minTime]:[minTime,(minTime+maxTime)/2,maxTime];
    ticks.forEach((t,i)=>{const d=new Date(t),date=d.toISOString();s.append(svgNode('text',{x:x(t),y:218,'text-anchor':i===0&&ticks.length>1?'start':i===ticks.length-1&&ticks.length>1?'end':'middle'},date.slice(5,10)+' '+date.slice(11,16)));});
    series.forEach((seriesItem,index)=>{
      let segment=[];
      const flush=()=>{if(segment.length>1)s.append(svgNode('polyline',{points:segment.join(' '),class:'series-line series-'+index,'stroke-dasharray':['none','6 3','2 3','8 3 2 3','4 4','1 3'][index%6]}));segment=[];};
      points.forEach((p,i)=>{if(!p.complete&&!includeIncomplete){flush();return;}if(aggregate&&!includeIncomplete&&i&&p.complete_projects!==points[i-1].complete_projects)flush();segment.push(x(times[i])+','+y(seriesItem.value(p)));});flush();
      points.forEach((p,i)=>{
        if(!p.complete&&!includeIncomplete)return;
        const a=aggregate?svgNode('g',{tabindex:0,role:'img'}):svgNode('a',{href:'/scans/'+encodeURIComponent(p.id)+'?project='+encodeURIComponent(document.body.dataset.project),tabindex:0});
        const dot=svgNode('circle',{cx:x(times[i]),cy:y(seriesItem.value(p)),r:3.5,class:p.complete?'point series-'+index:'incomplete-point'});
        const tooltip=new Date(times[i]).toISOString()+' · '+(aggregate?'Portfolio':p.id)+' · '+seriesItem.name+': '+safeNumber(seriesItem.value(p))+' · '+p.status;
        dot.append(svgNode('title',{},tooltip));a.setAttribute('aria-label',tooltip);a.append(dot);s.append(a);
      });
    });
    if(!includeIncomplete&&!aggregate)points.forEach((p,i)=>{if(p.complete)return;const a=svgNode('a',{href:'/scans/'+encodeURIComponent(p.id)+'?project='+encodeURIComponent(document.body.dataset.project),tabindex:0,'aria-label':'Incomplete run '+p.id});const dot=svgNode('path',{d:`M ${x(times[i])-4} ${y1-4} L ${x(times[i])+4} ${y1+4} M ${x(times[i])-4} ${y1+4} L ${x(times[i])+4} ${y1-4}`,class:'incomplete-point'});dot.append(svgNode('title',{},new Date(times[i]).toISOString()+' · INCOMPLETE · '+p.id));a.append(dot);s.append(a);});
    legend(parent,series.map(s=>s.name));
  }
  function barChart(id, labels, before, after, title) {
    const parent=byId(id);if(!parent)return;const s=svgBase(parent,title),x0=42,x1=585,y0=15,y1=198;
    const max=scaleMax(Math.max(0,...labels.flatMap(k=>[safeNumber(before[k]),safeNumber(after[k])]))),y=n=>y1-safeNumber(n)/max*(y1-y0);
    for(let i=0;i<=4;i++){const n=max*i/4;s.append(svgNode('line',{x1:x0,x2:x1,y1:y(n),y2:y(n),class:'grid'}),svgNode('text',{x:x0-8,y:y(n)+3,'text-anchor':'end'},Number(n.toFixed(2))));}
    const width=(x1-x0)/Math.max(1,labels.length);
    labels.forEach((name,i)=>{const start=x0+i*width+width*.18,bw=Math.min(26,width*.25);[before,after].forEach((values,j)=>{const n=safeNumber(values[name]);const rect=svgNode('rect',{x:start+j*(bw+4),y:y(n),width:bw,height:y1-y(n),rx:2,class:'series-'+j});rect.append(svgNode('title',{},name+' · '+(j?'candidate':'baseline')+': '+n));s.append(rect);});const label=name==='vulnerability'?'vuln.':name==='misconfiguration'?'config.':name;s.append(svgNode('text',{x:x0+(i+.5)*width,y:219,'text-anchor':'middle'},label));});legend(parent,['Baseline','Candidate']);
  }
  function projectPicker() {
    const input=document.querySelector('[data-project-filter]');
    const options=byId('project-options'),status=byId('project-picker-status');
    if(!input||input.readOnly||!options||!status)return;
    let timer,controller,generation=0;
    const lookup=async()=>{
      const current=++generation;
      if(controller)controller.abort();
      controller=new AbortController();
      status.textContent='Looking up project keys…';
      try {
        const params=new URLSearchParams({q:input.value,page_size:'25'});
        const response=await fetch('/api/projects?'+params,{signal:controller.signal,cache:'no-store'});
        if(!response.ok)throw new Error('Project lookup failed');
        const data=await response.json();
        if(current!==generation)return;
        if(!Array.isArray(data.items))throw new Error('Invalid project response');
        const choices=data.items.slice(0,25).filter(p=>typeof p.key==='string').map(p=>{
          const option=document.createElement('option');option.value=p.key;
          if(typeof p.name==='string'&&p.name!==p.key)option.label=p.name;
          return option;
        });
        options.replaceChildren(...choices);
        status.textContent=choices.length ? (data.has_next?'First 25 matches; type more to narrow.':'Choose an exact key from the suggestions.') : 'No matching projects. Check the exact key.';
      } catch(error) {
        if(error.name!=='AbortError'&&current===generation){options.replaceChildren();status.textContent='Suggestions unavailable; enter an exact project key.';}
      }
    };
    input.addEventListener('focus',lookup);
    input.addEventListener('input',()=>{
      ++generation;if(controller)controller.abort();options.replaceChildren();
      clearTimeout(timer);timer=setTimeout(lookup,200);
    });
    input.form.addEventListener('submit',()=>{
      // A comparison selected for one project must not leak into another.
      if(input.value!==document.body.dataset.project){
        for(const name of ['base','head','page','offset']){
          input.form.querySelectorAll('input[name="'+name+'"]').forEach(e=>e.remove());
        }
      }
    });
  }
  function selection() {
    const form=byId('compare-selection');if(!form)return;
    const base=byId('base-selection'),head=byId('head-selection');
    const key='sekscan-compare:'+JSON.stringify([document.body.dataset.namespace,document.body.dataset.project]);
    const defaults={base:base.value,head:head.value};
    const mark=()=>document.querySelectorAll('[data-pick]').forEach(b=>{const selected=b.dataset.run===(b.dataset.pick==='base'?base.value:head.value);b.classList.toggle('selected',selected);b.setAttribute('aria-pressed',String(selected));});
    const save=()=>{
      try{sessionStorage.setItem(key,JSON.stringify({base:base.value,head:head.value}));}catch(_){/* Selection is also carried in page links when storage is unavailable. */}
      document.querySelectorAll('.paging a,.tabs a').forEach(a=>{const u=new URL(a.getAttribute('href'),'http://history.invalid');u.searchParams.set('base',base.value);u.searchParams.set('head',head.value);a.setAttribute('href',u.pathname+u.search);});
      document.querySelectorAll('form:not(#compare-selection)').forEach(f=>{for(const [name,value] of [['base',base.value],['head',head.value]]){let input=f.querySelector('input[name='+name+']');if(!input){input=document.createElement('input');input.type='hidden';input.name=name;f.append(input);}input.value=value;}});
      mark();
    };
    try{const url=new URLSearchParams(location.search);const old=JSON.parse(sessionStorage.getItem(key)||'null');if(!url.has('base')&&!url.has('head')&&old&&typeof old.base==='string'&&typeof old.head==='string'&&old.base.length<=64&&old.head.length<=64){base.value=old.base;head.value=old.head;}}catch(_){/* Invalid local state does not prevent using manual IDs. */}
    document.querySelectorAll('[data-pick]').forEach(b=>b.addEventListener('click',()=>{(b.dataset.pick==='base'?base:head).value=b.dataset.run;save();}));
    base.addEventListener('input',save);head.addEventListener('input',save);
    byId('clear-selection').addEventListener('click',()=>{base.value=defaults.base;head.value=defaults.head;save();});
    form.addEventListener('submit',event=>{head.setCustomValidity(base.value===head.value?'Select two different runs.':'');if(!form.reportValidity())event.preventDefault();});
    head.addEventListener('input',()=>head.setCustomValidity(''));base.addEventListener('input',()=>head.setCustomValidity(''));save();
  }
  selection();
  projectPicker();
  const raw=byId('chart-data');if(!raw)return;
  try {
    const data=JSON.parse(raw.textContent);
    if(document.body.dataset.mode==='projects'&&document.body.dataset.tab==='overview') {
      const p=(data.points||[]).map(x=>({...x,started_at:x.date+'T00:00:00Z',complete:x.complete_projects>0,status:x.complete_projects+' complete / '+x.projects+' known projects'}));
      lineChart('portfolio-findings-chart',p,[{name:'Findings',value:x=>x.findings},{name:'Policy failures',value:x=>x.failures},{name:'Review',value:x=>x.reviews}],'Portfolio findings in complete latest assessments',false,true);
      lineChart('portfolio-states-chart',p,[{name:'Passed',value:x=>x.passed},{name:'Failed',value:x=>x.failed},{name:'Incomplete',value:x=>x.incomplete}],'Latest project assessment states',true,true);
      lineChart('portfolio-severity-chart',p,['critical','high','medium'].map(k=>({name:k,value:x=>x.by_severity[k]||0})),'Portfolio severity',false,true);
      lineChart('portfolio-freshness-chart',p,[{name:'Known projects',value:x=>x.projects},{name:'Stale snapshots',value:x=>x.stale_projects}],'Portfolio evidence freshness',true,true);
    } else if(document.body.dataset.mode==='runs'&&document.body.dataset.tab==='overview') {
      const p=Array.isArray(data.points)?data.points:[],last=p[p.length-1];
      byId('latest-findings').textContent=last&&last.complete?last.summary.findings:'—';byId('latest-failures').textContent=last&&last.complete?last.summary.failures:'—';byId('latest-status').textContent=last?last.status+' · '+last.id.slice(0,12):'No matching runs';byId('window-incomplete').textContent=p.filter(r=>!r.complete).length;
      if(new Set(p.map(x=>x.target_kind)).size>1||new Set(p.map(x=>x.branch)).size>1)byId('mixed-series').textContent='This window mixes branches or target kinds. Apply filters before interpreting a trend.';
      lineChart('trend-findings',p,[{name:'Findings',value:r=>r.summary.findings},{name:'Failures',value:r=>r.summary.failures},{name:'Review',value:r=>r.summary.reviews}],'Findings and policy outcomes over time');
      lineChart('trend-severity',p,['critical','high','medium'].map(k=>({name:k,value:r=>r.summary.by_severity?.[k]||0})),'Severity over time');
      const categories=[...new Set(p.flatMap(r=>Object.keys(r.summary.by_category||{})))].sort().slice(0,6);
      lineChart('trend-categories',p,categories.map(k=>({name:k,value:r=>r.summary.by_category?.[k]||0})),'Findings by category over time');
      lineChart('trend-components',p,[{name:'Components',value:r=>r.summary.components}],'Components over time');
      lineChart('trend-duration',p,[{name:'Seconds',value:r=>Math.round(r.duration_ms/100)/10}],'Scan duration in seconds',true);
    } else if(document.body.dataset.mode==='compare') {
      barChart('compare-severity',['critical','high','medium','low','info','unknown'],data.base.summary.by_severity||{},data.head.summary.by_severity||{},'Baseline and candidate severity');
      const categories=[...new Set([...Object.keys(data.base.summary.by_category||{}),...Object.keys(data.head.summary.by_category||{})])].sort();
      barChart('compare-categories',categories,data.base.summary.by_category||{},data.head.summary.by_category||{},'Baseline and candidate categories');
    }
  } catch(error) {
    document.querySelectorAll('.chart-area').forEach(e=>e.replaceChildren(text('p','Chart data could not be rendered. Use the tables or JSON API.','notice')));
    console.error('sekscan history chart:',error.message);
  }
})();
