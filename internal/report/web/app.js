'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = String(text); if (cls) n.className = cls; return n; };
  const clear = node => node.replaceChildren();
  const labels = {overview:'Security overview',findings:'All findings',licenses:'Application licenses',components:'Component inventory',changes:'Changes from baseline',health:'Scan health'};
  const rank = {critical:5,high:4,medium:3,low:2,info:1,unknown:0};
  const badgeClasses = new Set(['critical','high','medium','low','info','unknown','fail','failed','review','incomplete','pass','passed','completed','accepted','existing','new','resolved','skipped','excluded','unverified']);
  const badge = value => el('span', value || 'unknown', 'badge ' + (badgeClasses.has(value) ? value : 'unknown'));
  let report = JSON.parse($('report-data').textContent);
  let state = {view:'overview',page:0,sort:'severity',direction:-1};
  const viewSettings = new Map();
  let filtered = [], columns = [], componentIndex = new Map();
  let pageSize = 25;
  const controls = ['search','category','severity','scope','decision','engine','baseline','fix'];
  const normalize = v => String(v || '').toLowerCase();
  const at = array => Array.isArray(array) ? array : [];
  const fieldValue = (row, key) => {
    if (key === 'engine') return at(row.observations).map(x=>x.engine).join(', ');
    if (key === 'license') return at(row.licenses).map(x=>x.expression).join(' / ') || 'Unknown';
    if (key === 'fix') return at(row.fixed_versions).join(', ') || 'Not reported';
    if (key === 'decision') return row.decision || row.license_decision || 'not evaluated';
    return row[key] || '';
  };
  function fillSelect(id, values) {
    const node=$(id), first=node.options[0].textContent; clear(node);
    node.append(new Option(first,'')); [...new Set(values.filter(Boolean))].sort().forEach(v=>node.append(new Option(v,v)));
  }
  function initialize() {
    if (report.schema_version !== '1.0' || !Array.isArray(report.findings) || !Array.isArray(report.components) || !Array.isArray(report.engines)) throw new Error('Unsupported report schema');
    componentIndex=new Map(report.components.map(c=>[c.id,c]));
    const rows=report.findings.concat(at(report.resolved));
    fillSelect('category',rows.map(f=>f.category)); fillSelect('severity',rows.map(f=>f.severity));
    fillSelect('scope',['application','operating-system','unknown']);
    fillSelect('decision',['pass','fail','review','accepted','excluded']); fillSelect('engine',report.engines.map(e=>e.name));
    fillSelect('baseline',['new','existing','resolved']);
    $('target-description').textContent=(report.project_key?report.project_key+' · ':'')+(report.target.kind || 'target')+' / '+report.target.value;
    $('report-id').textContent='SCAN '+report.id.slice(0,12).toUpperCase();
    const status=badge(report.status); status.id='status'; $('status').replaceWith(status);
    $('run-time').textContent=new Date(report.finished_at).toLocaleString();
    $('footer-time').textContent='Generated '+new Date(report.finished_at).toISOString();
    $('app-version').textContent='sekscan '+report.app_version+' · schema '+report.schema_version;
    $('nav-count').textContent=String(report.findings.length);
    document.title=(report.project_key||'Scan report')+' — sekscan';
    document.querySelectorAll('[data-history-project]').forEach(a=>{a.textContent=report.project_key||'Project';a.href='/projects?'+new URLSearchParams({project:report.project_key||''});});
    document.querySelectorAll('[data-project-context]').forEach(e=>e.textContent=report.project_key||'Project');
    document.querySelectorAll('[data-project-route]').forEach(a=>a.href='/projects?'+new URLSearchParams({project:report.project_key||'',tab:a.dataset.projectRoute==='runs'?'runs':'overview'}));
    const banner=$('coverage-banner');
    banner.className='banner'+(report.complete && report.status==='passed'?'':' warning');
    banner.textContent=report.complete ? 'Configured scans completed. '+report.summary.failures+' policy failures · '+report.summary.reviews+' items require review. Completed scans do not guarantee full security coverage.' : 'INCOMPLETE SCAN — one or more required engines did not complete. Missing results must not be treated as a clean scan.';
    renderMetrics(); renderCharts(); renderHealth(); resetFilters();
    viewSettings.clear();const hash=location.hash.slice(1);state.view=labels[hash]?hash:'overview';render();
  }
  function renderMetrics() {
    clear($('metrics')); const s=report.summary;
    const specs=[['Critical findings',s.by_severity.critical || 0,'Immediate investigation','critical'],['High findings',s.by_severity.high || 0,'Prioritize remediation','high'],['Review required',s.reviews || 0,'License and evidence decisions','review'],['Components',s.components || 0,'Discovered in the supplied target','']];
    specs.forEach(([title,value,note,color])=>{const card=el('article',undefined,'metric');const top=el('div',undefined,'metric-top');top.append(el('span',title),el('span',undefined,'metric-dot '+color));card.append(top,el('div',value,'metric-number'),el('div',note,'metric-note'));$('metrics').append(card);});
  }
  function renderCharts() {
    const total=Math.max(report.findings.length,1);clear($('severity-chart'));
    ['critical','high','medium','low','info','unknown'].forEach(s=>{const row=el('div',undefined,'chart-row'), count=report.summary.by_severity[s] || 0;const progress=el('progress');progress.max=total;progress.value=count;progress.className=s;progress.setAttribute('aria-label',s+' findings');row.append(el('span',s,'chart-label'),progress,el('span',count,'chart-value'));$('severity-chart').append(row);});
    clear($('engine-overview'));report.engines.forEach(e=>{const row=el('div',undefined,'engine-row');const name=el('div');name.append(el('div',e.name+' '+(e.version||''),'engine-name'),el('div',at(e.checks).join(' · '),'engine-description'));row.append(name,badge(e.status));$('engine-overview').append(row);});
  }
  function keyValues(parent, pairs) {const grid=el('div',undefined,'keyvalue');pairs.forEach(([k,v])=>{grid.append(el('div',k,'muted'),el('div',v || 'Not recorded','value'));});parent.append(grid);}
  function renderHealth() {
    clear($('health-cards'));report.engines.forEach(e=>{const card=el('article',undefined,'health-card'), h=el('h2',e.name);h.append(badge(e.status));card.append(h);keyValues(card,[['Version',e.version],['Required',e.required?'Yes':'No'],['Checks',at(e.checks).join(', ')],['Duration',(e.duration_ms/1000).toFixed(2)+' seconds'],['Executable',e.executable],['SHA-256',e.executable_sha256],['Diagnostics',e.error || 'No execution error'],['Database',e.database?JSON.stringify(e.database,null,2):'No database metadata recorded for this engine']]);$('health-cards').append(card);});
    if(report.source){const card=el('article',undefined,'health-card');card.append(el('h2','Source provenance'));keyValues(card,[['Repository',report.source.repository],['Requested ref',report.source.requested_ref||'Default branch'],['Resolved ref',report.source.resolved_ref],['Commit',report.source.revision],['Subdirectory',report.source.subdir||'Repository root'],['Archive SHA-256',report.source.archive_sha256],['Batch',report.batch_id]]);$('health-cards').prepend(card);}
    clear($('warnings'));at(report.warnings).forEach(w=>$('warnings').append(el('li',w)));
  }
  function resetFilters() {controls.forEach(id=>$(id).value='');state.page=0;}
  function currentRows() {
    if (state.view==='components') return report.components;
    if (state.view==='licenses') return report.components.filter(c=>$('scope').value ? true : c.scope!=='operating-system');
    if (state.view==='changes') return report.findings.concat(at(report.resolved));
    return report.findings;
  }
  function matches(row) {
    const query=normalize($('search').value);
    if(query && !normalize(JSON.stringify(row)).includes(query)) return false;
    for(const key of ['category','severity','scope','decision','baseline']) {
      const value=$(key).value; if(value && fieldValue(row,key)!==value) return false;
    }
    const engine=$('engine').value;
    if(engine && !at(row.observations).some(o=>o.engine===engine) && !at(row.licenses).some(l=>l.source===engine)) return false;
    const fix=$('fix').value; if(fix && (at(row.fixed_versions).length>0)!==(fix==='yes')) return false;
    return true;
  }
  function selectView(view) {
    if(!labels[view])return;
    viewSettings.set(state.view,{...state,filters:Object.fromEntries(controls.map(id=>[id,$(id).value]))});
    const saved=viewSettings.get(view);
    if(saved){state={view,page:saved.page,sort:saved.sort,direction:saved.direction};controls.forEach(id=>$(id).value=saved.filters[id]||'');}
    else {state={view,page:0,sort:(view==='components'||view==='licenses')?'name':'severity',direction:(view==='components'||view==='licenses')?1:-1};resetFilters();}
    try{history.replaceState(null,'','#'+view);}catch{} render();
  }
  function render() {
    $('page-title').textContent=labels[state.view];document.querySelectorAll('.nav[data-view]').forEach(n=>{const active=n.dataset.view===state.view;n.classList.toggle('active',active);n.setAttribute('aria-selected',String(active));n.tabIndex=active?0:-1;});$('report-panel').setAttribute('aria-labelledby','tab-'+state.view);
    const health=state.view==='health', isComponent=state.view==='components'||state.view==='licenses';
    $('health-section').hidden=!health;$('data-section').hidden=health||state.view==='overview';$('overview-panels').hidden=state.view!=='overview';$('metrics').hidden=state.view!=='overview';$('coverage-banner').hidden=!['overview','health'].includes(state.view);
    ['category','severity','baseline','fix'].forEach(id=>{$(id).hidden=isComponent;$(id).closest('.sk-field').hidden=isComponent;});
    if(health)return;
    columns=isComponent ? [['name','Component'],['version','Version'],['ecosystem','Ecosystem'],['scope','Scope'],['license','License evidence'],['decision','Policy']] : [['severity','Severity'],['rule_id','Finding'],['package','Package / location'],['category','Category'],['fix','Reported fix'],['decision','Policy'],['baseline','Change']];
    $('table-title').textContent=state.view==='overview'?'Prioritized findings':labels[state.view];
    $('table-subtitle').textContent=state.view==='licenses'?'OS license policy is excluded. Different license expressions require evidence review.':isComponent?'Inspect packages, locations, license evidence, and ownership classification.':'Inspect a finding to see evidence, fixes, and policy decisions.';
    filtered=currentRows().filter(matches).sort((a,b)=>{let x=fieldValue(a,state.sort),y=fieldValue(b,state.sort);if(state.sort==='severity'){x=rank[x]||0;y=rank[y]||0;return (x-y)*state.direction;}return String(x).localeCompare(String(y))*state.direction;});
    const pages=Math.max(1,Math.ceil(filtered.length/pageSize));state.page=Math.min(state.page,pages-1);
    clear($('table-head'));const head=el('tr');columns.forEach(([key,title])=>{const th=el('th'),button=el('button',title+(key===state.sort?(state.direction>0?' ↑':' ↓'):''));button.addEventListener('click',()=>{if(state.sort===key)state.direction*=-1;else{state.sort=key;state.direction=1;}render();});th.setAttribute('scope','col');if(key===state.sort)th.setAttribute('aria-sort',state.direction>0?'ascending':'descending');th.append(button);head.append(th);});$('table-head').append(head);
    clear($('table-body'));filtered.slice(state.page*pageSize,(state.page+1)*pageSize).forEach(row=>{
      const tr=el('tr');columns.forEach(([key])=>{
        const td=el('td');let value=fieldValue(row,key);
        if(['severity','decision','baseline'].includes(key))td.append(badge(value));
        else if(key==='rule_id'||key==='name'){const button=el('button',value,'row-link');button.title=value;button.addEventListener('click',()=>showDetail(row,isComponent));td.append(button);td.append(el('div',isComponent?row.purl||row.ecosystem:row.title,'subline'));}
        else if(key==='package'){value=row.package || (at(row.locations)[0]||{}).path || 'Target-level finding';td.append(el('span',value));td.append(el('div',row.version || row.scope,'subline'));}
        else {td.textContent=value||'—';td.title=value;}
        tr.append(td);
      });$('table-body').append(tr);
    });
    $('empty-state').hidden=filtered.length!==0;$('result-count').textContent=filtered.length+' matching records · '+currentRows().length+' in this view';$('page-number').textContent=(state.page+1)+' / '+pages;$('previous').disabled=state.page===0;$('next').disabled=state.page>=pages-1;$('first-page').disabled=state.page===0;$('last-page').disabled=state.page>=pages-1;$('jump-page').value=state.page+1;$('jump-page').max=pages;
  }
  function section(title,text,pre=false) {const s=el('section',undefined,'detail-section');s.append(el('h3',title),el(pre?'pre':'p',text));$('detail-body').append(s);return s;}
  function showDetail(row,isComponent) {
    $('detail-title').textContent=isComponent?row.name:row.title;$('detail-category').textContent=isComponent?'COMPONENT EVIDENCE':row.category;clear($('detail-body'));
    if(isComponent){keyValues($('detail-body'),[['Version',row.version],['Ecosystem',row.ecosystem],['Package URL',row.purl],['Scope',row.scope],['Scope evidence',row.scope_reason],['License decision',row.license_decision],['Policy reason',row.license_reason]]);section('License evidence',JSON.stringify(at(row.licenses),null,2),true);}
    else {
      keyValues($('detail-body'),[['Rule',row.rule_id],['Severity',row.severity],['Decision',row.decision],['Policy reason',row.decision_reason],['Package',row.package],['Version',row.version],['Scope',row.scope],['Baseline',row.baseline],['Exception',row.exception],['Fingerprint',row.fingerprint]]);
      section('Description',row.description||'No additional description.');section('Reported fixed versions',at(row.fixed_versions).join(', ')||'No fix was reported by the scanner.');section('Scanner observations',JSON.stringify(at(row.observations),null,2),true);
      const links=at(row.observations).filter(o=>o.url&&/^https?:\/\//i.test(o.url));if(links.length){const s=section('Advisory references','');links.forEach(o=>{const p=el('p'),a=el('a',o.url);a.href=o.url;a.target='_blank';a.rel='noopener noreferrer';p.append(a);s.append(p);});}
      if(componentIndex.has(row.component_id)){const c=componentIndex.get(row.component_id);section('Component license evidence',JSON.stringify(at(c.licenses),null,2),true);}
    }
    section('Locations',at(row.locations).map(l=>l.path+(l.line?':'+l.line:'')).join('\n')||'No source location reported.',true);$('detail').showModal();$('detail-title').focus();
  }
  function download(name,type,content) {const address=URL.createObjectURL(new Blob([content],{type}));const a=el('a');a.href=address;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(address),1000);}
  function csvCell(value) {let s=String(value??'');if(/^\s*[=+@-]/.test(s)||/^[\t\r\n]/.test(s))s="'"+s;return '"'+s.replaceAll('"','""')+'"';}
  document.querySelectorAll('.nav[data-view]').forEach(n=>n.addEventListener('click',()=>selectView(n.dataset.view)));
  $('view-health').addEventListener('click',()=>selectView('health'));$('reset-filters').addEventListener('click',()=>{resetFilters();render();});
  controls.forEach(id=>$(id).addEventListener(id==='search'?'input':'change',()=>{state.page=0;render();}));
  $('page-size').addEventListener('change',()=>{pageSize=Number($('page-size').value);state.page=0;render();});
  $('first-page').addEventListener('click',()=>{state.page=0;render();});
  $('last-page').addEventListener('click',()=>{state.page=Math.max(0,Math.ceil(filtered.length/pageSize)-1);render();});
  $('jump-page').addEventListener('change',()=>{const v=Number($('jump-page').value);if(Number.isInteger(v)&&v>0){state.page=v-1;render();}});
  $('previous').addEventListener('click',()=>{state.page--;render();});$('next').addEventListener('click',()=>{state.page++;render();});
  $('close-detail').addEventListener('click',()=>$('detail').close());
  $('download-json').addEventListener('click',()=>download('sekscan-results.json','application/json',JSON.stringify(report,null,2)));
  $('export-csv').addEventListener('click',()=>{const content=[columns.map(c=>csvCell(c[1])).join(',')].concat(filtered.map(r=>columns.map(([key])=>csvCell(fieldValue(r,key))).join(','))).join('\r\n');download('sekscan-'+state.view+'.csv','text/csv;charset=utf-8',content);});
  $('load-report').addEventListener('click',()=>$('report-file').click());
  $('report-file').addEventListener('change',async event=>{const file=event.target.files[0];if(!file)return;const previous=report;const savedState={...state};const savedFilters=Object.fromEntries(controls.map(id=>[id,$(id).value]));$('import-error').hidden=true;try{if(file.size>512*1024*1024)throw new Error('Report exceeds 512 MiB');report=JSON.parse(await file.text());initialize();}catch(error){report=previous;initialize();state=savedState;controls.forEach(id=>$(id).value=savedFilters[id]||'');render();$('import-error').textContent='Cannot open report: '+String(error.message).slice(0,240)+'. The previous report is still displayed.';$('import-error').hidden=false;}event.target.value='';});
  window.addEventListener('hashchange',()=>{const view=location.hash.slice(1);if(labels[view]&&view!==state.view)selectView(view);});
  initialize();
})();
