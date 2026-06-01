
(function(){
  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
  const app = $('#app');
  const fileLoader = $('#fileLoader');

  let state = {
    raw: null,
    datasets: [],
    activeDatasetName: 'Synthetic Federal GitLab Security Payload',
    route: '#/dashboard',
    theme: localStorage.getItem('seip-theme') || 'dark',
    sidebarCollapsed: localStorage.getItem('seip-sidebar') === 'true',
    filters: { q:'', severity:'all', status:'all', scope:'all', prod:'all' },
    pagination: {},
    panelCollapsed: {}
  };

  document.documentElement.setAttribute('data-theme', state.theme);
  document.body.classList.toggle('sidebar-collapsed', state.sidebarCollapsed);

  function esc(v){ return String(v ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
  function fmt(n){ return Number(n||0).toLocaleString(); }
  function truthy(v){ return String(v).toUpperCase()==='TRUE' || v===true; }
  function sevClass(sev){ return 'sev-' + String(sev || 'unknown').toLowerCase(); }
  function statusBadge(s){
    const x=String(s||'UNKNOWN');
    const cls = x.includes('RESOLVED')?'good': x.includes('DISMISSED')?'warn': x.includes('PRESENT')?'bad':'';
    return `<span class="badge ${cls}">${esc(x)}</span>`;
  }
  function safeUrl(url){ return /^https?:\/\//i.test(String(url||'')) ? String(url) : ''; }
  function projectArray(data=state.raw){ return Object.values((data && data.projects) || {}); }
  function allVulns(data=state.raw){
    return projectArray(data).flatMap(p => (p.vulnerabilities||[]).map(v => ({...v, project:p})));
  }
  function normalizePayload(payload){
    const p = payload || {};
    p.summary_totals = p.summary_totals || {};
    p.summary_totals.statuses = p.summary_totals.statuses || {};
    p.projects = p.projects || {};
    return p;
  }
  async function loadDefault(){
    try {
      const res = await fetch('data/dashboard_payload.json');
      state.raw = normalizePayload(await res.json());
      state.datasets = [{name: state.activeDatasetName, loadedAt: new Date().toISOString(), payload: state.raw}];
    } catch(e) {
      state.raw = normalizePayload({generated_at:new Date().toISOString(), summary_totals:{statuses:{}}, projects:{}});
    }
    render();
  }

  function buildShell(content, title='Executive Dashboard', subtitle='Purpose-built portfolio overview. No fake monthly trend unless multiple snapshots are loaded.'){
    const navs = [
      ['dashboard','Dashboard','▦'],['projects','Projects','▣'],['groups','Groups','◎'],['vulnerabilities','Vulnerabilities','◇'],
      ['poam','POA&M','▤'],['aor','AOR','◫'],['deltas','Deltas','⇄'],['reports','Reports','▥'],['settings','Settings','⚙']
    ];
    const current = getRoute().name;
    return `<div class="app">
      <aside class="sidebar">
        <div class="brand">
          <div class="logo">SE</div>
          <div class="brand-text"><h1>Security Engineering</h1><p>Intelligence Platform</p></div>
        </div>
        <button class="btn ghost" id="collapseBtn">${state.sidebarCollapsed?'☰':'☰ Collapse'}</button>
        <nav class="nav">
          ${navs.map(([r,l,i])=>`<a class="${current===r?'active':''}" href="#/${r}" title="${l}"><span class="icon">${i}</span><span class="nav-label">${l}</span></a>`).join('')}
        </nav>
        <div class="sidebar-meta">
          <strong>Active:</strong> ${esc(state.activeDatasetName)}<br/>
          <strong>Datasets:</strong> ${state.datasets.length}<br/>
          <button class="btn" id="themeBtn" style="margin-top:10px">Switch ${state.theme==='dark'?'Light':'Dark'}</button>
        </div>
      </aside>
      <main class="main">
        ${breadcrumbs()}
        <div class="topbar">
          <div class="title"><h2>${esc(title)}</h2><p>${esc(subtitle)}</p></div>
          <div class="actions">
            <button class="btn primary" id="loadBtn">Load JSON</button>
            <button class="btn" id="saveBtn">Save Local</button>
            <button class="btn" id="exportBtn">Export Dataset</button>
          </div>
        </div>
        ${filterPanel()}
        ${content}
      </main>
    </div>`;
  }

  function getRoute(){
    const hash = location.hash || '#/dashboard';
    const parts = hash.replace(/^#\/?/,'').split('/').filter(Boolean);
    return { name: parts[0] || 'dashboard', id: decodeURIComponent(parts[1] || ''), parts };
  }
  function breadcrumbs(){
    const r = getRoute();
    let crumbs = [`<a href="#/dashboard">Dashboard</a>`];
    if(r.name && r.name !== 'dashboard') crumbs.push(`<a href="#/${r.name}">${labelRoute(r.name)}</a>`);
    if(r.id) crumbs.push(`<span>${esc(r.id)}</span>`);
    return `<div class="breadcrumbs">${crumbs.join('<span>/</span>')}</div>`;
  }
  function labelRoute(r){ return ({poam:'POA&M',aor:'AOR',dashboard:'Dashboard',projects:'Projects',groups:'Groups',vulnerabilities:'Vulnerabilities',project:'Project',group:'Group',vulnerability:'Vulnerability',deltas:'Deltas',reports:'Reports',settings:'Settings'}[r]||r); }

  function filterPanel(){
    return `<section class="card filters">
      <div class="panel-toggle" data-panel="filters"><strong>Global Search & Filters</strong><button class="btn ghost" type="button">Toggle</button></div>
      <div class="panel-body" style="${state.panelCollapsed.filters?'display:none':''}">
        <div class="filter-row" style="margin-top:14px">
          <input class="input" id="globalSearch" value="${esc(state.filters.q)}" placeholder="Search projects, CVEs, namespaces, ATO, stack, owners..." />
          <select id="severityFilter">
            ${['all','critical','high','medium','low','unknown'].map(x=>`<option value="${x}" ${state.filters.severity===x?'selected':''}>${x==='all'?'All severities':x}</option>`).join('')}
          </select>
          <select id="statusFilter">
            ${['all','PRESENT_STILL_EXISTS','RESOLVED','DISMISSED_ACCEPTED_RISK'].map(x=>`<option value="${x}" ${state.filters.status===x?'selected':''}>${x==='all'?'All statuses':x}</option>`).join('')}
          </select>
          <select id="scopeFilter">
            ${['all','in','out'].map(x=>`<option value="${x}" ${state.filters.scope===x?'selected':''}>${x==='all'?'All scope':x==='in'?'In scope':'Out of scope'}</option>`).join('')}
          </select>
          <select id="prodFilter">
            ${['all','prod','nonprod'].map(x=>`<option value="${x}" ${state.filters.prod===x?'selected':''}>${x==='all'?'All prod flags':x==='prod'?'Prod':'Non-prod'}</option>`).join('')}
          </select>
        </div>
      </div>
    </section>`;
  }

  function applyFiltersProjects(projects){
    const f=state.filters; const q=f.q.trim().toLowerCase();
    return projects.filter(p=>{
      const hay = [p.project_id,p.project_path,p.project_name,p.namespace,p.parent_group,p.inferred_system_name,p.program_area,p.ato_status,p.tech_stack,p.owner,p.policy_tags].join(' ').toLowerCase();
      if(q && !hay.includes(q) && !(p.vulnerabilities||[]).some(v=>[v.cve,v.vulnerability_id,v.package,v.policy_justification_notes].join(' ').toLowerCase().includes(q))) return false;
      if(f.scope==='in' && !truthy(p.in_scope)) return false;
      if(f.scope==='out' && truthy(p.in_scope)) return false;
      if(f.prod==='prod' && !truthy(p.is_prod)) return false;
      if(f.prod==='nonprod' && truthy(p.is_prod)) return false;
      if(f.severity!=='all' && !(p.vulnerabilities||[]).some(v=>String(v.severity).toLowerCase()===f.severity)) return false;
      if(f.status!=='all' && !(p.vulnerabilities||[]).some(v=>String(v.reconciliation_status)===f.status)) return false;
      return true;
    });
  }
  function applyFiltersVulns(rows){
    const f=state.filters; const q=f.q.trim().toLowerCase();
    return rows.filter(r=>{
      const p=r.project||{};
      const hay=[r.cve,r.vulnerability_id,r.severity,r.reconciliation_status,r.package,r.policy_justification_notes,p.project_path,p.parent_group,p.owner,p.ato_status,p.tech_stack].join(' ').toLowerCase();
      if(q && !hay.includes(q)) return false;
      if(f.severity!=='all' && String(r.severity).toLowerCase()!==f.severity) return false;
      if(f.status!=='all' && String(r.reconciliation_status)!==f.status) return false;
      if(f.scope==='in' && !truthy(p.in_scope)) return false;
      if(f.scope==='out' && truthy(p.in_scope)) return false;
      if(f.prod==='prod' && !truthy(p.is_prod)) return false;
      if(f.prod==='nonprod' && truthy(p.is_prod)) return false;
      return true;
    });
  }
  function riskScore(p){
    const weights={critical:20,high:12,medium:5,low:1,unknown:2};
    const vulns=p.vulnerabilities||[];
    let score = vulns.reduce((a,v)=>a+(weights[String(v.severity).toLowerCase()]||1)*(v.reconciliation_status==='PRESENT_STILL_EXISTS'?1:0.25),0);
    if(truthy(p.is_prod)) score*=1.4;
    if(!truthy(p.in_scope)) score*=0.35;
    return Math.round(score);
  }

  function renderDashboard(){
    const data=state.raw, totals=data.summary_totals||{}, statuses=totals.statuses||{};
    const projects=applyFiltersProjects(projectArray());
    const vulns=applyFiltersVulns(allVulns());
    const parentGroups = groupBy(projects, p=>p.parent_group || 'UNKNOWN');
    const severity = countBy(vulns, v=>String(v.severity||'unknown').toLowerCase());
    const content = `
      <section class="grid kpi-grid">
        ${kpi('Accessible Projects', totals.total_accessible_projects || projects.length, 'GitLab API reachability')}
        ${kpi('Scanned Projects', totals.total_scanned_projects || totals.total_projects_scanned || projects.length, 'Repository inventory baseline')}
        ${kpi('In Scope', totals.in_scope_count ?? projects.filter(p=>truthy(p.in_scope)).length, 'Governance included projects')}
        ${kpi('Out of Scope', totals.out_of_scope_count ?? projects.filter(p=>!truthy(p.in_scope)).length, 'Excluded or exempt projects')}
        ${kpi('Total Vulns', totals.total_vulnerabilities ?? allVulns().length, 'Snapshot reconciled count')}
        ${kpi('Security Health', securityHealth(vulns), 'Derived from active findings')}
      </section>
      <section class="grid two-col" style="margin-top:16px">
        <div class="card pad">
          <h3>Vulnerability Lifecycle</h3><p class="sub">Actual reconciled states from dataset</p>
          ${stackBar(statuses)}
        </div>
        <div class="card pad">
          <h3>Severity Distribution</h3><p class="sub">Click severity to open filtered vulnerability table</p>
          ${severityRows(severity)}
        </div>
      </section>
      <section class="grid two-col" style="margin-top:16px">
        <div class="card pad">
          <h3>Parent Group Risk Heatmap</h3><p class="sub">Click group to drill down</p>
          ${parentHeatmap(parentGroups)}
        </div>
        <div class="card pad">
          <h3>Top Risk Projects</h3><p class="sub">Click project to open detail page</p>
          ${topRisk(projects)}
        </div>
      </section>
      <section class="grid two-col" style="margin-top:16px">
        <div class="card pad">
          <h3>ATO / Registry Status</h3><p class="sub">Project governance readiness</p>
          ${miniBars(countBy(projects, p=>p.ato_status||'UNKNOWN'), 'ato')}
        </div>
        <div class="card pad">
          <h3>Tech Stack Intelligence</h3><p class="sub">Detected platform concentration</p>
          ${miniBars(countBy(projects, p=>p.tech_stack||'UNKNOWN'), 'stack')}
        </div>
      </section>
    `;
    return buildShell(content);
  }
  function kpi(label,value,desc){ return `<div class="card kpi"><div class="label">${esc(label)}</div><div class="value">${fmt(value)}</div><div class="desc">${esc(desc)}</div></div>`; }
  function securityHealth(vulns){
    const active=vulns.filter(v=>v.reconciliation_status==='PRESENT_STILL_EXISTS');
    const crit=active.filter(v=>String(v.severity).toLowerCase()==='critical').length;
    const high=active.filter(v=>String(v.severity).toLowerCase()==='high').length;
    return Math.max(0, 100-Math.min(100, crit*4+high*1.4+active.length*.02)).toFixed(0);
  }
  function stackBar(counts){
    const entries=Object.entries(counts||{}).filter(([,v])=>Number(v)>0);
    const total=entries.reduce((a,[,v])=>a+Number(v),0)||1;
    const colors={PRESENT_STILL_EXISTS:'var(--bad)',RESOLVED:'var(--good)',NOT_APPLICABLE_OUT_OF_SCOPE:'var(--unknown)',DISMISSED_ACCEPTED_RISK:'var(--accent2)'};
    return `<div class="stackbar">${entries.map(([k,v])=>`<div class="seg" style="width:${Number(v)/total*100}%;background:${colors[k]||'var(--accent)'}"></div>`).join('')}</div>
      <div class="legend">${entries.map(([k,v])=>`<span><i class="dot" style="background:${colors[k]||'var(--accent)'}"></i>${esc(k)}: ${fmt(v)}</span>`).join('')}</div>`;
  }
  function severityRows(severity){
    const max=Math.max(...Object.values(severity),1);
    return ['critical','high','medium','low','unknown'].map(s=>{
      const v=severity[s]||0;
      return `<div class="progress-row" data-severity-route="${s}">
        <strong class="${sevClass(s)}">${s}</strong><div class="progress"><i style="width:${v/max*100}%"></i></div><strong>${fmt(v)}</strong>
      </div>`;
    }).join('');
  }
  function parentHeatmap(groups){
    const rows=Object.entries(groups).map(([g,ps])=>({g,ps,score:ps.reduce((a,p)=>a+riskScore(p),0),prod:ps.filter(p=>truthy(p.is_prod)).length})).sort((a,b)=>b.score-a.score).slice(0,8);
    const max=Math.max(...rows.map(r=>r.score),1);
    return rows.map(r=>`<div class="progress-row" data-group-route="${esc(r.g)}">
      <div><strong>${esc(shorten(r.g,48))}</strong><br><span class="sub">${r.ps.length} projects • ${r.prod} prod</span></div>
      <div class="progress"><i style="width:${r.score/max*100}%"></i></div><strong>${fmt(r.score)}</strong>
    </div>`).join('') || `<div class="empty">No group data loaded.</div>`;
  }
  function topRisk(projects){
    return projects.map(p=>({p,score:riskScore(p)})).sort((a,b)=>b.score-a.score).slice(0,8).map(({p,score})=>`
      <div class="progress-row" data-project-route="${esc(p.project_id)}">
        <div><strong>${esc(p.project_name)}</strong><br><span class="sub">${esc(shorten(p.project_path,55))}</span></div>
        <div class="progress"><i style="width:${Math.min(100,score/6)}%"></i></div><strong>${fmt(score)}</strong>
      </div>`).join('') || `<div class="empty">No projects loaded.</div>`;
  }
  function miniBars(counts,type){
    const entries=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,8); const max=Math.max(...entries.map(e=>e[1]),1);
    return entries.map(([k,v])=>`<div class="progress-row">
      <strong>${esc(shorten(k,40))}</strong><div class="progress"><i style="width:${v/max*100}%"></i></div><strong>${fmt(v)}</strong>
    </div>`).join('');
  }

  function renderProjects(){
    const rows = applyFiltersProjects(projectArray()).map(p=>({...p,risk:riskScore(p), vulnCount:(p.vulnerabilities||[]).length}));
    return buildShell(tableCard('Projects', rows, [
      ['Project', p=>`<a href="#/project/${encodeURIComponent(p.project_id)}">${esc(p.project_name)}</a><br><span class="sub">${esc(p.project_path)}</span>`],
      ['Parent Group', p=>`<a href="#/group/${encodeURIComponent(p.parent_group)}">${esc(shorten(p.parent_group,55))}</a>`],
      ['Owner', p=>esc(p.owner)],
      ['ATO', p=>esc(p.ato_status)],
      ['Prod', p=>truthy(p.is_prod)?'<span class="badge bad">TRUE</span>':'<span class="badge">FALSE</span>'],
      ['Scope', p=>truthy(p.in_scope)?'<span class="badge good">IN</span>':'<span class="badge warn">OUT</span>'],
      ['Vulns', p=>fmt(p.vulnCount)],
      ['Risk', p=>fmt(p.risk)]
    ], 'projects'), 'Projects', 'Inventory mapped from the canonical projects object.');
  }

  function renderVulnerabilities(){
    const rows = applyFiltersVulns(allVulns());
    return buildShell(tableCard('Vulnerabilities', rows, [
      ['CVE', r=>`<a href="#/vulnerability/${encodeURIComponent(r.vulnerability_id)}">${esc(r.cve)}</a>`],
      ['Severity', r=>`<span class="${sevClass(r.severity)}">${esc(r.severity)}</span>`],
      ['Status', r=>statusBadge(r.reconciliation_status)],
      ['Project', r=>`<a href="#/project/${encodeURIComponent(r.project.project_id)}">${esc(r.project.project_name)}</a>`],
      ['Parent Group', r=>`<a href="#/group/${encodeURIComponent(r.project.parent_group)}">${esc(shorten(r.project.parent_group,45))}</a>`],
      ['Package', r=>esc(r.package||'') ],
      ['Verified', r=>esc((r.verified_at||'').slice(0,10))],
      ['Evidence', r=>safeUrl(r.evidence_location_url)?`<a target="_blank" rel="noopener" href="${esc(r.evidence_location_url)}">Evidence ↗</a>`:'']
    ], 'vulns'), 'Vulnerabilities', 'Filtered vulnerability workbench with evidence links.');
  }

  function renderGroups(){
    const groups = Object.entries(groupBy(applyFiltersProjects(projectArray()), p=>p.parent_group || 'UNKNOWN')).map(([group,projects])=>({
      group, projects, projectCount:projects.length, prod:projects.filter(p=>truthy(p.is_prod)).length, vulns:projects.reduce((a,p)=>a+(p.vulnerabilities||[]).length,0), risk:projects.reduce((a,p)=>a+riskScore(p),0)
    })).sort((a,b)=>b.risk-a.risk);
    return buildShell(tableCard('Groups', groups, [
      ['Parent Group', r=>`<a href="#/group/${encodeURIComponent(r.group)}">${esc(r.group)}</a>`],
      ['Projects', r=>fmt(r.projectCount)],
      ['Prod', r=>fmt(r.prod)],
      ['Vulnerabilities', r=>fmt(r.vulns)],
      ['Risk', r=>fmt(r.risk)]
    ], 'groups'), 'Groups', 'Parent group rollup and namespace risk drilldown.');
  }

  function renderProject(id){
    const p = state.raw.projects[id] || projectArray().find(x=>x.project_id===id);
    if(!p) return buildShell(`<div class="empty">Project not found: ${esc(id)}</div>`, 'Project Not Found','');
    const vulns=(p.vulnerabilities||[]).map(v=>({...v,project:p}));
    const detail = `<section class="grid detail-grid">
      ${kpi('Project ID',p.project_id,'Canonical project key')}
      ${kpi('Parent Group',shorten(p.parent_group,28),'Namespace family')}
      ${kpi('ATO',p.ato_status,'Registry status')}
      ${kpi('Prod',p.is_prod,'Production flag')}
      ${kpi('In Scope',p.in_scope,'Governance scope')}
      ${kpi('Tech Stack',p.tech_stack,'Detected stack')}
      ${kpi('Risk Score',riskScore(p),'Weighted active exposure')}
      ${kpi('Owner',p.owner,'AOR / registry owner')}
    </section>
    <div class="actions-row">
      ${safeUrl(p.gitlab_url)?`<a class="btn" target="_blank" rel="noopener" href="${esc(p.gitlab_url)}">Open GitLab</a>`:''}
      ${safeUrl(p.pipeline_url)?`<a class="btn" target="_blank" rel="noopener" href="${esc(p.pipeline_url)}">Pipelines</a>`:''}
      ${safeUrl(p.container_registry_url)?`<a class="btn" target="_blank" rel="noopener" href="${esc(p.container_registry_url)}">Registry</a>`:''}
    </div>
    ${tableCard('Project Vulnerabilities', vulns, [
      ['CVE', r=>`<a href="#/vulnerability/${encodeURIComponent(r.vulnerability_id)}">${esc(r.cve)}</a>`],
      ['Severity', r=>`<span class="${sevClass(r.severity)}">${esc(r.severity)}</span>`],
      ['Status', r=>statusBadge(r.reconciliation_status)],
      ['Package', r=>esc(r.package||'')],
      ['Notes', r=>esc(r.policy_justification_notes)],
      ['Evidence', r=>safeUrl(r.evidence_location_url)?`<a target="_blank" rel="noopener" href="${esc(r.evidence_location_url)}">Evidence ↗</a>`:'']
    ], 'project-'+id)}`;
    return buildShell(detail, p.project_name, p.project_path);
  }

  function renderGroup(id){
    const group=decodeURIComponent(id);
    const projects=applyFiltersProjects(projectArray().filter(p=>p.parent_group===group || p.namespace===group || String(p.parent_group||'').startsWith(group)));
    return buildShell(tableCard('Group Projects', projects.map(p=>({...p,risk:riskScore(p), vulnCount:(p.vulnerabilities||[]).length})), [
      ['Project', p=>`<a href="#/project/${encodeURIComponent(p.project_id)}">${esc(p.project_name)}</a><br><span class="sub">${esc(p.project_path)}</span>`],
      ['System', p=>esc(p.inferred_system_name)],
      ['ATO', p=>esc(p.ato_status)],
      ['Prod', p=>esc(p.is_prod)],
      ['Vulns', p=>fmt(p.vulnCount)],
      ['Risk', p=>fmt(p.risk)]
    ], 'group-'+group), 'Group Drilldown', group);
  }

  function renderVulnerability(id){
    const row=allVulns().find(v=>String(v.vulnerability_id)===String(id));
    if(!row) return buildShell(`<div class="empty">Vulnerability not found: ${esc(id)}</div>`, 'Vulnerability Not Found','');
    const p=row.project;
    const content=`<section class="grid detail-grid">
      ${kpi('Vulnerability ID',row.vulnerability_id,'GitLab security record')}
      ${kpi('CVE',row.cve,'Identifier')}
      ${kpi('Severity',row.severity,'Scanner severity')}
      ${kpi('Status',row.reconciliation_status,'Reconciliation state')}
      ${kpi('Project',p.project_name,'Affected repository')}
      ${kpi('Package',row.package||'Unknown','Affected component')}
      ${kpi('Verified',String(row.verified_at||'').slice(0,10),'Validation timestamp')}
      ${kpi('Digest',shorten(row.slsa_provenance_digest,18),'Provenance')}
    </section>
    <section class="card pad" style="margin-top:16px">
      <h3>Evidence & Justification</h3>
      <p>${esc(row.policy_justification_notes)}</p>
      <div class="actions-row">
        <a class="btn" href="#/project/${encodeURIComponent(p.project_id)}">Open Project</a>
        ${safeUrl(row.evidence_location_url)?`<a class="btn primary" target="_blank" rel="noopener" href="${esc(row.evidence_location_url)}">Open Evidence ↗</a>`:''}
      </div>
    </section>`;
    return buildShell(content,'Vulnerability Detail',`${row.cve} • ${p.project_name}`);
  }

  function renderPoam(){
    const rows=applyFiltersVulns(allVulns()).filter(v=>v.reconciliation_status==='PRESENT_STILL_EXISTS').map(v=>({
      ...v, weakness:v.cve, owner:v.project.owner, target: targetDate(v.severity), mitigation: remediation(v)
    }));
    return buildShell(`<div class="actions-row"><button class="btn primary" data-export-poam>Export POA&M CSV</button></div>` + tableCard('POA&M Candidates', rows, [
      ['Weakness', r=>esc(r.weakness)], ['Severity', r=>`<span class="${sevClass(r.severity)}">${esc(r.severity)}</span>`],
      ['Project', r=>`<a href="#/project/${encodeURIComponent(r.project.project_id)}">${esc(r.project.project_name)}</a>`],
      ['Owner', r=>esc(r.owner)], ['Target Date', r=>esc(r.target)], ['Mitigation', r=>esc(r.mitigation)]
    ], 'poam'), 'POA&M Manager', 'Generate remediation queue from active findings.');
  }
  function renderAor(){
    const rows=Object.entries(groupBy(projectArray(), p=>p.owner||'Unassigned')).map(([owner,ps])=>({owner, projects:ps.length, prod:ps.filter(p=>truthy(p.is_prod)).length, vulns:ps.reduce((a,p)=>a+(p.vulnerabilities||[]).length,0), risk:ps.reduce((a,p)=>a+riskScore(p),0)})).sort((a,b)=>b.risk-a.risk);
    return buildShell(tableCard('Area of Responsibility', rows, [
      ['Owner / AOR', r=>esc(r.owner)], ['Projects', r=>fmt(r.projects)], ['Prod', r=>fmt(r.prod)], ['Vulnerabilities', r=>fmt(r.vulns)], ['Risk', r=>fmt(r.risk)]
    ], 'aor'), 'AOR', 'Ownership and responsibility rollups.');
  }
  function renderDeltas(){
    let content = `<div class="card pad"><h3>Snapshot Comparison</h3><p class="sub">Load multiple JSON files using Load JSON to compare project and vulnerability deltas.</p>`;
    if(state.datasets.length<2) content += `<div class="empty">No historical datasets loaded yet.</div>`;
    else {
      const a=state.datasets[state.datasets.length-2].payload, b=state.datasets[state.datasets.length-1].payload;
      const av=new Set(allVulns(a).map(v=>v.vulnerability_id)); const bv=new Set(allVulns(b).map(v=>v.vulnerability_id));
      content += `<section class="grid kpi-grid">${kpi('Previous',state.datasets[state.datasets.length-2].name,'Baseline')}${kpi('Current',state.datasets[state.datasets.length-1].name,'Compared')}${kpi('New Findings',[...bv].filter(x=>!av.has(x)).length,'Appeared')}${kpi('Resolved/Removed',[...av].filter(x=>!bv.has(x)).length,'Dropped off')}${kpi('Current Vulns',bv.size,'Active snapshot')}${kpi('Previous Vulns',av.size,'Prior snapshot')}</section>`;
    }
    content += `</div>`;
    return buildShell(content,'Delta Analysis','Compare loaded JSON snapshots.');
  }
  function renderReports(){
    return buildShell(`<section class="grid two-col">
      <div class="card pad"><h3>Executive Brief</h3><p class="sub">Portfolio risk summary for leadership.</p><button class="btn primary" data-report="exec">Generate Markdown</button></div>
      <div class="card pad"><h3>Security Engineer Report</h3><p class="sub">Technical vulnerability and evidence report.</p><button class="btn primary" data-report="engineer">Generate Markdown</button></div>
      <div class="card pad"><h3>POA&M Export</h3><p class="sub">CSV queue for remediation tracking.</p><button class="btn primary" data-export-poam>Export POA&M CSV</button></div>
      <div class="card pad"><h3>AOR Export</h3><p class="sub">Ownership and project responsibility report.</p><button class="btn primary" data-report="aor">Generate CSV</button></div>
    </section>`, 'Reports', 'Generate leadership, AOR, and POA&M artifacts.');
  }
  function renderSettings(){
    return buildShell(`<section class="card pad"><h3>Settings</h3><p class="sub">Local-only settings persist in browser storage.</p>
      <div class="actions-row"><button class="btn" id="themeBtn2">Switch ${state.theme==='dark'?'Light':'Dark'}</button><button class="btn" id="resetFilters">Reset Filters</button><button class="btn" id="clearLocal">Clear Local Storage</button></div>
      <pre>${esc(JSON.stringify({theme:state.theme, filters:state.filters, datasets:state.datasets.map(d=>({name:d.name, loadedAt:d.loadedAt}))}, null, 2))}</pre>
    </section>`, 'Settings', 'Configure local workspace behavior.');
  }

  function tableCard(title, rows, cols, key){
    const pageSizeKey=key+'-size', pageKey=key+'-page';
    const size=state.pagination[pageSizeKey] || 25;
    const page=state.pagination[pageKey] || 1;
    const total=rows.length, pages=Math.max(1, Math.ceil(total/size));
    const current=Math.min(page,pages);
    const slice=rows.slice((current-1)*size, current*size);
    return `<section class="card table-card">
      <div class="table-head"><strong>${esc(title)}</strong><div><span class="sub">${fmt(total)} records</span> <select data-page-size="${key}">${[10,25,50,100,250].map(n=>`<option ${size===n?'selected':''}>${n}</option>`).join('')}</select></div></div>
      <div class="table-wrap"><table><thead><tr>${cols.map(([h])=>`<th>${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>${slice.map(row=>`<tr>${cols.map(([,fn])=>`<td>${fn(row)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>
      <div class="pagination"><button class="btn" data-page-prev="${key}" ${current<=1?'disabled':''}>Previous</button><span>Page ${current} of ${pages}</span><button class="btn" data-page-next="${key}" ${current>=pages?'disabled':''}>Next</button></div>
    </section>`;
  }

  function groupBy(arr, fn){ return arr.reduce((a,x)=>{ const k=fn(x); (a[k]=a[k]||[]).push(x); return a; },{}); }
  function countBy(arr, fn){ return arr.reduce((a,x)=>{ const k=fn(x); a[k]=(a[k]||0)+1; return a; },{}); }
  function shorten(s,n=40){ s=String(s??''); return s.length>n?s.slice(0,n-1)+'…':s; }
  function targetDate(sev){ const d=new Date(); const days={critical:15,high:30,medium:90,low:180,unknown:120}[String(sev).toLowerCase()]||90; d.setDate(d.getDate()+days); return d.toISOString().slice(0,10); }
  function remediation(v){ return `Validate ${v.package||'affected component'} version, patch base image/application dependency, rerun scan, and attach evidence.`; }

  function render(){
    const r=getRoute(); state.route=location.hash||'#/dashboard';
    let html;
    if(r.name==='projects') html=renderProjects();
    else if(r.name==='groups') html=renderGroups();
    else if(r.name==='group') html=renderGroup(r.id);
    else if(r.name==='project') html=renderProject(r.id);
    else if(r.name==='vulnerabilities') html=renderVulnerabilities();
    else if(r.name==='vulnerability') html=renderVulnerability(r.id);
    else if(r.name==='poam') html=renderPoam();
    else if(r.name==='aor') html=renderAor();
    else if(r.name==='deltas') html=renderDeltas();
    else if(r.name==='reports') html=renderReports();
    else if(r.name==='settings') html=renderSettings();
    else html=renderDashboard();
    app.innerHTML=html;
    bind();
  }

  let searchTimer;
  function bind(){
    $('#collapseBtn')?.addEventListener('click',()=>{ state.sidebarCollapsed=!state.sidebarCollapsed; localStorage.setItem('seip-sidebar',state.sidebarCollapsed); document.body.classList.toggle('sidebar-collapsed', state.sidebarCollapsed); render(); });
    $('#themeBtn')?.addEventListener('click',toggleTheme); $('#themeBtn2')?.addEventListener('click',toggleTheme);
    $('#loadBtn')?.addEventListener('click',()=>fileLoader.click());
    $('#saveBtn')?.addEventListener('click',()=>{ localStorage.setItem('seip-last-dataset', JSON.stringify(state.raw)); alert('Dataset saved to browser local storage.'); });
    $('#exportBtn')?.addEventListener('click',()=>download('security-engineering-dataset.json', JSON.stringify(state.raw,null,2), 'application/json'));
    $('#globalSearch')?.addEventListener('input',e=>{ state.filters.q=e.target.value; clearTimeout(searchTimer); searchTimer=setTimeout(()=>{ resetPages(); render(); },250); });
    $('#globalSearch')?.addEventListener('keydown',e=>{ if(e.key==='Enter'){ clearTimeout(searchTimer); resetPages(); render(); }});
    [['severityFilter','severity'],['statusFilter','status'],['scopeFilter','scope'],['prodFilter','prod']].forEach(([id,key])=>$( '#'+id)?.addEventListener('change',e=>{state.filters[key]=e.target.value; resetPages(); render();}));
    $$('[data-severity-route]').forEach(el=>el.addEventListener('click',()=>{ state.filters.severity=el.dataset.severityRoute; location.hash='#/vulnerabilities'; }));
    $$('[data-group-route]').forEach(el=>el.addEventListener('click',()=>{ location.hash='#/group/'+encodeURIComponent(el.dataset.groupRoute); }));
    $$('[data-project-route]').forEach(el=>el.addEventListener('click',()=>{ location.hash='#/project/'+encodeURIComponent(el.dataset.projectRoute); }));
    $$('[data-page-size]').forEach(el=>el.addEventListener('change',()=>{ state.pagination[el.dataset.pageSize+'-size']=Number(el.value); state.pagination[el.dataset.pageSize+'-page']=1; render(); }));
    $$('[data-page-prev]').forEach(el=>el.addEventListener('click',()=>{ const k=el.dataset.pagePrev+'-page'; state.pagination[k]=Math.max(1,(state.pagination[k]||1)-1); render(); }));
    $$('[data-page-next]').forEach(el=>el.addEventListener('click',()=>{ const k=el.dataset.pageNext+'-page'; state.pagination[k]=(state.pagination[k]||1)+1; render(); }));
    $$('[data-panel]').forEach(el=>el.addEventListener('click',e=>{ if(e.target.tagName==='INPUT' || e.target.tagName==='SELECT') return; const k=el.dataset.panel; state.panelCollapsed[k]=!state.panelCollapsed[k]; render(); }));
    $$('[data-export-poam]').forEach(el=>el.addEventListener('click',exportPoam));
    $('#resetFilters')?.addEventListener('click',()=>{ state.filters={q:'',severity:'all',status:'all',scope:'all',prod:'all'}; resetPages(); render(); });
    $('#clearLocal')?.addEventListener('click',()=>{ localStorage.clear(); alert('Local storage cleared.'); });
    $$('[data-report]').forEach(el=>el.addEventListener('click',()=>generateReport(el.dataset.report)));
  }
  function resetPages(){ state.pagination={}; }
  function toggleTheme(){ state.theme=state.theme==='dark'?'light':'dark'; localStorage.setItem('seip-theme',state.theme); document.documentElement.setAttribute('data-theme', state.theme); render(); }
  function download(name, text, type='text/plain'){ const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([text],{type})); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),1000); }
  function exportPoam(){
    const rows=applyFiltersVulns(allVulns()).filter(v=>v.reconciliation_status==='PRESENT_STILL_EXISTS');
    const headers=['vulnerability_id','cve','severity','project_id','project_name','parent_group','owner','target_date','mitigation','evidence_location_url'];
    const csv=[headers.join(',')].concat(rows.map(v=>headers.map(h=>{
      const val = h==='project_id'?v.project.project_id:h==='project_name'?v.project.project_name:h==='parent_group'?v.project.parent_group:h==='owner'?v.project.owner:h==='target_date'?targetDate(v.severity):h==='mitigation'?remediation(v):v[h];
      return `"${String(val??'').replace(/"/g,'""')}"`;
    }).join(','))).join('\n');
    download('poam_candidates.csv', csv, 'text/csv');
  }
  function generateReport(type){
    const totals=state.raw.summary_totals||{};
    const md=`# Security Engineering ${type.toUpperCase()} Report\n\nGenerated: ${new Date().toISOString()}\n\n- Total scanned projects: ${totals.total_scanned_projects||totals.total_projects_scanned||projectArray().length}\n- In scope: ${totals.in_scope_count||0}\n- Total vulnerabilities: ${totals.total_vulnerabilities||allVulns().length}\n- Active findings: ${(totals.statuses||{}).PRESENT_STILL_EXISTS||0}\n`;
    download(`security_${type}_report.md`, md, 'text/markdown');
  }
  fileLoader.addEventListener('change', async e=>{
    const files=Array.from(e.target.files||[]);
    for(const file of files){
      const payload=normalizePayload(JSON.parse(await file.text()));
      state.raw=payload; state.activeDatasetName=file.name; state.datasets.push({name:file.name, loadedAt:new Date().toISOString(), payload});
    }
    resetPages(); render(); fileLoader.value='';
  });
  window.addEventListener('hashchange', render);
  document.addEventListener('keydown', e=>{
    const editable = ['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
    if(e.key==='Backspace' && !editable) e.preventDefault();
  });
  loadDefault();
})();
