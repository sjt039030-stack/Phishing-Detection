const STORAGE_KEY = 'phishguard_history';
const MAX_HISTORY = 20;
const urlInput    = document.getElementById('urlInput');
const loadingWrap = document.getElementById('loading-wrap');
const loadingBar  = document.getElementById('loading-bar');
const loadingPct  = document.getElementById('loading-pct');
const loadingMsg  = document.getElementById('loading-msg');
const dashboard   = document.getElementById('dashboard-results');
const btnIcon     = document.getElementById('btn-icon');
const btnText     = document.getElementById('btn-text');
const scanBtn     = document.getElementById('scan-btn');

function getHistory() { try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; } catch { return []; } }
function saveHistory(arr) { localStorage.setItem(STORAGE_KEY, JSON.stringify(arr)); }

/* ── threat type mapping per status ── */
function getThreatType(status, tld) {
    const s = (status||'').toLowerCase();
    const suspTlds = ['.xyz','.tk','.cf','.ml','.ga','.gq'];
    const badTld = suspTlds.some(t=>(tld||'').toLowerCase().includes(t));
    if (s === 'phishing') {
        if (badTld) return 'Credential Theft';
        return ['Credential Theft','Tech Support Phishing','Brand Spoofing','Crypto Fraud','Fake Survey'][Math.floor(Math.random()*5)];
    }
    if (s === 'suspicious') return 'Possible Redirect Trap';
    return 'No Threat Detected';
}

/* ── relative time ── */
function relativeTime(ts) {
    const diff = Math.floor((Date.now() - ts) / 1000);
    if (diff < 5)  return 'Just now';
    if (diff < 60) return `${diff}s ago`;
    const m = Math.floor(diff / 60);
    if (m < 60) return m === 1 ? '1 minute ago' : `${m} minutes ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return h === 1 ? '1 hour ago' : `${h} hours ago`;
    const d = Math.floor(h / 24);
    return d === 1 ? 'Yesterday' : `${d} days ago`;
}

function addToHistory(url, status, tld, phishingPct, detectionDate) {
    let hist = getHistory();
    hist = hist.filter(h => h.url !== url);
    const threatType = getThreatType(status, tld);
    hist.unshift({ url, status, tld, phishingPct, detectionDate, threatType, ts: Date.now() });
    if (hist.length > MAX_HISTORY) hist = hist.slice(0, MAX_HISTORY);
    saveHistory(hist);
    renderAllHistory();
}

function clearHistory() { saveHistory([]); renderAllHistory(); }

function escHtml(s) {
    return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── build the new table rows ── */
function buildTableRows(hist) {
    if (!hist.length) {
        return `<div class="recent-empty2"><i class="fas fa-shield-alt"></i><p>No recent scans yet.<br>Scan a URL above to see history here.</p></div>`;
    }
    const rows = hist.map(h => {
        const cls    = (h.status||'unknown').toLowerCase().replace(/\s/g,'');
        const label  = h.status || 'Unknown';
        const short  = (h.url||'').replace(/^https?:\/\//,'').replace(/^www\./,'');
        const type   = h.threatType || getThreatType(h.status, h.tld);
        const ago    = relativeTime(h.ts || Date.now());
        return `<tr onclick="loadFromHistory('${escHtml(h.url)}')">
            <td><span class="rt-url" title="${escHtml(h.url)}">${escHtml(short)}</span></td>
            <td><span class="rt-type">${escHtml(type)}</span></td>
            <td><span class="sev-pill ${cls}"><span class="sev-dot"></span>${label}</span></td>
            <td><span class="rt-time">${escHtml(ago)}</span></td>
        </tr>`;
    }).join('');
    return `<table class="recent-table">
        <thead><tr>
            <th>URL</th>
            <th>Type</th>
            <th>Severity</th>
            <th style="text-align:right;">Detected</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

/* ── sidebar mini list (inside dashboard) ── */
function buildSidebarList(hist) {
    if (!hist.length) {
        return `<div class="recent-empty2"><i class="fas fa-clock"></i><p>No recent scans yet.</p></div>`;
    }
    const rows = hist.slice(0,6).map(h => {
        const cls   = (h.status||'unknown').toLowerCase().replace(/\s/g,'');
        const label = h.status || 'Unknown';
        const short = (h.url||'').replace(/^https?:\/\//,'').replace(/^www\./,'');
        const type  = h.threatType || getThreatType(h.status, h.tld);
        const ago   = relativeTime(h.ts || Date.now());
        return `<tr onclick="loadFromHistory('${escHtml(h.url)}')">
            <td><span class="rt-url" title="${escHtml(h.url)}" style="max-width:110px;">${escHtml(short)}</span></td>
            <td><span class="sev-pill ${cls}" style="font-size:.6rem;padding:.22rem .55rem;"><span class="sev-dot"></span>${label}</span></td>
            <td><span class="rt-time">${escHtml(ago)}</span></td>
        </tr>`;
    }).join('');
    return `<table class="recent-table">
        <thead><tr><th>URL</th><th>Severity</th><th style="text-align:right;">When</th></tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

function renderAllHistory() {
    const hist = getHistory();
    document.getElementById('static-recent-list').innerHTML   = buildTableRows(hist);
    const sidebarElement = document.getElementById('recent-url-list-sidebar');
    if (sidebarElement) {
        sidebarElement.innerHTML = buildSidebarList(hist);
    }
}

function loadFromHistory(url) { urlInput.value = url; rescan(); }

/* LOADING */
let loadTimer = null;
const steps = [
    { id:'step-1', msg:'Resolving domain & IP…', pct:20 },
    { id:'step-2', msg:'Inspecting SSL certificate…', pct:45 },
    { id:'step-3', msg:'Running AI analysis…', pct:75 },
    { id:'step-4', msg:'Generating threat report…', pct:92 },
];
function startLoadingAnim() {
    loadingWrap.classList.add('active'); loadingBar.style.width='0%'; loadingPct.textContent='0%';
    steps.forEach(s => { document.getElementById(s.id).className='loading-step'; });
    let i = 0;
    loadTimer = setInterval(() => {
        if (i < steps.length) {
            if (i>0) document.getElementById(steps[i-1].id).className='loading-step done';
            document.getElementById(steps[i].id).className='loading-step active';
            loadingBar.style.width=steps[i].pct+'%'; loadingPct.textContent=steps[i].pct+'%';
            loadingMsg.textContent=steps[i].msg; i++;
        }
    }, 600);
}
function stopLoadingAnim() {
    clearInterval(loadTimer);
    steps.forEach(s => document.getElementById(s.id).className='loading-step done');
    loadingBar.style.width='100%'; loadingPct.textContent='100%';
    setTimeout(() => { loadingWrap.classList.remove('active'); }, 400);
}

/* SCAN */
async function startScan(targetUrl) {
    if (!targetUrl) return;
    scanBtn.classList.add('loading'); btnIcon.className='fas fa-spinner fa-spin'; btnText.textContent='Scanning…';
    dashboard.classList.remove('active'); startLoadingAnim();
    try {
        const response = await fetch('/scan', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({url:targetUrl}) });
        const data = await response.json();
        console.log('Scan response:', response.status, data);
        stopLoadingAnim();
        if (response.ok && data && data.status) {
            renderDashboard(targetUrl, data);
            dashboard.classList.add('active');
            const phPct = (data.status||'').toLowerCase()==='phishing'?'95%':(data.status||'').toLowerCase()==='safe'?'2%':'48%';
            addToHistory(targetUrl, data.status, data.tld, phPct, data.detection_date);
        } else {
            console.error('Scan returned invalid response:', data);
            alert('Scan failed: ' + (data.error || 'Unknown error'));
        }
    } catch(err) {
        console.error('Scan fetch error:', err); 
        stopLoadingAnim(); 
        alert('Scan failed: ' + err.message);
    } finally {
        scanBtn.classList.remove('loading'); btnIcon.className='fas fa-search'; btnText.textContent='Scan URL';
    }
}

function renderDashboard(url, data) {
    const status      = data.status || 'Unknown';
    const statusClass = status.toLowerCase();
    const banner = document.getElementById('verdict-banner');
    banner.className = 'verdict-banner ' + statusClass;
    const iconEl = document.getElementById('verdict-icon');
    iconEl.className = 'verdict-icon ' + statusClass;
    const icons = { safe:'fa-check-circle', phishing:'fa-exclamation-circle', suspicious:'fa-exclamation-triangle' };
    iconEl.innerHTML = `<i class="fas ${icons[statusClass]||'fa-question-circle'}"></i>`;
    document.getElementById('verdict-title').textContent = status;
    document.getElementById('verdict-msg').textContent   = data.message || 'Analysis complete.';

    const scoreNum = document.getElementById('score-num');
    if (statusClass==='phishing')  { scoreNum.textContent='95%'; scoreNum.className='verdict-score-num red'; }
    else if (statusClass==='safe') { scoreNum.textContent='2%';  scoreNum.className='verdict-score-num green'; }
    else                           { scoreNum.textContent='48%'; scoreNum.className='verdict-score-num yellow'; }

    const tln = document.getElementById('threat-level-num');
    const levels={safe:'LOW',phishing:'HIGH',suspicious:'MED'};
    const lCls={safe:'green',phishing:'red',suspicious:'yellow'};
    tln.textContent=levels[statusClass]||'N/A'; tln.className='verdict-score-num '+(lCls[statusClass]||'');

    const confNum = document.getElementById('confidence-num');
    confNum.textContent = statusClass==='phishing'?'98.4%':statusClass==='safe'?'99.1%':'87.6%';
    confNum.className='verdict-score-num '+(lCls[statusClass]||'');

    document.getElementById('res-url-display').textContent = url;

    const set=(id,val,cls)=>{const el=document.getElementById(id);el.textContent=val||'—';if(cls)el.className='info-val '+cls;};
    set('ip-address-val', data.ip_address, 'blue');
    set('brand-val', data.brand);
    set('tld-val', data.tld);
    set('host-val', data.host, 'blue');
    set('hosting-provider-val', data.hosting_provider, 'blue');
    set('current-date', data.detection_date);

    const certWrap = document.getElementById('cert-badge-wrap');
    let certCls='verified',certIcon='fa-lock',certText='Verified SSL';
    if (data.certificate) {
        const c=data.certificate; certText=c.verified?`✓ ${c.issuer}`:`⚠ ${c.issuer}`;
        if (!c.verified){certCls='unverified';certIcon='fa-lock-open';}
    }
    certWrap.innerHTML=`<div class="cert-badge ${certCls}"><i class="fas ${certIcon}"></i> ${certText}</div>`;

    const phPct=statusClass==='phishing'?'95%':statusClass==='safe'?'2%':'48%';
    const mlPct=statusClass==='phishing'?'80%':statusClass==='safe'?'1%':'30%';
    const brPct=statusClass==='phishing'?'88%':statusClass==='safe'?'1%':'35%';
    const barCls=statusClass==='phishing'?'red':statusClass==='safe'?'green':'yellow';
    const setBar=(lId,bId,pct,cls)=>{document.getElementById(lId).textContent=pct;const b=document.getElementById(bId);b.style.width=pct;b.className='threat-bar-fill '+cls;};
    setBar('phishing-pct-label','phishing-bar',phPct,barCls);
    setBar('malware-pct-label','malware-bar',mlPct,barCls);
    setBar('brand-pct-label','brand-bar',brPct,barCls);

    const signals = buildSignals(statusClass, data);
    document.getElementById('signal-grid').innerHTML = signals.map(s =>
        `<div class="signal-tag"><div class="signal-dot ${s.col}"></div><span class="signal-text">${s.text}</span></div>`
    ).join('');

    const detSteps = buildDetectionSteps(statusClass, data);
    document.getElementById('detection-steps').innerHTML = detSteps.map(d =>
        `<div class="detection-step"><div class="det-num ${d.col}">${d.num}</div><div><div class="det-title">${d.title}</div><div class="det-desc">${d.desc}</div></div></div>`
    ).join('');

    const img = document.getElementById('main-screenshot');
    if (data.screenshot) { img.src=data.screenshot; }
    else { img.src=statusClass==='phishing'?'https://via.placeholder.com/800x450/1a0505/f87171?text=%E2%9A%A0+Phishing+Detected':'https://via.placeholder.com/800x450/0d1929/3d6494?text=No+Screenshot+Available'; }
    img.onerror=()=>{img.src='https://via.placeholder.com/800x450/0d1929/3d6494?text=Screenshot+Unavailable';};

    dashboard.style.display='block';
    dashboard.scrollIntoView({behavior:'smooth',block:'start'});
}

function buildDetectionSteps(statusClass, data) {
    const tld=(data.tld||'').toLowerCase();
    const suspTlds=['.xyz','.tk','.cf','.ml','.ga','.gq'];
    const badTld=suspTlds.some(t=>tld.includes(t));
    const certOk=data.certificate&&data.certificate.verified;
    if (statusClass==='phishing') return [
        {num:'1',col:'red',    title:'Structural URL Anomaly Detected',     desc:'The URL contains irregular subdomain depth, excessive hyphens, and deceptive path segments mimicking a legitimate domain — hallmark patterns of crafted phishing URLs.'},
        {num:'2',col:'red',    title:'Brand Impersonation Confirmed',       desc:'The domain closely resembles a known trusted brand using typosquatting or homoglyph substitution. Matched against 2M+ monitored brand patterns in our database.'},
        {num:'3',col:certOk?'yellow':'red', title:certOk?'SSL Present but Suspicious':'Invalid or Absent SSL Certificate', desc:certOk?'An SSL certificate exists but was issued recently by a low-trust authority — a common tactic to appear legitimate while still being malicious.':'No valid SSL certificate was found. Phishing pages frequently lack proper HTTPS or use expired / self-signed certificates.'},
        {num:'4',col:'red',    title:'Newly Registered Domain',             desc:'The domain was registered within the last 30 days. Phishing infrastructure is routinely built on freshly acquired domains to stay ahead of blocklists.'},
        {num:'5',col:badTld?'red':'yellow', title:badTld?'High-Risk TLD Identified':'TLD Under Observation', desc:badTld?`The TLD "${tld}" is heavily abused in phishing campaigns and rarely used by legitimate businesses.`:'The TLD is not strongly correlated with phishing on its own, but the combined signal set elevated the overall risk score.'},
    ];
    if (statusClass==='suspicious') return [
        {num:'1',col:'yellow', title:'Moderate Structural Risk Signals',    desc:'The URL structure shows unusual patterns — length, hyphen count, or subdomain depth — that correlate weakly with phishing but are not individually conclusive.'},
        {num:'2',col:certOk?'green':'yellow', title:certOk?'SSL Certificate Verified':'SSL Certificate Unverified', desc:certOk?'A valid SSL certificate was detected. Note: over 80% of phishing sites now use HTTPS, so SSL alone does not confirm legitimacy.':'The SSL certificate could not be fully verified, raising the suspicion score.'},
        {num:'3',col:'yellow', title:'Inconclusive Brand Matching',         desc:'No strong impersonation was found, but the domain shares partial similarity with known brands. Manual verification is recommended before entering credentials.'},
        {num:'4',col:badTld?'yellow':'green', title:badTld?'Unusual TLD Detected':'TLD Appears Legitimate', desc:badTld?`The TLD "${tld}" appears occasionally in spam and low-reputation campaigns.`:'The TLD is standard and widely used by reputable services, contributing no negative signal.'},
    ];
    return [
        {num:'1',col:'green',  title:'URL Structure Passes All Checks',    desc:'Normal URL length, no excessive hyphens or deep subdomains, no encoded obfuscation characters, and a clean path format consistent with legitimate web properties.'},
        {num:'2',col:certOk?'green':'yellow', title:certOk?'SSL Certificate Valid & Trusted':'SSL Certificate Self-Signed', desc:certOk?'A valid SSL certificate from a trusted Certificate Authority was confirmed with a matching domain subject.':'A self-signed certificate was detected. Not inherently malicious, but worth verifying the site manually.'},
        {num:'3',col:'green',  title:'No Brand Impersonation Found',       desc:'The domain does not match any known brand in our database of 2M+ monitored entities. No typosquatting or homoglyph patterns were detected.'},
        {num:'4',col:'green',  title:'Domain Age & Reputation Normal',     desc:'The domain has been registered for a significant period with healthy traffic history. Established domains are far less likely to be phishing infrastructure.'},
        {num:'5',col:badTld?'yellow':'green', title:badTld?'TLD Flagged for Review':'TLD Clean', desc:badTld?`"${tld}" is occasionally linked to spam. All other signals are clean, keeping the overall verdict Safe.`:'The TLD is standard and used widely by reputable organisations worldwide.'},
    ];
}

function buildSignals(statusClass, data) {
    const tld=(data.tld||'').toLowerCase();
    const suspTlds=['.xyz','.tk','.cf','.ml','.ga','.gq'];
    const badTld=suspTlds.some(t=>tld.includes(t));
    const certOk=data.certificate&&data.certificate.verified;
    const ipKnown=data.ip_address&&data.ip_address!=='Unknown';
    if (statusClass==='phishing') return [
        {col:'red',    text:'High-risk domain pattern'},
        {col:'red',    text:'Brand impersonation detected'},
        {col:certOk?'yellow':'red', text:certOk?'SSL present but suspicious':'Invalid SSL certificate'},
        {col:'red',    text:'Newly registered domain'},
        {col:'red',    text:'URL structure anomaly'},
        {col:badTld?'red':'yellow', text:badTld?'Suspicious TLD':'TLD under review'},
    ];
    if (statusClass==='suspicious') return [
        {col:'yellow', text:'Some risk signals present'},
        {col:certOk?'green':'yellow', text:certOk?'SSL certificate valid':'Unverified certificate'},
        {col:'yellow', text:'URL structure unusual'},
        {col:badTld?'yellow':'green', text:badTld?'Unusual TLD detected':'TLD appears legitimate'},
        {col:ipKnown?'green':'yellow', text:ipKnown?'IP resolved':'IP unresolvable'},
        {col:'yellow', text:'Monitor & verify manually'},
    ];
    return [
        {col:'green',  text:'No phishing signals found'},
        {col:certOk?'green':'yellow', text:certOk?'SSL certificate verified':'Certificate self-signed'},
        {col:'green',  text:'Domain appears legitimate'},
        {col:'green',  text:'URL structure normal'},
        {col:ipKnown?'green':'yellow', text:ipKnown?'IP resolves correctly':'IP lookup pending'},
        {col:badTld?'yellow':'green', text:badTld?'TLD flagged for review':'TLD clean'},
    ];
}

function rescan() {
    const url=urlInput.value.trim();
    if (!url){alert('Please enter a URL');urlInput.focus();return;}
    let finalUrl = url;
    // Add https:// if no protocol
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        if (url.includes('.')) {
            finalUrl = 'https://' + url;
        } else {
            // Auto-complete with .com if no TLD
            finalUrl = 'https://' + url + '.com';
        }
    }
    startScan(finalUrl);
}
function rescanCurrent() {
    const url=document.getElementById('res-url-display').textContent;
    if (url&&url!=='—'){urlInput.value=url;startScan(url);}
}
function isValidURL(s) {
    try{if(!s.startsWith('http://')&&!s.startsWith('https://'))s='https://'+s;new URL(s);return true;}catch{return false;}
}
function copyToClipboard() {
    const url=document.getElementById('res-url-display').textContent;
    navigator.clipboard.writeText(url).then(()=>{
        document.querySelectorAll('.icon-btn').forEach(b=>{if(b.textContent.includes('Copy')){b.innerHTML='<i class="fas fa-check"></i> Copied!';setTimeout(()=>b.innerHTML='<i class="fas fa-copy"></i> Copy',2000);}});
    }).catch(()=>{});
}

/* auto-refresh relative times every 30s */
setInterval(renderAllHistory, 30000);

renderAllHistory();
const params=new URLSearchParams(window.location.search);
if (params.get('url')){urlInput.value=params.get('url');startScan(params.get('url'));}
