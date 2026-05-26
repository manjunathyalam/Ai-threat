// ==========================================================================
// AETHER SHIELD SOC DASHBOARD - VIRUSTOTAL SCANNER UI
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    initVTTabs();
    initVTForm();
});

// --- 1. SCAN TYPE TOGGLING ---
function initVTTabs() {
    const tabs = document.querySelectorAll('.vt-tab');
    const typeInput = document.getElementById('vtQueryType');
    const valInput = document.getElementById('vtQueryValue');

    tabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
            e.preventDefault();
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const type = tab.getAttribute('data-type');
            typeInput.value = type;

            // Set placeholder prompts contextually
            if (type === 'ip') {
                valInput.placeholder = 'Enter IP Address (e.g. 185.220.101.5)';
                valInput.value = '185.220.101.5';
            } else if (type === 'domain') {
                valInput.placeholder = 'Enter Domain Name (e.g. evil-malware-download.com)';
                valInput.value = 'evil-malware-download.com';
            } else if (type === 'hash') {
                valInput.placeholder = 'Enter MD5/SHA256 File Hash (e.g. 44d88612fe831b81357c7378d46ad9d9)';
                valInput.value = '44d88612fe831b81357c7378d46ad9d9';
            } else if (type === 'url') {
                valInput.placeholder = 'Enter URL Link (e.g. http://phishing-bank-login.icu)';
                valInput.value = 'http://phishing-bank-login.icu';
            }
        });
    });
    
    // Set default value on initial load
    valInput.value = '185.220.101.5';
}

// --- 2. SUBMISSION AND DATABASE QUERY ---
function initVTForm() {
    const form = document.getElementById('vtScanForm');
    const loader = document.getElementById('vtLoading');
    const results = document.getElementById('vtResultArea');

    form.addEventListener('submit', (e) => {
        e.preventDefault();

        const type = document.getElementById('vtQueryType').value;
        const val = document.getElementById('vtQueryValue').value.trim();

        if (!val) return;

        // Reset display
        loader.classList.remove('hidden');
        results.classList.add('hidden');

        // Delay execution by 1200ms to show the cool radar scanning animation
        setTimeout(() => {
            fetch('/api/virustotal', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: type, value: val })
            })
            .then(res => res.json())
            .then(data => {
                loader.classList.add('hidden');
                renderVTResults(data);
            })
            .catch(err => {
                loader.classList.add('hidden');
                alert(`Scanner query failed: ${err.message}`);
            });
        }, 1200);
    });
}

// --- 3. RENDERING ENGINE DETAILS ---
function renderVTResults(data) {
    const results = document.getElementById('vtResultArea');
    results.classList.remove('hidden');

    // Setup Header info
    document.getElementById('vtResultQuery').innerText = data.value;
    document.getElementById('vtScanTime').innerText = data.scan_time;
    
    const typeBadge = document.getElementById('vtTypeBadge');
    typeBadge.innerText = data.type.toUpperCase();
    
    // Gauge score
    const scoreVal = document.getElementById('vtScoreVal');
    const verdictVal = document.getElementById('vtVerdictVal');
    const gaugeCircle = document.getElementById('vtGaugeCircle');
    
    scoreVal.innerText = `${data.engines_flagged}/${data.engines_total}`;
    verdictVal.innerText = data.reputation.toUpperCase();
    
    // Modify Gauge Colors
    gaugeCircle.className = 'vt-circle-gauge';
    verdictVal.className = 'label';
    
    // Circumference stroke updates
    const maliciousPct = (data.engines_flagged / data.engines_total) * 100;
    const cleanPct = 100 - maliciousPct;
    
    const redBar = document.getElementById('vtBarRed');
    const greenBar = document.getElementById('vtBarGreen');
    redBar.style.width = `${maliciousPct}%`;
    greenBar.style.width = `${cleanPct}%`;

    if (data.reputation === 'Malicious') {
        gaugeCircle.classList.add('malicious');
        verdictVal.classList.add('text-red');
        
        // Update circular conic gradient color styling
        gaugeCircle.style.background = `radial-gradient(circle, #0a1123 55%, transparent 56%), conic-gradient(#ff3e3e ${maliciousPct}%, #1e293b 0)`;
        gaugeCircle.style.boxShadow = '0 0 15px rgba(255, 62, 62, 0.25)';
    } else if (data.reputation === 'Suspicious') {
        gaugeCircle.classList.add('suspicious');
        verdictVal.classList.add('text-gold');
        gaugeCircle.style.background = `radial-gradient(circle, #0a1123 55%, transparent 56%), conic-gradient(#ffea00 ${maliciousPct}%, #1e293b 0)`;
        gaugeCircle.style.boxShadow = '0 0 15px rgba(255, 234, 0, 0.25)';
    } else {
        verdictVal.classList.add('text-green');
        gaugeCircle.style.background = `radial-gradient(circle, #0a1123 55%, transparent 56%), conic-gradient(#00ff80 100%, #1e293b 0)`;
        gaugeCircle.style.boxShadow = '0 0 15px rgba(0, 255, 128, 0.25)';
    }

    // Populate dynamic details grids based on types
    const grid = document.getElementById('vtDetailsGrid');
    grid.innerHTML = '';
    const details = data.details;

    if (data.type === 'ip') {
        grid.innerHTML = `
            <div><span class="label">REPUTATION STATE</span><span class="val text-cyan">${data.reputation}</span></div>
            <div><span class="label">GEOLOCATION COUNTRY</span><span class="val">${details.country}</span></div>
            <div><span class="label">RESOLVING RECOGNIZED HOSTNAME</span><span class="val">${details.hostname}</span></div>
            <div><span class="label">INTERNET SERVICE PROVIDER</span><span class="val">${details.isp}</span></div>
            <div><span class="label">THREAT INTEL CLASSIFICATION</span><span class="val text-red">${details.classification}</span></div>
            <div><span class="label">REGISTRY AGENT</span><span class="val">${details.intel_source}</span></div>
        `;
    } else if (data.type === 'domain') {
        grid.innerHTML = `
            <div><span class="label">DOMAIN AUTHORITY</span><span class="val text-cyan">${data.reputation}</span></div>
            <div><span class="label">REGISTRAR ENFORCING AGENT</span><span class="val">${details.registrar}</span></div>
            <div><span class="label">REGISTRY CREATION DATE</span><span class="val">${details.created_date}</span></div>
            <div><span class="label">RESOLVING ACTIVE IP(S)</span><span class="val"><code>${details.resolved_ips.join(', ')}</code></span></div>
            <div><span class="label">SECURITY CATEGORIES</span><span class="val">${details.categories.join(', ')}</span></div>
        `;
    } else if (data.type === 'hash') {
        grid.innerHTML = `
            <div><span class="label">CRYPTOGRAPHIC FILE SAFETY</span><span class="val text-cyan">${data.reputation}</span></div>
            <div><span class="label">FILE MIME TYPE</span><span class="val">${details.file_type}</span></div>
            <div><span class="label">FILE STORAGE SIZE</span><span class="val">${details.file_size}</span></div>
            <div><span class="label">FIRST SEEN BY TELEMETRY</span><span class="val">${details.first_seen}</span></div>
            <div><span class="label">ENTROPY COMPRESSION INDEX</span><span class="val">${details.entropy}</span></div>
            <div><span class="label">THREAT IDENTIFIER CLASSIFICATION</span><span class="val text-red">${details.threat_name}</span></div>
        `;
    } else if (data.type === 'url') {
        grid.innerHTML = `
            <div><span class="label">URL SAFETY INDEX</span><span class="val text-cyan">${data.reputation}</span></div>
            <div><span class="label">WEB SERVER HTTP STATUS CODE</span><span class="val">${details.http_status}</span></div>
            <div><span class="label">HOST SERVER TYPE</span><span class="val">${details.server}</span></div>
            <div><span class="label">INGRESS PAYLOAD ATTACHMENT</span><span class="val text-gold">${details.payload_delivered}</span></div>
            <div><span class="label">WEB CATEGORIZATIONS</span><span class="val">${details.categories.join(', ')}</span></div>
        `;
    }

    // Populate engine reputations
    const engines = ['eCrowdStrike', 'eKaspersky', 'eSymantec', 'ePaloAlto', 'eFireEye', 'eSophos'];
    engines.forEach(e => {
        const item = document.getElementById(e);
        const icon = item.previousElementSibling;
        
        if (data.engines_flagged > 0 && Math.random() < (data.engines_flagged / 75)) {
            // Flag engine as positive
            item.innerText = 'Malicious Indicator';
            item.className = 'text-red';
            icon.className = 'fa-solid fa-circle-exclamation text-red';
        } else {
            // Clean
            item.innerText = 'Clean';
            item.className = 'text-green';
            icon.className = 'fa-solid fa-circle-check text-green';
        }
    });
}
