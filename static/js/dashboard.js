// ==========================================================================
// AETHER SHIELD SOC DASHBOARD - CORE LOGIC
// ==========================================================================

// Global state
let currentReport = null;
let timelineChart = null;
let vectorChart = null;
let currentTab = 'dashboard';

// Initialize on document ready
document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initTabNavigation();
    initUploadSystem();
    initCharts();
    loadDashboardStats();
    loadSettings();
    initAlertsFilter();
    initGlobalSearch();
    
    // Wire up print and export actions
    document.getElementById('btnPrintReport').addEventListener('click', () => window.print());
    document.getElementById('btnExportJSON').addEventListener('click', exportRawJSON);
});

// --- 1. CLOCK LOGIC ---
function initClock() {
    const clockElement = document.querySelector('#headerClock span');
    function update() {
        const now = new Date();
        const utcStr = now.toISOString().replace('T', ' ').substring(0, 19);
        clockElement.textContent = `UTC ${utcStr}`;
    }
    setInterval(update, 1000);
    update();
}

// --- 2. TAB NAVIGATION ---
function initTabNavigation() {
    const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = item.getAttribute('data-tab');
            if (!targetTab) return;

            // Update active nav
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            // Update active pane
            tabPanes.forEach(pane => pane.classList.remove('active'));
            const targetPane = document.getElementById(`tab-${targetTab}`);
            if (targetPane) targetPane.classList.add('active');
            
            currentTab = targetTab;
            
            // Tab specific loaders
            if (targetTab === 'dashboard') {
                loadDashboardStats();
            } else if (targetTab === 'reports') {
                loadReportsArchive();
            }
        });
    });
}

// --- 3. CHARTS SYSTEM ---
function initCharts() {
    const timelineCtx = document.getElementById('threatTimelineChart').getContext('2d');
    const vectorCtx = document.getElementById('vectorPieChart').getContext('2d');

    // Default configuration for Chart.js (dark theme overrides)
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Share Tech Mono', sans-serif";

    // 1. Timeline Line Chart
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: ['06:00', '08:00', '10:00', '12:00', '14:00', '16:00'],
            datasets: [{
                label: 'Threat Level Index',
                data: [15, 20, 45, 30, 20, 15],
                borderColor: '#00e5ff',
                backgroundColor: 'rgba(0, 229, 255, 0.05)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#00e5ff',
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    min: 0,
                    max: 100
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });

    // 2. Vector Doughnut Chart
    vectorChart = new Chart(vectorCtx, {
        type: 'doughnut',
        data: {
            labels: ['SQLi', 'Brute Force', 'Cmd Injection', 'XSS', 'Malware', 'Port Scan'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: [
                    '#ff3e3e', // SQLi
                    '#ffea00', // Brute Force
                    '#0066ff', // Cmd Inj
                    '#d9f99d', // XSS
                    '#00ff80', // Malware
                    '#a5f3fc'  // Port Scan
                ],
                borderWidth: 1,
                borderColor: '#0a1123'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        boxWidth: 12,
                        font: { size: 10 }
                    }
                }
            },
            cutout: '65%'
        }
    });
}

// --- 4. COUNTER INCREMENTS & SECURITY GAUGE ---
function animateValue(obj, start, end, duration) {
    if (start === end) return;
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        obj.innerHTML = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

function updateSecurityGauge(threatScore) {
    const securityScore = Math.max(0, 100 - threatScore);
    const gaugeFill = document.getElementById('scoreGaugeFill');
    const scoreNumber = document.getElementById('scoreNumber');
    const scoreGrade = document.getElementById('scoreGrade');
    const scoreSummary = document.getElementById('scoreSummary');

    // SVG dash offset calculation (circumference is ~264)
    const strokeOffset = 264 * (1 - securityScore / 100);
    gaugeFill.style.strokeDashoffset = strokeOffset;

    // Animate score value
    const curVal = parseInt(scoreNumber.innerText) || 100;
    animateValue(scoreNumber, curVal, securityScore, 800);

    // Update colors and classifications based on posture
    gaugeFill.classList.remove('green-stroke', 'gold-stroke', 'red-stroke');
    scoreGrade.classList.remove('text-green', 'text-gold', 'text-red');

    if (securityScore >= 75) {
        gaugeFill.style.stroke = '#00ff80';
        scoreGrade.className = 'text-green';
        scoreGrade.innerText = 'STATUS: OPTIMAL';
        scoreSummary.innerText = 'All security controls active. Threat scans report clean baseline traffic patterns across analyzed environments.';
    } else if (securityScore >= 35) {
        gaugeFill.style.stroke = '#ffea00';
        scoreGrade.className = 'text-gold';
        scoreGrade.innerText = 'STATUS: DEGRADED';
        scoreSummary.innerText = 'System under suspicious scanning behavior. Log signatures reveal low-severity probes or brute-force profiling.';
    } else {
        gaugeFill.style.stroke = '#ff3e3e';
        scoreGrade.className = 'text-red';
        scoreGrade.innerText = 'STATUS: INTRUSION ACTIVE';
        scoreSummary.innerText = 'High-risk exploit footprint identified. Execute standard SOC containment procedures, isolate targeted nodes, and block bad IPs.';
    }
}

// --- 5. LOG UPLOAD AND SCAN SYSTEM ---
function initUploadSystem() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    // Prevent defaults for drag events
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    // Handle hover states
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    // Handle dropped files
    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length) uploadLogFile(files[0]);
    });

    // Handle selected files
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) uploadLogFile(fileInput.files[0]);
    });
}

function uploadLogFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const progressArea = document.getElementById('scanProgressArea');
    const progressBarFill = document.getElementById('progressBarFill');
    const progressFileName = document.getElementById('progressFileName');
    const progressStatusText = document.getElementById('progressStatusText');
    const resultsArea = document.getElementById('scanResultsArea');
    
    // Reset steps UI
    const step1 = document.getElementById('step1');
    const step2 = document.getElementById('step2');
    const step3 = document.getElementById('step3');
    const step4 = document.getElementById('step4');
    
    [step1, step2, step3, step4].forEach(s => s.className = 'step');

    // Show progress container, hide results
    progressArea.classList.remove('hidden');
    resultsArea.classList.add('hidden');
    
    progressFileName.innerText = file.name;
    progressBarFill.style.width = '0%';
    
    // Trigger animated loading stages to simulate pipeline parsing
    let progressVal = 0;
    step1.classList.add('active');
    progressStatusText.innerText = 'UPLOADING SECURE BINARIES...';

    const interval = setInterval(() => {
        if (progressVal < 25) {
            progressVal += 5;
            progressBarFill.style.width = `${progressVal}%`;
        } else if (progressVal < 50) {
            step1.className = 'step complete';
            step2.classList.add('active');
            progressStatusText.innerText = 'REGEX SECURITY SIGNATURE CHECKING...';
            progressVal += 5;
            progressBarFill.style.width = `${progressVal}%`;
        } else if (progressVal < 80) {
            step2.className = 'step complete';
            step3.classList.add('active');
            progressStatusText.innerText = 'COGNITIVE AI CLASSIFIER INJECTING DATA...';
            progressVal += 4;
            progressBarFill.style.width = `${progressVal}%`;
        }
    }, 150);

    // Make AJAX Upload call
    fetch('/api/upload', {
        method: 'POST',
        body: formData
    })
    .then(res => {
        if (!res.ok) {
            return res.json().then(err => { throw new Error(err.error || 'Scan upload failed'); });
        }
        return res.json();
    })
    .then(data => {
        clearInterval(interval);
        
        // Fast forward animations to complete
        progressBarFill.style.width = '100%';
        step3.className = 'step complete';
        step4.className = 'step complete';
        progressStatusText.innerText = 'COMMIT SUCCESSFUL.';
        
        setTimeout(() => {
            progressArea.classList.add('hidden');
            renderScanResults(data);
            loadDashboardStats(); // Refresh dashboard numbers
        }, 500);
    })
    .catch(err => {
        clearInterval(interval);
        progressArea.classList.add('hidden');
        alert(`Ingestion Fail: ${err.message}`);
    });
}

// --- 6. RENDER LOG ANALYSIS EVENT RESULTS ---
function renderScanResults(reportData) {
    currentReport = reportData;
    const resultsArea = document.getElementById('scanResultsArea');
    resultsArea.classList.remove('hidden');

    // Headers & file details
    document.getElementById('resultFileName').innerText = reportData.filename;
    document.getElementById('resultTimestamp').innerText = reportData.timestamp;
    document.getElementById('resultLinesCount').innerText = reportData.total_lines.toLocaleString();
    document.getElementById('resultThreatScore').innerText = reportData.threat_score;
    
    // Status badges
    const badge = document.getElementById('resultStatusBadge');
    badge.className = 'badge';
    badge.innerText = reportData.status;
    
    if (reportData.status === 'Clean') badge.classList.add('badge-success');
    else if (reportData.status === 'Suspicious') badge.classList.add('badge-warning');
    else badge.classList.add('badge-danger');

    // Severity Box stats
    const severityStats = reportData.detector_results.severity_stats;
    document.getElementById('resultCriticalCount').innerText = severityStats.Critical;
    document.getElementById('resultHighCount').innerText = severityStats.High;
    document.getElementById('resultMedLowCount').innerText = severityStats.Medium + severityStats.Low;

    // --- AI Analyser Output Rendering ---
    const aiReport = reportData.ai_report;
    document.getElementById('aiTechnicalExplanation').innerText = aiReport.technical_explanation;
    
    // Recommendations
    const recsList = document.getElementById('aiRecommendations');
    recsList.innerHTML = '';
    aiReport.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.innerText = rec;
        recsList.appendChild(li);
    });

    // Analyst Notes
    document.getElementById('aiSocNotes').innerText = aiReport.soc_notes;

    // MITRE ATT&CK Matrix
    const mitreBody = document.getElementById('aiMitreBody');
    mitreBody.innerHTML = '';
    if (aiReport.mitre_attack && aiReport.mitre_attack.length > 0) {
        aiReport.mitre_attack.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><span class="text-cyan"><i class="fa-solid fa-crosshairs"></i> ${item.tactic}</span></td>
                <td><code>${item.technique}</code></td>
            `;
            mitreBody.appendChild(tr);
        });
    } else {
        mitreBody.innerHTML = '<tr><td colspan="2" class="text-center">No ATT&CK Techniques Mapped</td></tr>';
    }

    // --- Rule Alerts Ingest Grid Rendering ---
    const alertsBody = document.getElementById('resultAlertsBody');
    alertsBody.innerHTML = '';
    const alertsList = reportData.detector_results.alerts;

    if (alertsList.length > 0) {
        alertsList.forEach((alert, index) => {
            const tr = document.createElement('tr');
            tr.setAttribute('data-index', index);
            
            let sevClass = 'text-green';
            if (alert.severity === 'Critical') sevClass = 'text-red font-bold';
            else if (alert.severity === 'High') sevClass = 'text-red';
            else if (alert.severity === 'Medium') sevClass = 'text-gold';
            else if (alert.severity === 'Low') sevClass = 'text-cyan';

            tr.innerHTML = `
                <td>${alert.line}</td>
                <td><span class="${sevClass}">${alert.severity}</span></td>
                <td>${alert.category}</td>
                <td><code>${alert.ip}</code></td>
                <td>${alert.timestamp}</td>
            `;
            
            tr.addEventListener('click', () => {
                // Remove active classes
                document.querySelectorAll('#resultAlertsBody tr').forEach(r => r.classList.remove('selected'));
                tr.classList.add('selected');
                inspectAlertDetail(alert);
            });
            alertsBody.appendChild(tr);
        });
        
        // Auto inspect first alert
        alertsBody.firstChild.click();
    } else {
        alertsBody.innerHTML = '<tr><td colspan="5" class="text-center">No alerts flagged by parser rules.</td></tr>';
        document.getElementById('alertDetailInspector').classList.add('hidden');
    }
}

// Alert detail inspector window
function inspectAlertDetail(alert) {
    const inspector = document.getElementById('alertDetailInspector');
    inspector.classList.remove('hidden');

    document.getElementById('inspectLine').innerText = alert.line;
    document.getElementById('inspectCategory').innerText = alert.category;
    document.getElementById('inspectIP').innerText = alert.ip;
    document.getElementById('inspectEvidence').innerText = alert.evidence;
    document.getElementById('inspectRaw').innerText = alert.raw;

    const sevBadge = document.getElementById('inspectSeverity');
    sevBadge.className = 'badge';
    sevBadge.innerText = alert.severity;
    
    if (alert.severity === 'Critical') sevBadge.classList.add('badge-danger');
    else if (alert.severity === 'High') sevBadge.classList.add('badge-danger');
    else if (alert.severity === 'Medium') sevBadge.classList.add('badge-warning');
    else sevBadge.classList.add('badge-info');
}

// Alerts filtering search box
function initAlertsFilter() {
    const input = document.getElementById('alertsFilterInput');
    input.addEventListener('keyup', () => {
        const query = input.value.toLowerCase();
        const rows = document.querySelectorAll('#resultAlertsBody tr');
        rows.forEach(row => {
            const text = row.innerText.toLowerCase();
            if (text.includes(query)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    });
}

// --- 7. EXPORT DATA FILES ---
function exportRawJSON() {
    if (!currentReport) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReport, null, 4));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `report_${currentReport.filename.split('.')[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
}

// --- 8. REPORTS ARCHIVE REPOSITORY ---
function loadReportsArchive() {
    fetch('/api/reports')
    .then(res => res.json())
    .then(reports => {
        const body = document.getElementById('reportsArchiveBody');
        body.innerHTML = '';

        if (reports.length === 0) {
            body.innerHTML = '<tr><td colspan="8" class="text-center">No security logs scanned in database history.</td></tr>';
            return;
        }

        reports.forEach(report => {
            const tr = document.createElement('tr');
            
            let statusClass = 'text-green';
            if (report.status === 'Critical') statusClass = 'text-red font-bold';
            else if (report.status === 'Malicious') statusClass = 'text-red';
            else if (report.status === 'Suspicious') statusClass = 'text-gold';
            
            tr.innerHTML = `
                <td><code>#${report.id}</code></td>
                <td><strong>${report.filename}</strong></td>
                <td>${report.timestamp}</td>
                <td>${report.total_lines.toLocaleString()}</td>
                <td><span class="text-cyan">${report.threat_score}</span></td>
                <td><span class="${statusClass}">${report.status}</span></td>
                <td>${report.alerts_count}</td>
                <td>
                    <div class="row-actions">
                        <button class="row-btn load" onclick="viewHistoricalReport(${report.id})" title="Load to scan view"><i class="fa-solid fa-folder-open"></i></button>
                        <button class="row-btn delete" onclick="deleteReport(${report.id}, this)" title="Delete scan"><i class="fa-solid fa-trash-can"></i></button>
                    </div>
                </td>
            `;
            body.appendChild(tr);
        });
    })
    .catch(err => console.error("Error loading archive reports:", err));
}

window.viewHistoricalReport = function(reportId) {
    fetch(`/api/reports/${reportId}`)
    .then(res => res.json())
    .then(reportData => {
        // Go to Scan Tab
        document.querySelector('.sidebar-nav .nav-item[data-tab="scan"]').click();
        renderScanResults(reportData);
    })
    .catch(err => alert(`Failed to load historical report: ${err.message}`));
}

window.deleteReport = function(reportId, btn) {
    if (!confirm("Are you sure you want to permanently delete this threat scan report?")) return;
    
    fetch(`/api/reports/${reportId}/delete`, { method: 'DELETE' })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            // Delete row
            const tr = btn.closest('tr');
            tr.remove();
            loadDashboardStats(); // Refresh dashboard stats
        }
    })
    .catch(err => alert(`Failed to delete: ${err.message}`));
}

// --- 9. DASHBOARD METRICS LOADER ---
function loadDashboardStats() {
    fetch('/api/reports')
    .then(res => res.json())
    .then(reports => {
        const totalScans = reports.length;
        let totalAlerts = 0;
        let sumScore = 0;
        let criticalAlerts = 0;
        
        let categoryCounts = {
            'SQL Injection': 0, 'Brute Force Logs': 0, 'Command Injection': 0, 
            'XSS Attempts': 0, 'Malware Indicators': 0, 'Port Scans': 0
        };
        
        let dailyTimeline = { labels: [], data: [] };

        reports.forEach(r => {
            totalAlerts += r.alerts_count;
            sumScore += r.threat_score;
        });

        // Compute Averages
        const avgRisk = totalScans > 0 ? Math.round(sumScore / totalScans) : 0;
        const avgThreatCount = totalScans > 0 ? totalAlerts : 0;

        // UI counters update
        const countScans = document.getElementById('statTotalScans');
        const countAlerts = document.getElementById('statThreatAlerts');
        const countAvgRisk = document.getElementById('statAvgRisk');
        const statusTrend = document.getElementById('statThreatTrend');

        // Animate counter figures
        animateValue(countScans, parseInt(countScans.innerText) || 0, totalScans, 700);
        animateValue(countAlerts, parseInt(countAlerts.innerText) || 0, avgThreatCount, 700);
        animateValue(countAvgRisk, parseInt(countAvgRisk.innerText) || 0, avgRisk, 700);
        
        // Update circular gauge score based on overall risk average
        updateSecurityGauge(avgRisk);

        // Fetch details of all reports to compile detailed chart vectors and incident history
        let fetches = reports.map(r => fetch(`/api/reports/${r.id}`).then(res => res.json()));
        
        Promise.all(fetches)
        .then(details => {
            // Re-aggregate counts
            details.forEach(d => {
                const cats = d.detector_results.category_stats;
                for (let key in cats) {
                    if (categoryCounts.hasOwnProperty(key)) {
                        categoryCounts[key] += cats[key];
                    }
                }
                
                criticalAlerts += d.detector_results.severity_stats.Critical;
            });

            // Update Critical Sub stats label
            document.getElementById('statCriticalAlerts').innerText = `${criticalAlerts} Critical events found`;
            
            // System status indicators update
            const socPill = document.getElementById('socStatusVal');
            if (criticalAlerts > 0) {
                socPill.className = 'status-val red';
                socPill.innerText = 'HIGH INCIDENTS ACTIVE';
                statusTrend.innerText = 'CRITICAL';
                statusTrend.className = 'text-red';
            } else if (avgRisk > 25) {
                socPill.className = 'status-val red';
                socPill.innerText = 'THREAT INTRUSION DETECTED';
                statusTrend.innerText = 'WARN';
                statusTrend.className = 'text-gold';
            } else {
                socPill.className = 'status-val green';
                socPill.innerText = 'ACTIVE RECORDING';
                statusTrend.innerText = 'STABLE';
                statusTrend.className = 'text-green';
            }

            // Update Vector Pie chart
            vectorChart.data.datasets[0].data = [
                categoryCounts['SQL Injection'],
                categoryCounts['Brute Force Logs'],
                categoryCounts['Command Injection'],
                categoryCounts['XSS Attempts'],
                categoryCounts['Malware Indicators'],
                categoryCounts['Port Scans']
            ];
            vectorChart.update();

            // Compile Incident Chronology Timeline graph (last 6 files parsed)
            const timelineData = details.slice(0, 6).reverse();
            timelineChart.data.labels = timelineData.map(t => t.timestamp.substring(11, 16));
            timelineChart.data.datasets[0].data = timelineData.map(t => t.threat_score);
            timelineChart.update();

            // Populate Live Intrusion Logs inside Dashboard Overview
            const container = document.getElementById('recentAlertsList');
            container.innerHTML = '';
            let timelineAlerts = [];
            
            details.forEach(d => {
                d.detector_results.alerts.forEach(a => {
                    timelineAlerts.push({
                        time: a.timestamp.substring(11, 19),
                        category: a.category,
                        desc: a.description,
                        severity: a.severity
                    });
                });
            });

            // Sort newest first
            timelineAlerts = timelineAlerts.slice(0, 6);
            if (timelineAlerts.length > 0) {
                timelineAlerts.forEach(alert => {
                    const item = document.createElement('div');
                    item.className = 'event-item ' + (alert.severity === 'Critical' || alert.severity === 'High' ? 'malicious' : 'suspicious');
                    
                    let badgeClass = 'badge-warning';
                    if (alert.severity === 'Critical' || alert.severity === 'High') badgeClass = 'badge-danger';
                    
                    item.innerHTML = `
                        <span class="time">${alert.time}</span>
                        <span class="category">${alert.category}</span>
                        <span class="desc">${alert.desc}</span>
                        <span class="badge ${badgeClass}">${alert.severity}</span>
                    `;
                    container.appendChild(item);
                });
            } else {
                container.innerHTML = `
                    <div class="event-item clean">
                        <span class="time">SECURE</span>
                        <span class="category">MONITOR ACTIVE</span>
                        <span class="desc">No malicious intrusion events mapped in logs history.</span>
                        <span class="badge badge-success">OK</span>
                    </div>
                `;
            }
        });
    })
    .catch(err => console.error("Error updating stats dashboard:", err));
}

// --- 10. GLOBAL SYSTEM SEARCH ---
function initGlobalSearch() {
    const input = document.getElementById('globalSearch');
    input.addEventListener('keyup', (e) => {
        if (e.key === 'Enter') {
            const query = input.value.trim().toLowerCase();
            if (!query) return;

            // Route search queries contextually
            if (currentTab === 'dashboard') {
                // Focus sidebar search
                const rows = document.querySelectorAll('#recentAlertsList .event-item');
                rows.forEach(r => {
                    r.style.display = r.innerText.toLowerCase().includes(query) ? '' : 'none';
                });
            } else if (currentTab === 'scan' && currentReport) {
                document.getElementById('alertsFilterInput').value = query;
                document.getElementById('alertsFilterInput').dispatchEvent(new Event('keyup'));
            } else if (currentTab === 'reports') {
                document.getElementById('reportArchiveSearch').value = query;
                document.getElementById('reportArchiveSearch').dispatchEvent(new Event('keyup'));
            } else if (currentTab === 'packets') {
                document.getElementById('packetSearch').value = query;
                document.getElementById('packetSearch').dispatchEvent(new Event('keyup'));
            } else if (currentTab === 'virustotal') {
                document.getElementById('vtQueryValue').value = query;
            }
        }
    });

    // Archive repository specific search
    const archiveSearch = document.getElementById('reportArchiveSearch');
    archiveSearch.addEventListener('keyup', () => {
        const query = archiveSearch.value.toLowerCase();
        const rows = document.querySelectorAll('#reportsArchiveBody tr');
        rows.forEach(row => {
            row.style.display = row.innerText.toLowerCase().includes(query) ? '' : 'none';
        });
    });
}

// --- 11. SOC SETTINGS SAVE ---
function loadSettings() {
    fetch('/api/settings')
    .then(res => res.json())
    .then(data => {
        document.getElementById('settingsAPIKey').value = data.openai_api_key;
        document.getElementById('settingsAutoAI').checked = data.auto_ai_scan;
        document.getElementById('settingsThreshold').value = data.alert_threshold;
        document.getElementById('thresholdVal').innerText = data.alert_threshold;
        document.getElementById('settingsPacketSpeed').value = data.packet_monitoring_speed;
        
        // Update header API status display
        const apiVal = document.getElementById('apiStatusVal');
        if (data.openai_api_key) {
            apiVal.innerText = 'GPT-4O-MINI ACTIVE';
            apiVal.className = 'api-val text-green';
        } else {
            apiVal.innerText = 'LOCAL LOGIC ONLY';
            apiVal.className = 'api-val text-gold';
        }
    })
    .catch(err => console.error("Error loading settings:", err));
}

// Range tracker update
document.getElementById('settingsThreshold').addEventListener('input', (e) => {
    document.getElementById('thresholdVal').innerText = e.target.value;
});

document.getElementById('settingsForm').addEventListener('submit', (e) => {
    e.preventDefault();
    
    const payload = {
        openai_api_key: document.getElementById('settingsAPIKey').value,
        auto_ai_scan: document.getElementById('settingsAutoAI').checked,
        alert_threshold: parseInt(document.getElementById('settingsThreshold').value),
        packet_monitoring_speed: document.getElementById('settingsPacketSpeed').value
    };

    fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            alert("Security policy changes committed successfully.");
            loadSettings(); // Reload and refresh
            
            // If packet monitor is running, restart loop to pick up new speed
            if (typeof restartPacketCapture === 'function') {
                restartPacketCapture();
            }
        }
    })
    .catch(err => alert(`Failed to save settings: ${err.message}`));
});

// Toggle key masking
window.toggleApiKeyVisibility = function() {
    const input = document.getElementById('settingsAPIKey');
    const eye = document.getElementById('keyEyeIcon');
    if (input.type === 'password') {
        input.type = 'text';
        eye.className = 'fa-solid fa-eye-slash';
    } else {
        input.type = 'password';
        eye.className = 'fa-solid fa-eye';
    }
}
