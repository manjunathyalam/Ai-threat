// ==========================================================================
// AETHER SHIELD SOC DASHBOARD - WIRESHARK PACKET MONITOR
// ==========================================================================

let packetCount = 0;
let captureActive = true;
let packetLoopId = null;
let packetList = [];
let selectedPacket = null;

// Initialize when ready
document.addEventListener('DOMContentLoaded', () => {
    initPacketCapture();
    initPacketFilters();
    initInspectorTabs();
    
    document.getElementById('btnToggleCapture').addEventListener('click', toggleCapture);
    document.getElementById('btnClearPackets').addEventListener('click', clearPackets);
});

// --- 1. CAPTURE CONTROL LOOP ---
function initPacketCapture() {
    // Run initial fetch to fill the screen
    fetchPackets(12);
    
    // Start live interval
    startCaptureLoop();
}

function startCaptureLoop() {
    if (packetLoopId) clearInterval(packetLoopId);
    
    // Read speed from settings or default
    const speedSelect = document.getElementById('settingsPacketSpeed');
    const speed = speedSelect ? speedSelect.value : 'medium';
    
    let intervalMs = 2000;
    if (speed === 'slow') intervalMs = 4000;
    else if (speed === 'fast') intervalMs = 800;
    
    packetLoopId = setInterval(() => {
        if (captureActive && currentTab === 'packets') {
            fetchPackets(1);
        }
    }, intervalMs);
}

// Global hook to restart loop on settings commit
window.restartPacketCapture = function() {
    startCaptureLoop();
};

function toggleCapture() {
    const btn = document.getElementById('btnToggleCapture');
    captureActive = !captureActive;
    
    if (captureActive) {
        btn.innerHTML = '<i class="fa-solid fa-pause"></i> PAUSE CAPTURE';
        btn.className = 'cyber-btn';
        startCaptureLoop();
    } else {
        btn.innerHTML = '<i class="fa-solid fa-play"></i> RESUME CAPTURE';
        btn.className = 'cyber-btn-outline';
        if (packetLoopId) clearInterval(packetLoopId);
    }
}

function clearPackets() {
    packetList = [];
    document.getElementById('packetsBody').innerHTML = '';
    document.getElementById('packetFrameTree').innerHTML = '<li><i class="fa-solid fa-circle-info"></i> Select a packet to inspect frame structure.</li>';
    document.getElementById('packetHexDump').innerText = '0000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................';
    selectedPacket = null;
}

function fetchPackets(count) {
    fetch(`/api/packets?count=${count}`)
    .then(res => res.json())
    .then(newPackets => {
        newPackets.forEach(p => {
            packetCount++;
            p.no = packetCount;
            packetList.push(p);
            
            // Limit buffer to 200 packets to prevent DOM bloating
            if (packetList.length > 200) {
                packetList.shift();
                // Remove first row from DOM
                const body = document.getElementById('packetsBody');
                if (body.firstChild) body.removeChild(body.firstChild);
            }
            
            appendPacketToTable(p);
        });
    })
    .catch(err => console.error("Error retrieving packet stream:", err));
}

// --- 2. DOM RENDERING & STYLING ---
function appendPacketToTable(packet) {
    const body = document.getElementById('packetsBody');
    const tr = document.createElement('tr');
    tr.setAttribute('data-proto', packet.protocol);
    tr.setAttribute('data-no', packet.no);
    
    if (packet.suspicious) {
        tr.className = 'suspicious';
    }
    
    tr.innerHTML = `
        <td>${packet.no}</td>
        <td>${packet.time}</td>
        <td><code>${packet.source}</code></td>
        <td><code>${packet.destination}</code></td>
        <td>${packet.protocol}</td>
        <td>${packet.length}</td>
        <td class="text-truncate" style="max-width: 320px;">${packet.info}</td>
    `;
    
    tr.addEventListener('click', () => {
        document.querySelectorAll('#packetsBody tr').forEach(r => r.classList.remove('selected'));
        tr.classList.add('selected');
        inspectPacket(packet);
    });
    
    body.appendChild(tr);
    
    // Auto scroll to bottom of packets table if user isn't reviewing a specific packet
    if (!selectedPacket) {
        const container = document.querySelector('.packets-table-container');
        container.scrollTop = container.scrollHeight;
    }
}

// --- 3. LAYER INSPECTION & HEX GENERATION ---
function inspectPacket(packet) {
    selectedPacket = packet;
    
    // 1. Compile details tree
    const tree = document.getElementById('packetFrameTree');
    tree.innerHTML = `
        <li><i class="fa-solid fa-caret-down"></i> <strong>Frame ${packet.no}:</strong> ${packet.length} bytes on wire captured on interface eth0</li>
        <li><i class="fa-solid fa-caret-down"></i> <strong>Ethernet II:</strong> Src: Intel_${randMacByte()}:${randMacByte()} (00:1c:42:${randMacByte()}:${randMacByte()}:${randMacByte()}), Dst: Router_${randMacByte()}:${randMacByte()} (00:50:56:${randMacByte()}:${randMacByte()}:${randMacByte()})</li>
        <li><i class="fa-solid fa-caret-down"></i> <strong>Internet Protocol Version 4:</strong> Src: ${packet.source}, Dst: ${packet.destination}, Version: 4, Header Length: 20 bytes, TTL: 64</li>
    `;
    
    // Protocol layer additions
    const protocolLi = document.createElement('li');
    if (packet.protocol === 'TCP') {
        protocolLi.innerHTML = `<i class="fa-solid fa-caret-down"></i> <strong>Transmission Control Protocol:</strong> Src Port: ${packet.sport}, Dst Port: ${packet.dport}, Seq: ${Math.floor(Math.random()*1000)}, Ack: ${Math.floor(Math.random()*1000)}, Flags: [PSH, ACK], Window Size: 502`;
    } else if (packet.protocol === 'UDP') {
        protocolLi.innerHTML = `<i class="fa-solid fa-caret-down"></i> <strong>User Datagram Protocol:</strong> Src Port: ${packet.sport}, Dst Port: ${packet.dport}, Length: ${packet.length - 20}, Checksum: 0x${Math.floor(Math.random()*65535).toString(16).toUpperCase()}`;
    } else if (packet.protocol === 'ICMP') {
        protocolLi.innerHTML = `<i class="fa-solid fa-caret-down"></i> <strong>Internet Control Message Protocol:</strong> Type: ${packet.sport === '0' ? '0 (Echo Reply)' : '8 (Echo Request)'}, Code: 0, Checksum: 0x${Math.floor(Math.random()*65535).toString(16).toUpperCase()}`;
    } else {
        protocolLi.innerHTML = `<i class="fa-solid fa-caret-down"></i> <strong>User Datagram Protocol:</strong> Domain Name System query/response layer, Port: 53`;
    }
    tree.appendChild(protocolLi);
    
    // Application layer representation
    const appLi = document.createElement('li');
    appLi.innerHTML = `<i class="fa-solid fa-caret-down"></i> <strong>Data Payload details:</strong> ${packet.info}`;
    tree.appendChild(appLi);

    // Expand details listener
    tree.querySelectorAll('li').forEach(li => {
        li.addEventListener('click', (e) => {
            e.stopPropagation();
            const caret = li.querySelector('i');
            if (caret.classList.contains('fa-caret-down')) {
                caret.className = 'fa-solid fa-caret-right';
                // Mock hide subfields (simple toggle)
            } else {
                caret.className = 'fa-solid fa-caret-down';
            }
        });
    });

    // 2. Generate customized Hex raw data
    generateHexDump(packet);
}

function randMacByte() {
    return Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
}

function generateHexDump(packet) {
    const dumpElem = document.getElementById('packetHexDump');
    
    // Customize dump depending on protocol/attack type
    let hexContent = "";
    let lines = 4;
    if (packet.length > 200) lines = 8;
    if (packet.length > 1000) lines = 12;
    
    // Inject strings into hex lines contextually
    let readableText = "";
    if (packet.info.includes("UNION SELECT")) {
        readableText = "UNION SELECT u.username, u.password FROM users..";
    } else if (packet.info.includes("cat /etc/passwd")) {
        readableText = "id; cat /etc/passwd; exit;";
    } else if (packet.info.includes("Failed password")) {
        readableText = "sshd:auth: Failed password for root from " + packet.source;
    } else if (packet.info.includes("DNS")) {
        readableText = "DNS query: google.com. A IN AAAA";
    } else if (packet.protocol === 'TCP') {
        readableText = "TLSv1.3 Handshake ClientHello SessionTicket Extension";
    } else {
        readableText = "ICMP PING ECHO REQUEST Payload-1029384756abcdefgh";
    }
    
    for (let i = 0; i < lines; i++) {
        const offset = (i * 16).toString(16).padStart(4, '0');
        let hexBytes = "";
        let asciiChars = "";
        
        for (let j = 0; j < 16; j++) {
            const charIdx = (i * 16) + j;
            let byteVal = 0;
            let charVal = ".";
            
            if (charIdx < readableText.length) {
                byteVal = readableText.charCodeAt(charIdx);
                charVal = readableText[charIdx];
                if (byteVal < 32 || byteVal > 126) charVal = ".";
            } else {
                // Random filler bytes
                byteVal = Math.floor(Math.random() * 256);
                charVal = byteVal >= 32 && byteVal <= 126 ? String.fromCharCode(byteVal) : ".";
            }
            
            hexBytes += byteVal.toString(16).padStart(2, '0') + " ";
            if (j === 7) hexBytes += " "; // Middle split gap
            asciiChars += charVal;
        }
        
        hexContent += `${offset}  ${hexBytes.padEnd(49, ' ')}  ${asciiChars}\n`;
    }
    
    dumpElem.innerText = hexContent;
}

// --- 4. FILTERS AND PATTERN FILTERING ---
function initPacketFilters() {
    const protoFilter = document.getElementById('packetProtoFilter');
    const searchFilter = document.getElementById('packetSearch');
    const suspiciousFilter = document.getElementById('packetSuspiciousOnly');
    
    const applyFilters = () => {
        const proto = protoFilter.value;
        const query = searchFilter.value.toLowerCase().trim();
        const suspiciousOnly = suspiciousFilter.checked;
        
        const rows = document.querySelectorAll('#packetsBody tr');
        
        rows.forEach(row => {
            const rowNo = row.getAttribute('data-no');
            const packet = packetList.find(p => p.no == rowNo);
            if (!packet) return;
            
            let show = true;
            
            // Protocol filter
            if (proto !== 'ALL') {
                if (proto === 'DNS' && packet.protocol !== 'DNS') show = false;
                else if (proto !== 'DNS' && packet.protocol !== proto) show = false;
            }
            
            // Suspicious filter
            if (suspiciousOnly && !packet.suspicious) {
                show = false;
            }
            
            // Text expression filter
            if (query && show) {
                const matchSrc = query.includes("ip.src") || query.includes("src");
                const matchDest = query.includes("ip.dst") || query.includes("dst");
                const matchPort = query.includes("port");
                
                // Extract search values
                const searchVal = query.replace(/(ip\.src|ip\.dst|src|dst|port|==|\s)/g, "");
                
                if (matchSrc) {
                    show = packet.source.toLowerCase().includes(searchVal);
                } else if (matchDest) {
                    show = packet.destination.toLowerCase().includes(searchVal);
                } else if (matchPort) {
                    show = packet.sport.includes(searchVal) || packet.dport.includes(searchVal);
                } else {
                    // Generic search
                    show = row.innerText.toLowerCase().includes(query);
                }
            }
            
            row.style.display = show ? '' : 'none';
        });
    };
    
    protoFilter.addEventListener('change', applyFilters);
    searchFilter.addEventListener('keyup', applyFilters);
    suspiciousFilter.addEventListener('change', applyFilters);
}

// --- 5. INSPECTOR VIEW SPLIT SWITCH ---
function initInspectorTabs() {
    const tabs = document.querySelectorAll('.inspector-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            const targetPane = tab.getAttribute('data-pane');
            document.getElementById('pane-frame-info').classList.add('hidden');
            document.getElementById('pane-hex-dump').classList.add('hidden');
            
            document.getElementById(`pane-${targetPane}`).classList.remove('hidden');
        });
    });
}
