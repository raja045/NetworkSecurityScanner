// Network Security Scanner Application
class NetSecScanPro {
    constructor() {
        this.isScanning = false;
        this.scanProgress = 0;
        this.currentScan = null;
        this.scanResults = [];
        this.scanStartTime = null;
        
        // Common ports and services data
        this.commonPorts = [
            {port: 21, service: "FTP", description: "File Transfer Protocol"},
            {port: 22, service: "SSH", description: "Secure Shell"},
            {port: 23, service: "Telnet", description: "Telnet Protocol"},
            {port: 25, service: "SMTP", description: "Simple Mail Transfer Protocol"},
            {port: 53, service: "DNS", description: "Domain Name System"},
            {port: 80, service: "HTTP", description: "Hypertext Transfer Protocol"},
            {port: 110, service: "POP3", description: "Post Office Protocol v3"},
            {port: 143, service: "IMAP", description: "Internet Message Access Protocol"},
            {port: 443, service: "HTTPS", description: "HTTP Secure"},
            {port: 993, service: "IMAPS", description: "IMAP over SSL"},
            {port: 995, service: "POP3S", description: "POP3 over SSL"},
            {port: 1433, service: "MSSQL", description: "Microsoft SQL Server"},
            {port: 3306, service: "MySQL", description: "MySQL Database"},
            {port: 3389, service: "RDP", description: "Remote Desktop Protocol"},
            {port: 5432, service: "PostgreSQL", description: "PostgreSQL Database"},
            {port: 5900, service: "VNC", description: "Virtual Network Computing"},
            {port: 8080, service: "HTTP-ALT", description: "HTTP Alternate"}
        ];

        this.vulnerabilities = [
            {cve: "CVE-2021-44228", description: "Apache Log4j RCE", severity: "Critical", cvss: 10.0},
            {cve: "CVE-2017-0144", description: "EternalBlue SMB Vulnerability", severity: "Critical", cvss: 8.1},
            {cve: "CVE-2021-34527", description: "PrintNightmare", severity: "High", cvss: 8.8},
            {cve: "CVE-2020-1472", description: "Zerologon", severity: "Critical", cvss: 10.0},
            {cve: "CVE-2019-0708", description: "BlueKeep RDP Vulnerability", severity: "Critical", cvss: 9.8},
            {cve: "CVE-2021-26855", description: "Microsoft Exchange SSRF", severity: "High", cvss: 9.1},
            {cve: "CVE-2020-14882", description: "Oracle WebLogic RCE", severity: "Critical", cvss: 9.8}
        ];

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupTabNavigation();
        this.setupFormHandlers();
        this.logMessage("NetSecScan Pro initialized and ready for scanning.", "info");
    }

    setupEventListeners() {
        // Tab navigation - Fixed selector issue
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                const tabName = tab.getAttribute('data-tab');
                this.switchTab(tabName);
            });
        });

        // Scan controls
        const startBtn = document.getElementById('start-scan');
        const stopBtn = document.getElementById('stop-scan');
        const clearLogBtn = document.getElementById('clear-log');
        const exportBtn = document.getElementById('export-results');
        const searchInput = document.getElementById('results-search');

        if (startBtn) startBtn.addEventListener('click', () => this.startScan());
        if (stopBtn) stopBtn.addEventListener('click', () => this.stopScan());
        if (clearLogBtn) clearLogBtn.addEventListener('click', () => this.clearLog());
        if (exportBtn) exportBtn.addEventListener('click', () => this.exportResults());
        if (searchInput) searchInput.addEventListener('input', (e) => this.filterResults(e.target.value));

        // Thread count range slider
        const threadSlider = document.getElementById('thread-count');
        const threadValue = document.getElementById('thread-count-value');
        if (threadSlider && threadValue) {
            threadSlider.addEventListener('input', (e) => {
                threadValue.textContent = e.target.value;
            });
        }
    }

    setupTabNavigation() {
        // Set initial active tab
        this.switchTab('scanner');
    }

    setupFormHandlers() {
        // Port range selection handler
        const portRangeSelect = document.getElementById('port-range');
        if (portRangeSelect) {
            portRangeSelect.addEventListener('change', (e) => {
                const customPorts = document.getElementById('custom-ports');
                if (customPorts) {
                    if (e.target.value === 'custom') {
                        customPorts.style.display = 'block';
                    } else {
                        customPorts.style.display = 'none';
                    }
                }
            });
        }
    }

    switchTab(tabName) {
        console.log('Switching to tab:', tabName); // Debug log
        
        // Remove active class from all tabs and content
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('nav-tab--active');
        });
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('tab-content--active');
        });

        // Add active class to selected tab and content
        const selectedTab = document.querySelector(`[data-tab="${tabName}"]`);
        const selectedContent = document.getElementById(`${tabName}-tab`);
        
        if (selectedTab) {
            selectedTab.classList.add('nav-tab--active');
        }
        if (selectedContent) {
            selectedContent.classList.add('tab-content--active');
        }
    }

    generateIPRange(target) {
        const ips = [];
        
        if (target.includes('/')) {
            // CIDR notation
            const [baseIP, prefixLength] = target.split('/');
            const prefix = parseInt(prefixLength);
            const [a, b, c, d] = baseIP.split('.').map(Number);
            
            if (prefix >= 24) {
                // /24 or smaller - scan last octet
                const numHosts = Math.min(50, 254); // Limit to reasonable number for demo
                
                for (let i = 1; i <= numHosts; i++) {
                    ips.push(`${a}.${b}.${c}.${i}`);
                }
            } else {
                // Larger networks - sample some IPs
                for (let i = 1; i <= 20; i++) {
                    ips.push(`${a}.${b}.${c}.${i}`);
                }
            }
        } else if (target.includes('-')) {
            // IP range like 192.168.1.1-192.168.1.50
            const [startIP, endIP] = target.split('-');
            const [, , , startOctet] = startIP.split('.').map(Number);
            const [a, b, c, endOctet] = endIP.split('.').map(Number);
            
            for (let i = startOctet; i <= endOctet && ips.length < 50; i++) {
                ips.push(`${a}.${b}.${c}.${i}`);
            }
        } else {
            // Single IP
            ips.push(target);
        }
        
        return ips;
    }

    async startScan() {
        if (this.isScanning) return;

        const target = document.getElementById('target-input').value.trim();
        const portRange = document.getElementById('port-range').value;
        const scanType = document.getElementById('scan-type').value;
        const scanSpeed = document.getElementById('scan-speed').value;
        const threadCount = document.getElementById('thread-count').value;
        const timeout = document.getElementById('timeout').value;

        if (!target) {
            this.logMessage("Error: Please specify a target to scan.", "error");
            return;
        }

        this.isScanning = true;
        this.scanProgress = 0;
        this.scanStartTime = Date.now();
        this.scanResults = [];

        // Update UI
        const startBtn = document.getElementById('start-scan');
        const stopBtn = document.getElementById('stop-scan');
        const scanStatus = document.getElementById('scan-status');

        if (startBtn) startBtn.style.display = 'none';
        if (stopBtn) stopBtn.style.display = 'block';
        if (scanStatus) {
            scanStatus.textContent = 'Scanning';
            scanStatus.classList.add('scanning-animation');
        }

        // Reset counters
        this.updateCounters(0, 0, 0);
        this.updateProgress();

        this.logMessage(`Starting ${scanType} scan on ${target}`, "info");
        this.logMessage(`Configuration: Port range=${portRange}, Speed=${scanSpeed}, Threads=${threadCount}, Timeout=${timeout}s`, "info");

        try {
            const targetIPs = this.generateIPRange(target);
            const ports = this.getPortsToScan(portRange);
            
            this.logMessage(`Generated ${targetIPs.length} target(s) and ${ports.length} port(s) to scan`, "info");
            
            await this.performScan(targetIPs, ports, scanType, scanSpeed);
            
        } catch (error) {
            this.logMessage(`Scan error: ${error.message}`, "error");
        }

        this.completeScan();
    }

    getPortsToScan(portRange) {
        switch (portRange) {
            case 'common':
                return this.commonPorts.map(p => p.port);
            case 'all':
                // Return a subset for demo purposes
                return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080];
            case 'custom':
                const customInput = document.getElementById('custom-port-input');
                if (customInput && customInput.value) {
                    return this.parseCustomPorts(customInput.value);
                }
                return this.commonPorts.map(p => p.port);
            default:
                return this.commonPorts.map(p => p.port);
        }
    }

    parseCustomPorts(input) {
        const ports = [];
        const parts = input.split(',');
        
        parts.forEach(part => {
            part = part.trim();
            if (part.includes('-')) {
                const [start, end] = part.split('-').map(Number);
                for (let i = start; i <= end && i <= 65535; i++) {
                    ports.push(i);
                }
            } else {
                const port = parseInt(part);
                if (port > 0 && port <= 65535) {
                    ports.push(port);
                }
            }
        });
        
        return [...new Set(ports)]; // Remove duplicates
    }

    async performScan(targetIPs, ports, scanType, scanSpeed) {
        const totalTargets = targetIPs.length;
        let hostsScanned = 0;
        let totalOpenPorts = 0;
        let totalVulnerabilities = 0;

        const speedMultiplier = this.getScanSpeedMultiplier(scanSpeed);

        for (const ip of targetIPs) {
            if (!this.isScanning) break;

            const currentTargetElement = document.getElementById('current-target');
            if (currentTargetElement) {
                currentTargetElement.textContent = ip;
            }
            
            this.logMessage(`Scanning host ${ip}...`, "info");

            const hostResult = {
                ip: ip,
                hostname: this.generateHostname(ip),
                status: 'unknown',
                openPorts: [],
                os: 'Unknown',
                riskLevel: 'low',
                responseTime: 0,
                vulnerabilities: []
            };

            // Simulate host discovery
            await this.delay(200 * speedMultiplier);
            
            const isHostUp = Math.random() > 0.4; // 60% chance host is up
            
            if (isHostUp) {
                hostResult.status = 'up';
                hostResult.responseTime = Math.floor(Math.random() * 100) + 10;
                this.logMessage(`Host ${ip} is up (${hostResult.responseTime}ms)`, "success");

                // Scan ports on this host
                const portsToScan = ports.slice(0, Math.floor(Math.random() * 8) + 3); // Random subset for variety
                
                for (const port of portsToScan) {
                    if (!this.isScanning) break;

                    await this.delay(100 * speedMultiplier);

                    const isPortOpen = this.simulatePortScan(port, scanType);
                    
                    if (isPortOpen) {
                        const service = this.getServiceInfo(port);
                        const portInfo = {
                            port: port,
                            service: service.service,
                            version: this.generateServiceVersion(service.service),
                            state: 'open',
                            banner: this.generateBanner(service.service)
                        };
                        
                        hostResult.openPorts.push(portInfo);
                        totalOpenPorts++;
                        this.logMessage(`${ip}:${port} (${service.service}) - OPEN`, "success");

                        // Check for vulnerabilities
                        if (Math.random() > 0.7) { // 30% chance of vulnerability
                            const vuln = this.vulnerabilities[Math.floor(Math.random() * this.vulnerabilities.length)];
                            hostResult.vulnerabilities.push({...vuln, port: port, service: service.service});
                            totalVulnerabilities++;
                            this.logMessage(`Vulnerability found on ${ip}:${port} - ${vuln.cve}`, "warning");
                        }
                    }
                }

                // Determine risk level based on open ports and vulnerabilities
                hostResult.riskLevel = this.calculateRiskLevel(hostResult);
                hostResult.os = this.generateOSFingerprint();

                this.scanResults.push(hostResult);

            } else {
                hostResult.status = 'down';
                this.logMessage(`Host ${ip} appears to be down`, "info");
            }

            hostsScanned++;
            this.scanProgress = (hostsScanned / totalTargets) * 100;
            
            // Update progress and counters
            this.updateProgress();
            this.updateCounters(hostsScanned, totalOpenPorts, totalVulnerabilities);
            
            // Update results display in real-time
            this.updateResultsDisplay();
        }
    }

    updateCounters(hosts, ports, vulns) {
        const hostsElement = document.getElementById('hosts-scanned');
        const portsElement = document.getElementById('ports-found');
        const vulnsElement = document.getElementById('vulnerabilities-found');
        
        if (hostsElement) hostsElement.textContent = hosts;
        if (portsElement) portsElement.textContent = ports;
        if (vulnsElement) vulnsElement.textContent = vulns;
    }

    simulatePortScan(port, scanType) {
        // Different scan types have different success rates
        let baseChance = 0.15; // 15% base chance port is open
        
        // Common ports are more likely to be open
        if (this.commonPorts.some(p => p.port === port)) {
            baseChance = 0.35; // 35% for common ports
        }
        
        // Very common ports even more likely
        if ([80, 443, 22, 21].includes(port)) {
            baseChance = 0.55; // 55% for very common ports
        }

        // Scan type affects detection
        switch (scanType) {
            case 'tcp-syn':
                return Math.random() < baseChance;
            case 'tcp-connect':
                return Math.random() < baseChance * 0.9;
            case 'udp':
                return Math.random() < baseChance * 0.4;
            case 'comprehensive':
                return Math.random() < baseChance * 1.3;
            case 'vulnerability':
                return Math.random() < baseChance * 1.1;
            default:
                return Math.random() < baseChance;
        }
    }

    getServiceInfo(port) {
        const service = this.commonPorts.find(p => p.port === port);
        return service || {port: port, service: 'unknown', description: 'Unknown service'};
    }

    generateServiceVersion(service) {
        const versions = {
            'HTTP': ['Apache/2.4.41', 'nginx/1.18.0', 'IIS/10.0', 'Apache/2.2.15'],
            'HTTPS': ['Apache/2.4.41 (OpenSSL/1.1.1)', 'nginx/1.18.0', 'IIS/10.0'],
            'SSH': ['OpenSSH_7.4', 'OpenSSH_8.0p1', 'OpenSSH_6.6.1'],
            'FTP': ['vsftpd 3.0.3', 'ProFTPD 1.3.6', 'Microsoft ftpd'],
            'SMTP': ['Postfix smtpd', 'Microsoft ESMTP 6.0.3790.4675', 'Exim smtpd 4.92']
        };
        
        const serviceVersions = versions[service] || ['Unknown'];
        return serviceVersions[Math.floor(Math.random() * serviceVersions.length)];
    }

    generateBanner(service) {
        const banners = {
            'HTTP': '200 OK Server: Apache/2.4.41',
            'HTTPS': '200 OK Server: Apache/2.4.41 (OpenSSL/1.1.1)',
            'SSH': 'SSH-2.0-OpenSSH_7.4',
            'FTP': '220 Welcome to FTP server',
            'SMTP': '220 mail.example.com ESMTP Postfix'
        };
        
        return banners[service] || `${service} service detected`;
    }

    generateOSFingerprint() {
        const os = ['Windows 10', 'Windows Server 2019', 'Ubuntu 20.04', 'CentOS 7', 'RedHat Enterprise Linux 8', 'FreeBSD 12.2', 'macOS 11.6'];
        return os[Math.floor(Math.random() * os.length)];
    }

    generateHostname(ip) {
        const domains = ['example.com', 'corp.local', 'internal.net', 'server.lan'];
        const prefixes = ['web', 'mail', 'db', 'app', 'srv', 'host'];
        
        if (Math.random() > 0.4) {
            const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
            const domain = domains[Math.floor(Math.random() * domains.length)];
            return `${prefix}${Math.floor(Math.random() * 99) + 1}.${domain}`;
        }
        
        return ''; // No hostname resolved
    }

    calculateRiskLevel(hostResult) {
        let riskScore = 0;
        
        // Open ports increase risk
        riskScore += hostResult.openPorts.length * 10;
        
        // Vulnerabilities significantly increase risk
        hostResult.vulnerabilities.forEach(vuln => {
            if (vuln.severity === 'Critical') riskScore += 100;
            else if (vuln.severity === 'High') riskScore += 70;
            else if (vuln.severity === 'Medium') riskScore += 40;
            else riskScore += 20;
        });
        
        // Dangerous services increase risk
        const dangerousPorts = [21, 23, 135, 139, 445, 1433, 3389];
        hostResult.openPorts.forEach(portInfo => {
            if (dangerousPorts.includes(portInfo.port)) {
                riskScore += 30;
            }
        });
        
        if (riskScore >= 100) return 'critical';
        if (riskScore >= 70) return 'high';
        if (riskScore >= 30) return 'medium';
        return 'low';
    }

    getScanSpeedMultiplier(speed) {
        const multipliers = {
            'paranoid': 3,
            'sneaky': 2,
            'polite': 1.5,
            'normal': 1,
            'aggressive': 0.6,
            'insane': 0.3
        };
        return multipliers[speed] || 1;
    }

    updateProgress() {
        const progressFill = document.getElementById('progress-fill');
        const progressPercent = document.getElementById('progress-percent');
        const progressEta = document.getElementById('progress-eta');
        
        if (progressFill) {
            progressFill.style.width = `${this.scanProgress}%`;
        }
        if (progressPercent) {
            progressPercent.textContent = `${Math.round(this.scanProgress)}%`;
        }
        
        // Calculate ETA
        if (progressEta && this.scanStartTime && this.scanProgress > 5) {
            const elapsed = Date.now() - this.scanStartTime;
            const totalEstimated = (elapsed / this.scanProgress) * 100;
            const remaining = totalEstimated - elapsed;
            
            if (remaining > 0) {
                const minutes = Math.floor(remaining / 60000);
                const seconds = Math.floor((remaining % 60000) / 1000);
                progressEta.textContent = `ETA: ${minutes}:${seconds.toString().padStart(2, '0')}`;
            } else {
                progressEta.textContent = 'ETA: Almost done';
            }
        }
    }

    updateResultsDisplay() {
        const tbody = document.getElementById('results-tbody');
        const summary = document.getElementById('results-summary');
        
        if (!tbody) return;
        
        if (this.scanResults.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-state">
                    <td colspan="7">
                        <div class="empty-state__content">
                            <svg width="48" height="48" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M3 5a2 2 0 012-2h10a2 2 0 012 2v8a2 2 0 01-2 2h-2.22l.123.489.804.804A1 1 0 0113 18H7a1 1 0 01-.707-1.707l.804-.804L7.22 15H5a2 2 0 01-2-2V5zm5.771 7H5V5h10v7H8.771z" clip-rule="evenodd"/>
                            </svg>
                            <h3>No scan results available</h3>
                            <p>Start a scan to see network security results here.</p>
                        </div>
                    </td>
                </tr>
            `;
            if (summary) summary.style.display = 'none';
            return;
        }
        
        // Show summary
        if (summary) {
            summary.style.display = 'block';
            
            const summaryHosts = document.getElementById('summary-hosts');
            const summaryPorts = document.getElementById('summary-ports');
            const summaryCritical = document.getElementById('summary-critical');
            const summaryHigh = document.getElementById('summary-high');
            
            if (summaryHosts) summaryHosts.textContent = this.scanResults.length;
            
            const totalPorts = this.scanResults.reduce((sum, host) => sum + host.openPorts.length, 0);
            if (summaryPorts) summaryPorts.textContent = totalPorts;
            
            const criticalHosts = this.scanResults.filter(host => host.riskLevel === 'critical').length;
            if (summaryCritical) summaryCritical.textContent = criticalHosts;
            
            const highRiskHosts = this.scanResults.filter(host => host.riskLevel === 'high').length;
            if (summaryHigh) summaryHigh.textContent = highRiskHosts;
        }
        
        // Populate results table
        tbody.innerHTML = this.scanResults.map(host => `
            <tr>
                <td><code>${host.ip}</code></td>
                <td>${host.hostname || '—'}</td>
                <td>
                    <div class="host-status host-status--${host.status}">
                        <div class="host-status__dot"></div>
                        ${host.status.toUpperCase()}
                        ${host.responseTime ? ` (${host.responseTime}ms)` : ''}
                    </div>
                </td>
                <td>
                    <div class="port-list">
                        ${host.openPorts.slice(0, 5).map(port => 
                            `<span class="port-badge">${port.port}/${port.service}</span>`
                        ).join('')}
                        ${host.openPorts.length > 5 ? `<span class="port-badge">+${host.openPorts.length - 5} more</span>` : ''}
                    </div>
                </td>
                <td>${host.os}</td>
                <td><span class="risk-level risk-level--${host.riskLevel}">${host.riskLevel}</span></td>
                <td>
                    <button class="btn btn--sm btn--outline" onclick="app.showHostDetails('${host.ip}')">
                        Details
                    </button>
                </td>
            </tr>
        `).join('');
    }

    filterResults(query) {
        const tbody = document.getElementById('results-tbody');
        if (!tbody) return;
        
        const rows = tbody.querySelectorAll('tr:not(.empty-state)');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            const match = text.includes(query.toLowerCase());
            row.style.display = match ? '' : 'none';
        });
    }

    showHostDetails(ip) {
        const host = this.scanResults.find(h => h.ip === ip);
        if (!host) return;
        
        let details = `Host Details: ${host.ip}\n\n`;
        details += `Hostname: ${host.hostname || 'N/A'}\n`;
        details += `Status: ${host.status}\n`;
        details += `OS: ${host.os}\n`;
        details += `Response Time: ${host.responseTime}ms\n`;
        details += `Risk Level: ${host.riskLevel.toUpperCase()}\n\n`;
        
        if (host.openPorts.length > 0) {
            details += `Open Ports (${host.openPorts.length}):\n`;
            host.openPorts.forEach(port => {
                details += `  ${port.port}/${port.service} - ${port.version}\n`;
            });
        }
        
        if (host.vulnerabilities.length > 0) {
            details += `\nVulnerabilities (${host.vulnerabilities.length}):\n`;
            host.vulnerabilities.forEach(vuln => {
                details += `  ${vuln.cve} - ${vuln.description} (${vuln.severity})\n`;
            });
        }
        
        alert(details);
    }

    stopScan() {
        this.isScanning = false;
        this.completeScan();
        this.logMessage("Scan stopped by user", "warning");
    }

    completeScan() {
        this.isScanning = false;
        
        // Update UI
        const startBtn = document.getElementById('start-scan');
        const stopBtn = document.getElementById('stop-scan');
        const scanStatus = document.getElementById('scan-status');
        const currentTarget = document.getElementById('current-target');
        
        if (startBtn) startBtn.style.display = 'block';
        if (stopBtn) stopBtn.style.display = 'none';
        if (scanStatus) {
            scanStatus.textContent = 'Complete';
            scanStatus.classList.remove('scanning-animation');
        }
        if (currentTarget) currentTarget.textContent = '—';
        
        const duration = this.scanStartTime ? ((Date.now() - this.scanStartTime) / 1000).toFixed(1) : 0;
        this.logMessage(`Scan completed in ${duration} seconds. Found ${this.scanResults.length} hosts.`, "success");
        
        // Switch to results tab if we have results
        if (this.scanResults.length > 0) {
            this.switchTab('results');
        }
    }

    exportResults() {
        if (this.scanResults.length === 0) {
            alert('No scan results to export.');
            return;
        }
        
        // Create CSV data
        let csv = 'IP Address,Hostname,Status,Open Ports,OS,Risk Level,Vulnerabilities\n';
        
        this.scanResults.forEach(host => {
            const openPorts = host.openPorts.map(p => `${p.port}/${p.service}`).join(';');
            const vulnerabilities = host.vulnerabilities.map(v => v.cve).join(';');
            
            csv += `"${host.ip}","${host.hostname}","${host.status}","${openPorts}","${host.os}","${host.riskLevel}","${vulnerabilities}"\n`;
        });
        
        // Download CSV
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `netscan-results-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        this.logMessage("Results exported to CSV file", "success");
    }

    clearLog() {
        const logContainer = document.getElementById('scan-log');
        if (logContainer) {
            logContainer.innerHTML = `
                <div class="log-entry">
                    <span class="log-time">[Ready]</span>
                    <span class="log-message">NetSecScan Pro initialized and ready for scanning.</span>
                </div>
            `;
        }
    }

    logMessage(message, type = 'info') {
        const logContainer = document.getElementById('scan-log');
        if (!logContainer) return;
        
        const timestamp = new Date().toLocaleTimeString();
        
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-entry--${type}`;
        logEntry.innerHTML = `
            <span class="log-time">[${timestamp}]</span>
            <span class="log-message">${message}</span>
        `;
        
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize the application
let app;

// Wait for DOM to be ready
document.addEventListener('DOMContentLoaded', () => {
    app = new NetSecScanPro();
    
    // Add tooltips or help text
    const helpTexts = {
        'target-input': 'Examples: 192.168.1.1, 10.0.0.0/24, 172.16.1.1-172.16.1.100',
        'scan-type': 'TCP SYN is fastest and most stealthy, Comprehensive provides most complete results',
        'scan-speed': 'Slower speeds are more stealthy and thorough, faster speeds may miss some services'
    };
    
    Object.entries(helpTexts).forEach(([id, text]) => {
        const element = document.getElementById(id);
        if (element) {
            element.title = text;
        }
    });
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (!app) return;
        
        // Ctrl+Enter to start scan
        if (e.ctrlKey && e.key === 'Enter') {
            if (!app.isScanning) {
                app.startScan();
            }
        }
        
        // Escape to stop scan
        if (e.key === 'Escape' && app.isScanning) {
            app.stopScan();
        }
    });
});