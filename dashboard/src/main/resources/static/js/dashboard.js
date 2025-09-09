// ThreatX Dashboard JavaScript - Enhanced Version

/**
 * @fileoverview ThreatX Dashboard JavaScript with browser API support
 * @global fetch - Fetch API for HTTP requests (native browser API)
 * @global Chart - Chart.js library for data visualization
 * @global bootstrap - Bootstrap 5 JavaScript components
 */

/* global fetch, Chart, bootstrap */

// Fetch API polyfill for browser compatibility
(function() {
    'use strict';
    
    // Ensure fetch is available globally
    if (typeof window !== 'undefined' && typeof window.fetch === 'undefined') {
        console.warn('Fetch API not available, implementing XMLHttpRequest fallback');
        
        window.fetch = function(url, options) {
            return new Promise(function(resolve, reject) {
                const xhr = new XMLHttpRequest();
                const method = (options && options.method) || 'GET';
                
                xhr.open(method, url, true);
                
                // Set headers
                if (options && options.headers) {
                    for (const header in options.headers) {
                        xhr.setRequestHeader(header, options.headers[header]);
                    }
                }
                
                xhr.onload = function() {
                    if (xhr.status >= 200 && xhr.status < 300) {
                        resolve({
                            ok: true,
                            status: xhr.status,
                            statusText: xhr.statusText,
                            json: function() {
                                return Promise.resolve(JSON.parse(xhr.responseText));
                            },
                            text: function() {
                                return Promise.resolve(xhr.responseText);
                            }
                        });
                    } else {
                        reject(new Error('HTTP ' + xhr.status + ': ' + xhr.statusText));
                    }
                };
                
                xhr.onerror = function() {
                    reject(new Error('Network Error'));
                };
                
                xhr.ontimeout = function() {
                    reject(new Error('Request Timeout'));
                };
                
                // Send request
                if (options && options.body) {
                    xhr.send(options.body);
                } else {
                    xhr.send();
                }
            });
        };
    }
    
    // Ensure fetch is available in global scope for static analysis
    if (typeof fetch === 'undefined' && typeof window !== 'undefined' && window.fetch) {
        // Make fetch available globally
        globalThis.fetch = window.fetch;
    }
})();

// Global variables
let threatTimelineChart;
let threatTypesChart;
let realTimeData = {};
let updateInterval;
let notificationCount = 0;

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    setupEventListeners();
    startRealTimeUpdates();
    initializeTooltips();
    addNotificationBadge();
    initializeKeyboardShortcuts();
});

// Initialize dashboard components
function initializeDashboard() {
    console.log('Initializing ThreatX Dashboard...');
    
    // Add loading animations to cards
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.classList.add('fade-in');
    });
    
    // Load initial data
    loadDashboardData();
    
    // Add pulse animation to status indicator
    const statusIndicator = document.querySelector('.status-indicator');
    if (statusIndicator) {
        statusIndicator.classList.add('pulse');
    }
    
    // Initialize current time display
    updateCurrentTime();
    setInterval(updateCurrentTime, 1000);
}

// Setup event listeners
function setupEventListeners() {
    // Auto-refresh toggle
    const autoRefreshToggle = document.getElementById('autoRefreshToggle');
    if (autoRefreshToggle) {
        autoRefreshToggle.addEventListener('change', function() {
            if (this.checked) {
                startRealTimeUpdates();
                showNotification('Auto-refresh enabled', 'info');
            } else {
                stopRealTimeUpdates();
                showNotification('Auto-refresh disabled', 'warning');
            }
        });
    }
    
    // Time range selector
    const timeRangeSelector = document.getElementById('timeRangeSelector');
    if (timeRangeSelector) {
        timeRangeSelector.addEventListener('change', function() {
            loadThreatStatistics(this.value);
        });
    }
    
    // Refresh button
    const refreshButton = document.getElementById('refreshButton');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            refreshDashboard();
        });
    }
}

// Initialize tooltips
function initializeTooltips() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Add notification badge to navbar
function addNotificationBadge() {
    const navItems = document.querySelectorAll('.nav-item');
    if (navItems.length > 0) {
        // Add to threats nav item
        const threatsNavItem = navItems[2]; // Assuming threats is the 3rd item
        if (threatsNavItem) {
            const link = threatsNavItem.querySelector('a');
            if (link && !link.querySelector('.notification-badge')) {
                const badge = document.createElement('span');
                badge.className = 'badge bg-danger notification-badge';
                badge.textContent = '5';
                badge.style.fontSize = '0.6rem';
                badge.style.position = 'absolute';
                badge.style.top = '5px';
                badge.style.right = '5px';
                link.style.position = 'relative';
                link.appendChild(badge);
            }
        }
    }
}

// Show notification
function showNotification(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        // Create toast container if it doesn't exist
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.position = 'fixed';
        container.style.top = '20px';
        container.style.right = '20px';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }
    
    notificationCount++;
    const toastId = `toast-${notificationCount}`;
    
    const toastHTML = `
        <div id="${toastId}" class="toast fade show mb-2" role="alert" aria-live="assertive" aria-atomic="true" data-bs-delay="5000">
            <div class="toast-header bg-${type} text-white">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-triangle' : type === 'danger' ? 'exclamation-circle' : 'info-circle'} me-2"></i>
                <strong class="me-auto">ThreatX Notification</strong>
                <small class="text-white">Just now</small>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    document.getElementById('toastContainer').insertAdjacentHTML('beforeend', toastHTML);
    
    // Initialize and show toast
    const toastEl = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastEl);
    toast.show();
    
    // Auto remove after delay
    setTimeout(() => {
        if (toastEl) {
            toastEl.remove();
        }
    }, 5000);
}

// Load dashboard data
function loadDashboardData() {
    showLoadingState();
    
    Promise.all([
        loadThreatStatistics('24h'),
        loadSuspiciousIPs(),
        loadRecentThreats()
    ]).then(() => {
        hideLoadingState();
        console.log('Dashboard data loaded successfully');
        showNotification('Dashboard updated successfully', 'success');
    }).catch(error => {
        hideLoadingState();
        console.error('Error loading dashboard data:', error);
        showNotification('Error loading dashboard data', 'danger');
    });
}

// Load threat statistics
function loadThreatStatistics(timeRange = '24h') {
    return fetch(`/api/threat-statistics?range=${timeRange}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            updateThreatStatistics(data);
            updateThreatCharts(data);
            return data;
        })
        .catch(error => {
            console.error('Error loading threat statistics:', error);
            showNotification('Failed to load threat statistics', 'warning');
        });
}

// Load suspicious IPs
function loadSuspiciousIPs() {
    return fetch('/api/suspicious-ips?limit=10')
        .then(response => response.json())
        .then(data => {
            if (Array.isArray(data)) {
                updateSuspiciousIPsTable(data);
            }
            return data;
        })
        .catch(error => {
            console.error('Error loading suspicious IPs:', error);
            showNotification('Failed to load suspicious IPs', 'warning');
        });
}

// Load recent threats
function loadRecentThreats() {
    return fetch('/api/threat-statistics?range=24h')
        .then(response => response.json())
        .then(data => {
            if (data && data.timeline_data) {
                // Extract recent threats from timeline data
                const recentThreats = [];
                Object.keys(data.timeline_data).forEach(timestamp => {
                    const threatData = data.timeline_data[timestamp];
                    Object.keys(threatData).forEach(riskLevel => {
                        if (threatData[riskLevel] > 0) {
                            recentThreats.push({
                                analysis_timestamp: timestamp,
                                risk_level: riskLevel,
                                threat_count: threatData[riskLevel]
                            });
                        }
                    });
                });
                updateRecentThreatsTable(recentThreats);
            } else if (data && data.threat_categories) {
                // Handle the case where we get threat_categories instead of timeline_data
                const recentThreats = [];
                Object.keys(data.threat_categories).forEach(category => {
                    if (data.threat_categories[category] > 0) {
                        // Map categories to risk levels for display
                        let riskLevel = 'UNKNOWN';
                        if (category === 'DoS') {
                            riskLevel = 'HIGH';
                        } else if (category === 'Probe') {
                            riskLevel = 'MEDIUM';
                        } else if (category === 'Normal') {
                            riskLevel = 'LOW';
                        }
                        
                        recentThreats.push({
                            analysis_timestamp: data.generated_at || new Date().toISOString(),
                            risk_level: riskLevel,
                            threat_count: data.threat_categories[category],
                            threat_type: category
                        });
                    }
                });
                updateRecentThreatsTable(recentThreats);
            }
            return data;
        })
        .catch(error => {
            console.error('Error loading recent threats:', error);
            showNotification('Failed to load recent threats', 'warning');
        });
}

// Update threat statistics display
function updateThreatStatistics(data) {
    // Handle both formats - the new format from backend and the expected format
    const stats = data.threat_counts || data.threat_categories || {};
    const totalThreats = data.total_threats || data.recent_count || 0;
    const suspiciousIpsCount = data.suspicious_ips_count || (data.suspicious_ips ? data.suspicious_ips.length : 0);
    
    // Update stat cards with animation
    updateStatCard('totalThreats', totalThreats);
    updateStatCard('highRiskThreats', stats.HIGH || stats.DoS || 0);
    updateStatCard('mediumRiskThreats', stats.MEDIUM || 0);
    updateStatCard('suspiciousIPsCount', suspiciousIpsCount);
    
    // Update timestamp
    updateElement('lastUpdated', new Date().toLocaleString());
}

// Update stat card value with animation
function updateStatCard(cardId, value) {
    const element = document.getElementById(cardId);
    if (element) {
        const oldValue = parseInt(element.textContent) || 0;
        element.textContent = value;
        
        // Add animation class
        element.classList.add('pop-in');
        setTimeout(() => element.classList.remove('pop-in'), 500);
        
        // Show notification if significant change
        if (value > oldValue && oldValue > 0) {
            const diff = value - oldValue;
            showNotification(`Detected ${diff} new threats`, 'warning');
        }
    }
}

// Update threat charts
function updateThreatCharts(data) {
    // Handle both formats
    const timelineData = data.timeline_data || {};
    const threatTypes = data.top_threat_types || [];
    
    // If we don't have the expected format, try to convert from the backend format
    if (!data.timeline_data && data.threat_categories) {
        // Create a simple timeline data structure from threat categories
        const timestamp = new Date().toISOString();
        timelineData[timestamp] = data.threat_categories;
    }
    
    if (!data.top_threat_types && data.threat_categories) {
        // Convert threat categories to top threat types format
        Object.keys(data.threat_categories).forEach(category => {
            threatTypes.push({
                threat_type: category,
                count: data.threat_categories[category]
            });
        });
    }
    
    updateThreatTimelineChart(timelineData);
    updateThreatTypesChart(threatTypes);
}

// Update timeline chart
function updateThreatTimelineChart(timelineData) {
    const ctx = document.getElementById('threatTimelineChart');
    if (!ctx) return;
    
    if (threatTimelineChart) {
        threatTimelineChart.destroy();
    }
    
    const labels = [];
    const highRiskData = [];
    const mediumRiskData = [];
    const lowRiskData = [];
    
    if (timelineData) {
        Object.keys(timelineData).forEach(timestamp => {
            labels.push(formatTimestamp(timestamp));
            const data = timelineData[timestamp];
            highRiskData.push(data.HIGH || 0);
            mediumRiskData.push(data.MEDIUM || 0);
            lowRiskData.push(data.LOW || 0);
        });
    }
    
    threatTimelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'High Risk',
                data: highRiskData,
                borderColor: '#ef476f',
                backgroundColor: 'rgba(239, 71, 111, 0.1)',
                tension: 0.3,
                borderWidth: 3,
                pointRadius: 4,
                pointBackgroundColor: '#ef476f',
                fill: true
            }, {
                label: 'Medium Risk',
                data: mediumRiskData,
                borderColor: '#ffd166',
                backgroundColor: 'rgba(255, 209, 102, 0.1)',
                tension: 0.3,
                borderWidth: 3,
                pointRadius: 4,
                pointBackgroundColor: '#ffd166',
                fill: true
            }, {
                label: 'Low Risk',
                data: lowRiskData,
                borderColor: '#1b9aaa',
                backgroundColor: 'rgba(27, 154, 170, 0.1)',
                tension: 0.3,
                borderWidth: 3,
                pointRadius: 4,
                pointBackgroundColor: '#1b9aaa',
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: '#e2e8f0',
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: 'Threat Detection Timeline',
                    color: '#e2e8f0',
                    font: {
                        size: 14,
                        weight: 'bold'
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                },
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
}

// Update threat types chart
function updateThreatTypesChart(threatTypes) {
    const ctx = document.getElementById('threatTypesChart');
    if (!ctx) return;
    
    if (threatTypesChart) {
        threatTypesChart.destroy();
    }
    
    const labels = [];
    const data = [];
    const colors = ['#ef476f', '#ffd166', '#1b9aaa', '#06d6a0', '#6c757d'];
    
    if (threatTypes && Array.isArray(threatTypes)) {
        threatTypes.slice(0, 5).forEach((type, index) => {
            labels.push(type.threat_type || 'Unknown');
            data.push(type.count || 0);
        });
    }
    
    // Fill with default data if no threats
    if (labels.length === 0) {
        labels.push('No Threats Detected');
        data.push(1);
    }
    
    threatTypesChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderWidth: 0,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#e2e8f0',
                        font: {
                            size: 11
                        },
                        padding: 15
                    }
                }
            },
            cutout: '60%',
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1000
            }
        }
    });
}

// Update suspicious IPs table
function updateSuspiciousIPsTable(ips) {
    const tableBody = document.querySelector('#suspiciousIpsTable tbody');
    if (!tableBody) return;
    
    if (!ips || ips.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No suspicious IPs detected</td></tr>';
        return;
    }
    
    tableBody.innerHTML = ips.map(ip => `
        <tr class="fade-in">
            <td class="ip-address">${ip.ip_address || 'Unknown'}</td>
            <td>${ip.threat_count || 0}</td>
            <td>${ip.country_code || 'Unknown'}</td>
            <td>
                <span class="badge ${ip.is_blocked ? 'bg-warning' : 'bg-danger'}">
                    ${ip.is_blocked ? 'Blocked' : 'Active'}
                </span>
            </td>
        </tr>
    `).join('');
}

// Update recent threats table
function updateRecentThreatsTable(threats) {
    const tableBody = document.querySelector('#recentThreatsTable tbody');
    if (!tableBody) return;
    
    if (!threats || threats.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No recent threats</td></tr>';
        return;
    }
    
    tableBody.innerHTML = threats.map(threat => `
        <tr class="fade-in">
            <td class="timestamp">${formatTimestamp(threat.analysis_timestamp)}</td>
            <td>
                <span class="badge ${getRiskBadgeClass(threat.risk_level)}">
                    ${threat.risk_level || 'Unknown'}
                </span>
            </td>
            <td class="ip-address">${threat.ip_address || 'Unknown'}</td>
            <td>
                ${threat.threat_type || (threat.threat_types ? threat.threat_types.slice(0, 2).map(type => 
                    `<span class="threat-tag">${type}</span>`
                ).join(' ') : 'Unknown'}
            </td>
        </tr>
    `).join('');
}

// Get risk badge class
function getRiskBadgeClass(riskLevel) {
    switch (riskLevel) {
        case 'HIGH': return 'bg-danger';
        case 'MEDIUM': return 'bg-warning';
        case 'LOW': return 'bg-info';
        default: return 'bg-success';
    }
}

// Format timestamp
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Unknown';
    
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

// Start real-time updates
function startRealTimeUpdates() {
    if (updateInterval) clearInterval(updateInterval);
    
    updateInterval = setInterval(() => {
        loadDashboardData();
    }, 30000); // Update every 30 seconds
    
    console.log('Real-time updates started');
}

// Stop real-time updates
function stopRealTimeUpdates() {
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
    console.log('Real-time updates stopped');
}

// Refresh dashboard
function refreshDashboard() {
    showLoadingState();
    loadDashboardData();
    showNotification('Dashboard refreshed', 'info');
}

// Show loading state
function showLoadingState() {
    const loadingElements = document.querySelectorAll('.loading-placeholder');
    loadingElements.forEach(el => {
        el.innerHTML = '<div class="text-center"><div class="loading-spinner"></div> <span class="ms-2">Loading...</span></div>';
    });
    
    // Add loading state to refresh button
    const refreshBtn = document.getElementById('refreshButton');
    if (refreshBtn) {
        refreshBtn.innerHTML = '<i class="fas fa-sync fa-spin me-2"></i>Refreshing...';
        refreshBtn.disabled = true;
    }
}

// Hide loading state
function hideLoadingState() {
    // Restore refresh button
    const refreshBtn = document.getElementById('refreshButton');
    if (refreshBtn) {
        refreshBtn.innerHTML = '<i class="fas fa-sync-alt me-2"></i>Refresh Data';
        refreshBtn.disabled = false;
    }
}

// Update element content
function updateElement(id, content) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = content;
    }
}

// Update current time display
function updateCurrentTime() {
    const now = new Date();
    const timeDisplay = document.getElementById('currentTimeDisplay');
    if (timeDisplay) {
        timeDisplay.textContent = now.toLocaleString();
    }
}

// Test threat detection function
function testThreatDetection() {
    const modal = new bootstrap.Modal(document.getElementById('testDetectionModal'));
    modal.show();
}

// Run threat detection test
function runThreatDetectionTest() {
    const testData = {
        ip_address: document.getElementById('testIpAddress').value,
        user_id: document.getElementById('testUserId').value,
        failed_login_attempts: parseInt(document.getElementById('testFailedLogins').value),
        total_login_attempts: parseInt(document.getElementById('testFailedLogins').value) + 1,
        event_type: document.getElementById('testEventType').value,
        bytes_transferred: 1024,
        timestamp: new Date().toISOString()
    };

    const resultDiv = document.getElementById('testResult');
    resultDiv.innerHTML = '<div class="text-center"><div class="loading-spinner"></div> <span class="ms-2">Analyzing threat...</span></div>';

    fetch('/test-detection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(testData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            resultDiv.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>${data.error}</div>`;
            showNotification('Threat detection test failed', 'danger');
        } else {
            const riskBadge = getRiskBadgeClass(data.risk_level);
            
            resultDiv.innerHTML = `
                <div class="alert alert-success">
                    <h6 class="mb-3"><i class="fas fa-check-circle me-2"></i>Detection Result</h6>
                    <div class="row">
                        <div class="col-md-6">
                            <p class="mb-1"><strong>Risk Score:</strong> ${data.risk_score}</p>
                            <p class="mb-1"><strong>Risk Level:</strong> <span class="badge bg-${riskBadge}">${data.risk_level}</span></p>
                        </div>
                        <div class="col-md-6">
                            <p class="mb-1"><strong>Confidence:</strong> ${(data.confidence * 100).toFixed(1)}%</p>
                            <p class="mb-1"><strong>Threat Types:</strong> ${data.threat_types ? data.threat_types.join(', ') : 'None'}</p>
                        </div>
                    </div>
                    ${data.recommendations ? `
                    <hr>
                    <h6 class="mb-2"><i class="fas fa-lightbulb me-2"></i>Recommendations</h6>
                    <ul class="mb-0">
                        ${data.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                    ` : ''}
                </div>
            `;
            showNotification('Threat detection test completed', 'success');
        }
    })
    .catch(error => {
        resultDiv.innerHTML = `<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Error: ${error.message}</div>`;
        showNotification('Threat detection test error', 'danger');
    });
}

// Initialize keyboard shortcuts
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl+R or F5 to refresh
        if ((e.ctrlKey && e.key === 'r') || e.key === 'F5') {
            e.preventDefault();
            refreshDashboard();
        }
        
        // T for test detection
        if (e.key === 't' || e.key === 'T') {
            testThreatDetection();
        }
        
        // M for monitoring page
        if (e.key === 'm' || e.key === 'M') {
            window.location.href = '/monitoring';
        }
        
        // H for threats page
        if (e.key === 'h' || e.key === 'H') {
            window.location.href = '/threats';
        }
        
        // U for users page
        if (e.key === 'u' || e.key === 'U') {
            window.location.href = '/users';
        }
    });
}

// Export functions for global access
window.ThreatXDashboard = {
    testThreatDetection,
    runThreatDetectionTest,
    refreshDashboard,
    startRealTimeUpdates,
    stopRealTimeUpdates
};

// Handle page visibility changes
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        stopRealTimeUpdates();
    } else {
        startRealTimeUpdates();
        loadDashboardData(); // Refresh data when page becomes visible
    }
});

// Handle window resize events for responsive charts
window.addEventListener('resize', function() {
    // Debounce resize events
    clearTimeout(window.resizeTimeout);
    window.resizeTimeout = setTimeout(function() {
        // Update chart sizes if they exist
        if (typeof threatTimelineChart !== 'undefined' && threatTimelineChart) {
            threatTimelineChart.resize();
        }
        if (typeof threatTypesChart !== 'undefined' && threatTypesChart) {
            threatTypesChart.resize();
        }
        // Add more chart resize calls as needed for other pages
    }, 250);
});

// Handle orientation change for mobile devices
window.addEventListener('orientationchange', function() {
    // Give the browser time to adjust layout
    setTimeout(function() {
        // Trigger resize event to update charts
        window.dispatchEvent(new Event('resize'));
        
        // Adjust any mobile-specific UI elements
        adjustMobileUI();
    }, 300);
});

// Adjust UI for mobile devices
function adjustMobileUI() {
    const isMobile = window.innerWidth <= 768;
    const isLandscape = window.innerHeight < window.innerWidth;
    
    // Adjust chart heights for mobile landscape
    if (isMobile && isLandscape) {
        const chartAreas = document.querySelectorAll('.chart-area, .chart-pie');
        chartAreas.forEach(chart => {
            chart.style.height = '200px';
        });
    }
    
    // Toggle mobile-specific classes
    document.body.classList.toggle('mobile-view', isMobile);
    document.body.classList.toggle('landscape', isLandscape);
    
    // Adjust navbar for mobile
    const navbar = document.querySelector('.navbar-collapse');
    if (navbar && isMobile) {
        // Ensure navbar is properly collapsed on mobile
        const bsCollapse = new bootstrap.Collapse(navbar, {
            toggle: false
        });
        // Only collapse if it's not already collapsed
        if (navbar.classList.contains('show')) {
            bsCollapse.hide();
        }
    }
}

// Initialize mobile UI adjustments
document.addEventListener('DOMContentLoaded', function() {
    adjustMobileUI();
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    stopRealTimeUpdates();
});

console.log('ThreatX Dashboard JavaScript loaded successfully');