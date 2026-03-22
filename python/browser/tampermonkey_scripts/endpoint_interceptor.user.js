// ==UserScript==
// @name         llmrt Endpoint Interceptor
// @namespace    https://llmrt.io/
// @version      1.0.0
// @description  Intercepts and logs API endpoints for AI applications
// @author       llmrt
// @match        *://*/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_xmlhttpRequest
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    // Configuration
    const CONFIG = {
        enabled: true,
        logToConsole: true,
        exportEndpoint: 'http://localhost:9999/api/endpoints',
        captureHeaders: true,
        captureBody: true,
        maxBodySize: 10000, // bytes
        aiEndpointPatterns: [
            '/chat',
            '/completion',
            '/generate',
            '/v1/messages',
            '/api/chat',
            '/inference',
            '/predict',
            '/query'
        ]
    };

    // Storage for intercepted endpoints
    let interceptedEndpoints = [];

    // Initialize
    console.log('[llmrt] Endpoint Interceptor loaded');

    // Intercept XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function (method, url, ...args) {
        this._llmrt_method = method;
        this._llmrt_url = url;
        return originalXHROpen.apply(this, [method, url, ...args]);
    };

    XMLHttpRequest.prototype.send = function (body) {
        if (CONFIG.enabled && isAIEndpoint(this._llmrt_url)) {
            const endpoint = {
                timestamp: new Date().toISOString(),
                method: this._llmrt_method,
                url: this._llmrt_url,
                type: 'xhr',
                headers: {},
                requestBody: null,
                responseBody: null,
                statusCode: null
            };

            // Capture request headers
            if (CONFIG.captureHeaders) {
                try {
                    const requestHeaders = this.getAllResponseHeaders();
                    endpoint.headers = parseHeaders(requestHeaders);
                } catch (e) {
                    console.warn('[llmrt] Failed to capture headers:', e);
                }
            }

            // Capture request body
            if (CONFIG.captureBody && body) {
                endpoint.requestBody = truncateBody(body);
            }

            // Capture response
            this.addEventListener('load', function () {
                endpoint.statusCode = this.status;
                if (CONFIG.captureBody) {
                    endpoint.responseBody = truncateBody(this.responseText);
                }
                logEndpoint(endpoint);
            });

            this.addEventListener('error', function () {
                endpoint.statusCode = 0;
                endpoint.error = 'Request failed';
                logEndpoint(endpoint);
            });
        }

        return originalXHRSend.apply(this, arguments);
    };

    // Intercept Fetch API
    const originalFetch = window.fetch;
    window.fetch = function (url, options = {}) {
        if (CONFIG.enabled && isAIEndpoint(url)) {
            const endpoint = {
                timestamp: new Date().toISOString(),
                method: options.method || 'GET',
                url: url.toString(),
                type: 'fetch',
                headers: {},
                requestBody: null,
                responseBody: null,
                statusCode: null
            };

            // Capture request headers
            if (CONFIG.captureHeaders && options.headers) {
                endpoint.headers = options.headers;
            }

            // Capture request body
            if (CONFIG.captureBody && options.body) {
                endpoint.requestBody = truncateBody(options.body);
            }

            // Call original fetch and capture response
            return originalFetch.apply(this, arguments)
                .then(response => {
                    endpoint.statusCode = response.status;

                    // Clone response to read body
                    if (CONFIG.captureBody) {
                        const clonedResponse = response.clone();
                        clonedResponse.text().then(text => {
                            endpoint.responseBody = truncateBody(text);
                            logEndpoint(endpoint);
                        }).catch(e => {
                            console.warn('[llmrt] Failed to read response body:', e);
                            logEndpoint(endpoint);
                        });
                    } else {
                        logEndpoint(endpoint);
                    }

                    return response;
                })
                .catch(error => {
                    endpoint.statusCode = 0;
                    endpoint.error = error.message;
                    logEndpoint(endpoint);
                    throw error;
                });
        }

        return originalFetch.apply(this, arguments);
    };

    // Helper: Check if URL is AI endpoint
    function isAIEndpoint(url) {
        const urlStr = url.toString().toLowerCase();
        return CONFIG.aiEndpointPatterns.some(pattern => urlStr.includes(pattern));
    }

    // Helper: Parse headers string
    function parseHeaders(headersStr) {
        const headers = {};
        if (!headersStr) return headers;

        headersStr.split('\r\n').forEach(line => {
            const parts = line.split(': ');
            if (parts.length === 2) {
                headers[parts[0]] = parts[1];
            }
        });

        return headers;
    }

    // Helper: Truncate body to max size
    function truncateBody(body) {
        if (!body) return null;

        const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);

        if (bodyStr.length > CONFIG.maxBodySize) {
            return bodyStr.substring(0, CONFIG.maxBodySize) + '... [truncated]';
        }

        return bodyStr;
    }

    // Helper: Log endpoint
    function logEndpoint(endpoint) {
        interceptedEndpoints.push(endpoint);

        if (CONFIG.logToConsole) {
            console.log('[llmrt] Intercepted endpoint:', endpoint);
        }

        // Save to storage
        GM_setValue('llmrt_endpoints', JSON.stringify(interceptedEndpoints));

        // Export to llmrt server
        exportEndpoint(endpoint);
    }

    // Helper: Export endpoint to llmrt server
    function exportEndpoint(endpoint) {
        if (!CONFIG.exportEndpoint) return;

        GM_xmlhttpRequest({
            method: 'POST',
            url: CONFIG.exportEndpoint,
            headers: {
                'Content-Type': 'application/json'
            },
            data: JSON.stringify(endpoint),
            onload: function (response) {
                if (response.status !== 200) {
                    console.warn('[llmrt] Failed to export endpoint:', response.statusText);
                }
            },
            onerror: function (error) {
                console.warn('[llmrt] Export error:', error);
            }
        });
    }

    // Add UI panel
    function createPanel() {
        const panel = document.createElement('div');
        panel.id = 'llmrt-panel';
        panel.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 300px;
            max-height: 400px;
            background: #1e1e1e;
            color: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            font-family: monospace;
            font-size: 12px;
            z-index: 999999;
            overflow: hidden;
        `;

        panel.innerHTML = `
            <div style="padding: 10px; background: #2d2d2d; border-bottom: 1px solid #444;">
                <strong>🛡️ llmrt Endpoint Interceptor</strong>
                <button id="llmrt-toggle" style="float: right; background: #4CAF50; color: white; border: none; padding: 2px 8px; border-radius: 4px; cursor: pointer;">
                    ${CONFIG.enabled ? 'ON' : 'OFF'}
                </button>
            </div>
            <div id="llmrt-content" style="padding: 10px; max-height: 340px; overflow-y: auto;">
                <div id="llmrt-stats" style="margin-bottom: 10px;">
                    Intercepted: <span id="llmrt-count">0</span> endpoints
                </div>
                <div id="llmrt-list"></div>
            </div>
        `;

        document.body.appendChild(panel);

        // Toggle button
        document.getElementById('llmrt-toggle').addEventListener('click', function () {
            CONFIG.enabled = !CONFIG.enabled;
            this.textContent = CONFIG.enabled ? 'ON' : 'OFF';
            this.style.background = CONFIG.enabled ? '#4CAF50' : '#f44336';
        });

        // Update panel periodically
        setInterval(updatePanel, 1000);
    }

    // Update panel content
    function updatePanel() {
        const countEl = document.getElementById('llmrt-count');
        const listEl = document.getElementById('llmrt-list');

        if (countEl) {
            countEl.textContent = interceptedEndpoints.length;
        }

        if (listEl) {
            const recent = interceptedEndpoints.slice(-5).reverse();
            listEl.innerHTML = recent.map(ep => `
                <div style="margin-bottom: 8px; padding: 8px; background: #2d2d2d; border-radius: 4px; border-left: 3px solid ${ep.statusCode >= 200 && ep.statusCode < 300 ? '#4CAF50' : '#f44336'};">
                    <div><strong>${ep.method}</strong> ${ep.statusCode || '?'}</div>
                    <div style="font-size: 10px; color: #888; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        ${ep.url}
                    </div>
                </div>
            `).join('');
        }
    }

    // Initialize panel when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', createPanel);
    } else {
        createPanel();
    }

    // Export function for manual access
    window.llmrt = {
        getEndpoints: () => interceptedEndpoints,
        clearEndpoints: () => {
            interceptedEndpoints = [];
            GM_setValue('llmrt_endpoints', '[]');
        },
        exportAll: () => {
            interceptedEndpoints.forEach(exportEndpoint);
        },
        toggle: () => {
            CONFIG.enabled = !CONFIG.enabled;
            console.log('[llmrt] Interceptor', CONFIG.enabled ? 'enabled' : 'disabled');
        }
    };

    console.log('[llmrt] Endpoint Interceptor ready. Access via window.llmrt');
})();
