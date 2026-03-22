// ==UserScript==
// @name         llmrt MCP Config Harvester
// @namespace    https://llmrt.io/
// @version      1.0.0
// @description  Harvests MCP server configurations from AI applications
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
        exportEndpoint: 'http://localhost:9999/api/mcp-configs',
        scanInterval: 5000, // ms
        patterns: {
            configFiles: [
                'mcp.json',
                'mcp-config.json',
                '.mcp/config.json',
                'claude_desktop_config.json',
                'cline_mcp_settings.json'
            ],
            mcpUrls: [
                /mcp:\/\/[^\s"']+/gi,
                /https?:\/\/[^\s"']+\/mcp[^\s"']*/gi,
                /ws:\/\/[^\s"']+\/mcp[^\s"']*/gi,
                /wss:\/\/[^\s"']+\/mcp[^\s"']*/gi
            ],
            toolPatterns: [
                /"tools":\s*\[/gi,
                /"resources":\s*\[/gi,
                /"prompts":\s*\[/gi,
                /"mcpServers":\s*{/gi
            ]
        }
    };

    let discoveredConfigs = [];
    let scannedElements = new Set();

    console.log('[llmrt] MCP Config Harvester loaded');

    // Scan page for MCP configurations
    function scanPage() {
        if (!CONFIG.enabled) return;

        // Scan script tags
        scanScripts();

        // Scan localStorage
        scanLocalStorage();

        // Scan sessionStorage
        scanSessionStorage();

        // Scan DOM for config data
        scanDOM();

        // Scan network requests
        scanNetworkRequests();
    }

    // Scan script tags
    function scanScripts() {
        const scripts = document.querySelectorAll('script');

        scripts.forEach(script => {
            if (scannedElements.has(script)) return;
            scannedElements.add(script);

            const content = script.textContent;
            if (!content) return;

            // Look for MCP patterns
            CONFIG.patterns.mcpUrls.forEach(pattern => {
                const matches = content.match(pattern);
                if (matches) {
                    matches.forEach(url => {
                        addDiscoveredConfig({
                            type: 'mcp_url',
                            source: 'script',
                            value: url,
                            context: content.substring(Math.max(0, content.indexOf(url) - 100), content.indexOf(url) + 100)
                        });
                    });
                }
            });

            // Look for tool definitions
            CONFIG.patterns.toolPatterns.forEach(pattern => {
                if (pattern.test(content)) {
                    try {
                        // Try to extract JSON
                        const jsonMatch = content.match(/\{[^{}]*"tools"[^{}]*\}/);
                        if (jsonMatch) {
                            addDiscoveredConfig({
                                type: 'tool_definition',
                                source: 'script',
                                value: jsonMatch[0]
                            });
                        }
                    } catch (e) {
                        console.warn('[llmrt] Failed to parse tool definition:', e);
                    }
                }
            });
        });
    }

    // Scan localStorage
    function scanLocalStorage() {
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                const value = localStorage.getItem(key);

                if (isMCPRelated(key) || isMCPRelated(value)) {
                    addDiscoveredConfig({
                        type: 'localStorage',
                        source: 'localStorage',
                        key: key,
                        value: value
                    });
                }
            }
        } catch (e) {
            console.warn('[llmrt] Failed to scan localStorage:', e);
        }
    }

    // Scan sessionStorage
    function scanSessionStorage() {
        try {
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                const value = sessionStorage.getItem(key);

                if (isMCPRelated(key) || isMCPRelated(value)) {
                    addDiscoveredConfig({
                        type: 'sessionStorage',
                        source: 'sessionStorage',
                        key: key,
                        value: value
                    });
                }
            }
        } catch (e) {
            console.warn('[llmrt] Failed to scan sessionStorage:', e);
        }
    }

    // Scan DOM
    function scanDOM() {
        // Look for data attributes
        const elements = document.querySelectorAll('[data-mcp], [data-config], [data-tools]');

        elements.forEach(el => {
            if (scannedElements.has(el)) return;
            scannedElements.add(el);

            const mcpData = el.dataset.mcp || el.dataset.config || el.dataset.tools;
            if (mcpData) {
                addDiscoveredConfig({
                    type: 'dom_attribute',
                    source: 'dom',
                    element: el.tagName,
                    value: mcpData
                });
            }
        });

        // Look for hidden inputs with config
        const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
        hiddenInputs.forEach(input => {
            if (scannedElements.has(input)) return;
            scannedElements.add(input);

            if (isMCPRelated(input.name) || isMCPRelated(input.value)) {
                addDiscoveredConfig({
                    type: 'hidden_input',
                    source: 'dom',
                    name: input.name,
                    value: input.value
                });
            }
        });
    }

    // Scan network requests
    function scanNetworkRequests() {
        // Intercept fetch
        const originalFetch = window.fetch;
        window.fetch = function (...args) {
            const url = args[0];

            if (isMCPRelated(url)) {
                addDiscoveredConfig({
                    type: 'network_request',
                    source: 'fetch',
                    url: url.toString(),
                    method: args[1]?.method || 'GET'
                });
            }

            return originalFetch.apply(this, args);
        };

        // Intercept XHR
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url, ...args) {
            if (isMCPRelated(url)) {
                addDiscoveredConfig({
                    type: 'network_request',
                    source: 'xhr',
                    url: url,
                    method: method
                });
            }

            return originalXHROpen.apply(this, [method, url, ...args]);
        };
    }

    // Check if string is MCP-related
    function isMCPRelated(str) {
        if (!str) return false;

        const lowerStr = str.toString().toLowerCase();
        const keywords = [
            'mcp',
            'model-context-protocol',
            'claude',
            'anthropic',
            'tool',
            'resource',
            'prompt',
            'server',
            'mcpServers'
        ];

        return keywords.some(keyword => lowerStr.includes(keyword));
    }

    // Add discovered config
    function addDiscoveredConfig(config) {
        config.timestamp = new Date().toISOString();
        config.url = window.location.href;

        // Check for duplicates
        const isDuplicate = discoveredConfigs.some(c =>
            c.type === config.type &&
            c.value === config.value
        );

        if (!isDuplicate) {
            discoveredConfigs.push(config);
            console.log('[llmrt] Discovered MCP config:', config);

            // Save to storage
            GM_setValue('llmrt_mcp_configs', JSON.stringify(discoveredConfigs));

            // Export to server
            exportConfig(config);

            // Update UI
            updatePanel();
        }
    }

    // Export config to llmrt server
    function exportConfig(config) {
        if (!CONFIG.exportEndpoint) return;

        GM_xmlhttpRequest({
            method: 'POST',
            url: CONFIG.exportEndpoint,
            headers: {
                'Content-Type': 'application/json'
            },
            data: JSON.stringify(config),
            onload: function (response) {
                if (response.status !== 200) {
                    console.warn('[llmrt] Failed to export config:', response.statusText);
                }
            },
            onerror: function (error) {
                console.warn('[llmrt] Export error:', error);
            }
        });
    }

    // Create UI panel
    function createPanel() {
        const panel = document.createElement('div');
        panel.id = 'llmrt-mcp-panel';
        panel.style.cssText = `
            position: fixed;
            top: 20px;
            left: 20px;
            width: 350px;
            max-height: 500px;
            background: #1e1e1e;
            color: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            font-family: monospace;
            font-size: 12px;
            z-index: 999999;
            overflow: hidden;
            display: none;
        `;

        panel.innerHTML = `
            <div style="padding: 10px; background: #2d2d2d; border-bottom: 1px solid #444;">
                <strong>🔌 llmrt MCP Harvester</strong>
                <button id="llmrt-mcp-close" style="float: right; background: #f44336; color: white; border: none; padding: 2px 8px; border-radius: 4px; cursor: pointer;">
                    ✕
                </button>
                <button id="llmrt-mcp-toggle" style="float: right; margin-right: 5px; background: #4CAF50; color: white; border: none; padding: 2px 8px; border-radius: 4px; cursor: pointer;">
                    ${CONFIG.enabled ? 'ON' : 'OFF'}
                </button>
            </div>
            <div id="llmrt-mcp-content" style="padding: 10px; max-height: 440px; overflow-y: auto;">
                <div id="llmrt-mcp-stats" style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
                    Discovered: <span id="llmrt-mcp-count" style="color: #4CAF50; font-weight: bold;">0</span> configs
                </div>
                <div id="llmrt-mcp-list"></div>
            </div>
        `;

        document.body.appendChild(panel);

        // Event listeners
        document.getElementById('llmrt-mcp-close').addEventListener('click', () => {
            panel.style.display = 'none';
        });

        document.getElementById('llmrt-mcp-toggle').addEventListener('click', function () {
            CONFIG.enabled = !CONFIG.enabled;
            this.textContent = CONFIG.enabled ? 'ON' : 'OFF';
            this.style.background = CONFIG.enabled ? '#4CAF50' : '#f44336';
        });
    }

    // Update panel
    function updatePanel() {
        const countEl = document.getElementById('llmrt-mcp-count');
        const listEl = document.getElementById('llmrt-mcp-list');

        if (countEl) {
            countEl.textContent = discoveredConfigs.length;
        }

        if (listEl) {
            listEl.innerHTML = discoveredConfigs.map(config => `
                <div style="margin-bottom: 8px; padding: 8px; background: #2d2d2d; border-radius: 4px; border-left: 3px solid #4CAF50;">
                    <div style="color: #4CAF50; font-weight: bold;">${config.type}</div>
                    <div style="font-size: 10px; color: #888;">Source: ${config.source}</div>
                    <div style="font-size: 10px; color: #ccc; margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        ${config.value ? config.value.substring(0, 100) : config.url}
                    </div>
                </div>
            `).join('');
        }
    }

    // Create toggle button
    function createToggleButton() {
        const button = document.createElement('button');
        button.textContent = '🔌';
        button.style.cssText = `
            position: fixed;
            bottom: 80px;
            right: 20px;
            width: 50px;
            height: 50px;
            background: #1e1e1e;
            color: white;
            border: 2px solid #4CAF50;
            border-radius: 50%;
            font-size: 24px;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            z-index: 999998;
        `;

        button.addEventListener('click', () => {
            const panel = document.getElementById('llmrt-mcp-panel');
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        });

        document.body.appendChild(button);
    }

    // Initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            createPanel();
            createToggleButton();
            scanPage();
        });
    } else {
        createPanel();
        createToggleButton();
        scanPage();
    }

    // Periodic scanning
    setInterval(scanPage, CONFIG.scanInterval);

    // Export API
    window.llmrt_mcp = {
        getConfigs: () => discoveredConfigs,
        clearConfigs: () => {
            discoveredConfigs = [];
            GM_setValue('llmrt_mcp_configs', '[]');
            updatePanel();
        },
        scan: scanPage,
        toggle: () => {
            CONFIG.enabled = !CONFIG.enabled;
            console.log('[llmrt] MCP Harvester', CONFIG.enabled ? 'enabled' : 'disabled');
        }
    };

    console.log('[llmrt] MCP Config Harvester ready. Access via window.llmrt_mcp');
})();
