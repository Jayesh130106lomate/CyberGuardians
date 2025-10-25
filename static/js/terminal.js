// terminal.js - Terminal management and streaming
class TerminalModule {
    constructor(core) {
        this.core = core;
        this.eventSource = null;
        this.isConnected = false;
        this.init();
    }

    init() {
        this.setupTerminal();
        this.connectToTerminalStream();
        this.setupEventListeners();
    }

    setupTerminal() {
        const terminal = document.getElementById('terminalBody');
        if (terminal) {
            terminal.innerHTML = '<div class="terminal-line terminal-info">🎯 Terminal ready. Waiting for scan...</div>';
        }
    }

    connectToTerminalStream() {
        if (this.eventSource) {
            this.eventSource.close();
        }

        try {
            this.eventSource = new EventSource('/api/terminal-stream');

            this.eventSource.onopen = () => {
                this.isConnected = true;
                console.log('Terminal stream connected');
            };

            this.eventSource.onmessage = (event) => {
                const data = JSON.parse(event.data);

                if (data.output) {
                    this.addTerminalLine(data.output, data.type || 'info');
                }

                if (data.done) {
                    this.addTerminalLine('✓ Scan completed', 'success');
                }
            };

            this.eventSource.onerror = (error) => {
                console.error('Terminal stream error:', error);
                this.isConnected = false;
                this.addTerminalLine('⚠️ Terminal connection lost', 'error');
            };

        } catch (error) {
            console.error('Failed to connect to terminal stream:', error);
            this.addTerminalLine('❌ Failed to connect to terminal stream', 'error');
        }
    }

    addTerminalLine(text, type = 'info') {
        const terminal = document.getElementById('terminalBody');
        if (!terminal) return;

        // Create line element
        const line = document.createElement('div');
        line.className = `terminal-line terminal-${type}`;

        // Add timestamp for better UX
        const timestamp = new Date().toLocaleTimeString();
        line.innerHTML = `<span class="terminal-timestamp">[${timestamp}]</span> ${this.escapeHtml(text)}`;

        // Add to terminal
        terminal.appendChild(line);

        // Auto scroll to bottom
        this.scrollToBottom();

        // Limit lines to prevent memory issues (keep last 1000 lines)
        this.limitTerminalLines(1000);
    }

    scrollToBottom() {
        const terminal = document.getElementById('terminalBody');
        if (terminal) {
            terminal.scrollTop = terminal.scrollHeight;
        }
    }

    limitTerminalLines(maxLines) {
        const terminal = document.getElementById('terminalBody');
        if (!terminal) return;

        const lines = terminal.querySelectorAll('.terminal-line');
        if (lines.length > maxLines) {
            const excess = lines.length - maxLines;
            for (let i = 0; i < excess; i++) {
                lines[i].remove();
            }
        }
    }

    clearTerminal() {
        const terminal = document.getElementById('terminalBody');
        if (terminal) {
            terminal.innerHTML = '<div class="terminal-line terminal-info">🧹 Terminal cleared</div>';
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    disconnect() {
        if (this.eventSource) {
            this.eventSource.close();
            this.isConnected = false;
        }
    }

    setupEventListeners() {
        // Clear terminal button
        const clearBtn = document.getElementById('clearTerminal');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.clearTerminal();
            });
        }

        // Scroll to bottom button
        const scrollBtn = document.getElementById('scrollTerminal');
        if (scrollBtn) {
            scrollBtn.addEventListener('click', () => {
                this.scrollToBottom();
            });
        }
    }
}

// Export for module system
window.TerminalModule = TerminalModule;