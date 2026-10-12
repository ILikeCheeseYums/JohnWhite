# John White
## An fully automated bot powered by Local LLMs for Pentesting and finding vulnerabilities
### It works in 4 Stages (currently works upto the 2nd Phase)
- **Reconnaissance** (the initial step is to send a agent capable of sending requests via  headless browsers and CLI tools and intercept the responses by the server and determine  possible flaws)

- **Vulnerabilities Analysis** the second step is for the 2nd ai agent to analyze the responses and think of what exact vulnerabilities are by analysis its similarity with previous commonly done mistakes and occasionally call the first agent to gather more specific information

- **Exploitation & Verification** The Agent then starts preparing for the follow up commands for the pentesting and executes it with human authorization 
- **Reporting & Remediation** After demonstrating and Confirming the vulnerabilities the AI then starts to give advice on how this can be fixed 
## Usage

### 1. Interactive Web GUI Wrapper

Launch the interactive Web GUI dashboard:

```bash
# Launch Web GUI (opens automatically at http://127.0.0.1:5050)
uv run scripts --gui

# Or using the dedicated scripts-gui command
uv run scripts-gui

# Custom port or headless server mode
uv run scripts --gui --port 8080 --no-browser
```

The Web GUI features:
- **Real-Time Live Feed:** Server-Sent Events (SSE) streaming logs, probe results, and AI thoughts.
- **Interactive Control Panel:** Target host selector, Ollama model auto-detection, and crawler toggles.
- **Pipeline Stage Visualizer:** Live progress tracking across Reconnaissance and Vulnerability Analysis.
- **Structured Findings View:** Filterable HTTP probe tables with header/body inspector, browser intercepted traffic, and form extractor.
- **Vulnerability Audit Report:** Full Markdown report preview, copy to clipboard, and one-click `.md` export.
- **Assessment History:** Session archives to reload and inspect previous scans.

### 2. Command-Line Interface (CLI)

Run the agent pipeline directly in your terminal:

```bash
# Basic run with HTTP probing and Stage 2 Vulnerability Analysis
uv run scripts --target http://localhost:3000

# Run with headless browser interception enabled (Playwright)
uv run scripts --target http://localhost:3000 --browser

# Specify a custom local Ollama model (default is fast lightweight qwen3.5:0.8b)
uv run scripts --model qwen3.5:0.8b
```

