# John White
## An fully automated bot powered by Local LLMs for Pentesting and finding vulnerabilities
### It works in 4 Stages (currently works upto the 2nd Phase)
- **Reconnaissance** (the initial step is to send a agent capable of sending requests via  headless browsers and CLI tools and intercept the responses by the server and determine  possible flaws)

- **Vulnerabilities Analysis** the second step is for the 2nd ai agent to analyze the responses and think of what exact vulnerabilities are by analysis its similarity with previous commonly done mistakes and occasionally call the first agent to gather more specific information

- **Exploitation & Verification** The Agent then starts preparing for the follow up commands for the pentesting and executes it with human authorization 
- **Reporting & Remediation** After demonstrating and Confirming the vulnerabilities the AI then starts to give advice on how this can be fixed 
## Usage

Run the agent pipeline using `uv`:

```bash
# Basic run with HTTP probing and Stage 2 Vulnerability Analysis
uv run scripts --target http://localhost:3000

# Run with headless browser interception enabled (Playwright)
uv run scripts --target http://localhost:3000 --browser

# Specify a custom local Ollama model
uv run scripts --model qwen3.5:9b
```
