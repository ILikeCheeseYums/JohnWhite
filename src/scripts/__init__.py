import argparse
import sys
from .recon import ReconAgent
from .vuln_analysis import VulnAnalysisAgent


def main() -> None:
    parser = argparse.ArgumentParser(
        description="John White - Multi-Agent Local LLM Automated Pentesting Framework"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Target base URL (default: http://localhost:3000)",
    )
    parser.add_argument(
        "--model",
        default="qwen3.5:0.8b",
        help="Ollama model to use (default: qwen3.5:0.8b)",
    )
    parser.add_argument(
        "--ollama-url",
        default="http://localhost:11434/api/generate",
        help="Ollama API endpoint",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Enable Stage 1 Playwright headless browser crawling & interception",
    )
    parser.add_argument(
        "--think",
        action="store_true",
        help="Enable deep chain-of-thought reasoning (slower, disabled by default for speed)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the interactive Web GUI wrapper in your browser",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address for Web GUI (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5050,
        help="Port to run Web GUI on (default: 5050)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not auto-open web browser when launching Web GUI",
    )
    args = parser.parse_args()

    if args.gui:
        from .web import run_web_gui
        run_web_gui(host=args.host, port=args.port, open_browser=not args.no_browser)
        return

    print("=" * 60)
    print(" John White: Automated Pentesting Bot")
    print(f" Target: {args.target}")
    print(f" Model:  {args.model}")
    print("=" * 60)

    # Instantiate Stage 1: Reconnaissance Agent
    print("\n[+] Stage 1: Initializing Reconnaissance Agent...")
    recon_agent = ReconAgent(base_url=args.target)

    # 1a. Fast HTTP probe sweep
    print("[*] Probing common routes...")
    scan_findings = recon_agent.quick_scan()
    for item in scan_findings:
        endpoint = item.get("endpoint", "")
        status = item.get("status_code", item.get("error", "Error"))
        print(f"    [Probe] {endpoint} -> Status: {status}")

    # 1b. Optional Headless browser crawl & interception
    browser_data = {}
    if args.browser:
        print("\n[*] Launching headless Chromium to intercept dynamic network traffic & forms...")
        browser_data = recon_agent.browser_crawl_and_intercept("/")
        req_count = browser_data.get("intercepted_requests_count", 0)
        forms_count = len(browser_data.get("extracted_forms", []))
        print(f"    [Browser] Intercepted {req_count} target requests, found {forms_count} forms.")

    # Instantiate Stage 2: Vulnerability Analysis Agent
    print("\n[+] Stage 2: Initializing Vulnerability Analysis Agent...")
    vuln_agent = VulnAnalysisAgent(
        recon_agent=recon_agent,
        ollama_url=args.ollama_url,
        model_name=args.model,
        keep_alive=-1,  # Keeps model pinned in memory across runs
        think=args.think,
    )

    # Interactive Stage 2 -> Stage 1 Querying:
    print("[*] Stage 2 determining if targeted follow-up probing is required from Stage 1...")
    follow_up_endpoints = vuln_agent.decide_follow_up_probes(scan_findings)

    follow_up_results = []
    if follow_up_endpoints:
        print(f"[*] Stage 2 requested additional probes for: {follow_up_endpoints}")
        for endpoint in follow_up_endpoints:
            res = recon_agent.probe_endpoint(endpoint)
            follow_up_results.append(res)
            print(f"    [Follow-up Probe] {endpoint} -> Status: {res.get('status_code', 'Error')}")
    else:
        print("[*] No follow-up probes requested; proceeding to report synthesis.")

    # Run complete Vulnerability Analysis
    recon_summary = {
        "http_probes": scan_findings,
        "browser_traffic": browser_data,
    }

    vuln_agent.analyze_vulnerabilities(
        recon_data=recon_summary,
        follow_up_findings=follow_up_results,
    )
    print("\n[+] Stages 1 & 2 Completed.")


if __name__ == "__main__":
    main()
