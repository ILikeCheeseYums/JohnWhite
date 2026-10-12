import argparse
from datetime import datetime
import json
import logging
from pathlib import Path
import queue
import re
import socketserver
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import requests

from .recon import ReconAgent
from .vuln_analysis import VulnAnalysisAgent

logger = logging.getLogger("johnwhite.web")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
SCANS_DIR = Path.cwd() / "scans"
SCANS_DIR.mkdir(parents=True, exist_ok=True)


class ScanManager:
    """Thread-safe manager for orchestrating scans, streaming SSE updates,

    and archiving results.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.subscribers: List[queue.Queue] = []
        self.current_scan: Optional[Dict[str, Any]] = None
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None

    def add_subscriber(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=500)
        with self._lock:
            self.subscribers.append(q)
        return q

    def remove_subscriber(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def broadcast(self, event_type: str, data: Any) -> None:
        message = json.dumps({"event": event_type, "data": data})
        dead_queues = []
        with self._lock:
            for q in self.subscribers:
                try:
                    q.put_nowait(message)
                except queue.Full:
                    dead_queues.append(q)
            for dq in dead_queues:
                if dq in self.subscribers:
                    self.subscribers.remove(dq)

    def log(self, message: str, level: str = "INFO") -> None:
        log_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        }
        with self._lock:
            if self.current_scan:
                self.current_scan["logs"].append(log_entry)
        self.broadcast("log", log_entry)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            if not self.current_scan:
                return {
                    "status": "idle",
                    "scan_id": None,
                    "target": None,
                    "model": None,
                    "stage": "idle",
                    "progress": 0,
                    "counts": {
                        "probes": 0,
                        "probes_2xx": 0,
                        "probes_err": 0,
                        "intercepted": 0,
                        "forms": 0,
                        "follow_ups": 0,
                    },
                }
            return {
                "status": self.current_scan.get("status", "idle"),
                "scan_id": self.current_scan.get("scan_id"),
                "target": self.current_scan.get("target"),
                "model": self.current_scan.get("model"),
                "stage": self.current_scan.get("stage", "idle"),
                "stage_title": self.current_scan.get("stage_title", ""),
                "progress": self.current_scan.get("progress", 0),
                "started_at": self.current_scan.get("started_at"),
                "elapsed": round(
                    time.time() - self.current_scan.get("start_ts", time.time()), 1
                ),
                "counts": self.current_scan.get("counts", {}),
            }

    def get_current_scan_snapshot(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self.current_scan:
                return None
            return dict(self.current_scan)

    def start_scan(
        self,
        target: str,
        model: str = "qwen3.5:0.8b",
        ollama_url: str = "http://localhost:11434/api/generate",
        use_browser: bool = False,
        think: bool = False,
        custom_paths: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            if self.current_scan and self.current_scan.get("status") == "running":
                return {"error": "A scan is already in progress. Stop it first."}

            scan_id = datetime.now().strftime("scan_%Y%m%d_%H%M%S")
            self.stop_event.clear()

            self.current_scan = {
                "scan_id": scan_id,
                "status": "running",
                "stage": "init",
                "stage_title": "Initializing Assessment Agents",
                "progress": 5,
                "target": target.rstrip("/"),
                "model": model,
                "ollama_url": ollama_url,
                "use_browser": use_browser,
                "think": think,
                "custom_paths": custom_paths or [],
                "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "start_ts": time.time(),
                "finished_at": None,
                "probes": [],
                "browser_data": {},
                "follow_up_endpoints": [],
                "follow_up_results": [],
                "thinking_stream": "",
                "report_stream": "",
                "logs": [],
                "counts": {
                    "probes": 0,
                    "probes_2xx": 0,
                    "probes_err": 0,
                    "intercepted": 0,
                    "forms": 0,
                    "follow_ups": 0,
                },
                "error": None,
            }

        self.broadcast("scan_started", self.get_status())
        self.log(f"Started pentest assessment for target: {target}")
        self.log(f"Configured Ollama Model: {model} ({ollama_url})")

        self.worker_thread = threading.Thread(
            target=self._run_scan_thread,
            args=(scan_id, target, model, ollama_url, use_browser, think, custom_paths),
            daemon=True,
        )
        self.worker_thread.start()

        return {"status": "started", "scan_id": scan_id}

    def stop_scan(self) -> Dict[str, Any]:
        with self._lock:
            if not self.current_scan or self.current_scan.get("status") != "running":
                return {"status": "not_running"}
            self.stop_event.set()
            self.current_scan["status"] = "stopping"
            self.current_scan["stage_title"] = "Stopping Assessment..."

        self.log("Cancellation signal received. Stopping gracefully...", "WARN")
        self.broadcast("scan_stopping", self.get_status())
        return {"status": "stopping"}

    def _update_stage(self, stage: str, stage_title: str, progress: int) -> None:
        with self._lock:
            if self.current_scan:
                self.current_scan["stage"] = stage
                self.current_scan["stage_title"] = stage_title
                self.current_scan["progress"] = progress
        self.broadcast(
            "stage_changed",
            {"stage": stage, "stage_title": stage_title, "progress": progress},
        )
        self.log(f"[{stage.upper()}] {stage_title}")

    def _run_scan_thread(
        self,
        scan_id: str,
        target: str,
        model: str,
        ollama_url: str,
        use_browser: bool,
        think: bool,
        custom_paths: Optional[List[str]],
    ) -> None:
        try:
            # Stage 1: Reconnaissance
            self._update_stage(
                "recon", "Stage 1: Probing attack surface routes...", 15
            )

            recon_agent = ReconAgent(base_url=target)

            def on_probe_finding(res: Dict[str, Any]):
                with self._lock:
                    if not self.current_scan:
                        return
                    self.current_scan["probes"].append(res)
                    self.current_scan["counts"]["probes"] += 1
                    status = res.get("status_code", 0)
                    if isinstance(status, int) and 200 <= status < 300:
                        self.current_scan["counts"]["probes_2xx"] += 1
                    elif "error" in res or (isinstance(status, int) and status >= 400):
                        self.current_scan["counts"]["probes_err"] += 1

                endpoint = res.get("endpoint", "")
                status_desc = res.get("status_code", res.get("error", "Error"))
                self.log(f"[Probe] {endpoint} -> Status: {status_desc}")
                self.broadcast("probe_finding", res)

            scan_findings = recon_agent.quick_scan(
                custom_paths=custom_paths if custom_paths else None,
                on_probe=on_probe_finding,
                should_stop=self.stop_event.is_set,
            )

            if self.stop_event.is_set():
                self._handle_stopped(scan_id)
                return

            # Stage 1b: Browser Crawl
            browser_data = {}
            if use_browser:
                self._update_stage(
                    "browser",
                    "Stage 1b: Headless Chromium network interception & form discovery...",
                    35,
                )

                def on_intercept(item: Dict[str, Any]):
                    with self._lock:
                        if self.current_scan:
                            self.current_scan["counts"]["intercepted"] += 1
                    self.broadcast("browser_traffic_intercepted", item)

                browser_data = recon_agent.browser_crawl_and_intercept(
                    start_path="/",
                    wait_time_ms=3000,
                    on_intercept=on_intercept,
                    should_stop=self.stop_event.is_set,
                )

                req_count = browser_data.get("intercepted_requests_count", 0)
                forms = browser_data.get("extracted_forms", [])
                with self._lock:
                    if self.current_scan:
                        self.current_scan["browser_data"] = browser_data
                        self.current_scan["counts"]["forms"] = len(forms)

                self.log(
                    f"[Browser Crawl] Intercepted {req_count} requests, extracted {len(forms)} forms."
                )
                self.broadcast("browser_completed", browser_data)

            if self.stop_event.is_set():
                self._handle_stopped(scan_id)
                return

            # Stage 2a: AI Follow-Up Decisions
            self._update_stage(
                "llm_followup",
                "Stage 2a: Querying AI Agent for follow-up probe paths...",
                50,
            )

            def on_log_from_vuln(msg: str):
                self.log(msg)

            vuln_agent = VulnAnalysisAgent(
                recon_agent=recon_agent,
                ollama_url=ollama_url,
                model_name=model,
                keep_alive=-1,
                think=think,
                on_log=on_log_from_vuln,
                should_stop=self.stop_event.is_set,
            )

            follow_up_endpoints = vuln_agent.decide_follow_up_probes(scan_findings)
            with self._lock:
                if self.current_scan:
                    self.current_scan["follow_up_endpoints"] = follow_up_endpoints
                    self.current_scan["counts"]["follow_ups"] = len(
                        follow_up_endpoints
                    )

            self.broadcast("follow_ups_decided", follow_up_endpoints)

            follow_up_results = []
            if follow_up_endpoints:
                self._update_stage(
                    "follow_up_probes",
                    f"Stage 2a: Executing targeted deep probes for {len(follow_up_endpoints)} endpoints...",
                    65,
                )
                self.log(f"Agent requested deeper probes: {follow_up_endpoints}")
                for ep in follow_up_endpoints:
                    if self.stop_event.is_set():
                        break
                    res = recon_agent.probe_endpoint(ep, timeout=8)
                    follow_up_results.append(res)
                    with self._lock:
                        if self.current_scan:
                            self.current_scan["follow_up_results"].append(res)
                    self.log(
                        f"[Follow-up Probe] {ep} -> Status: {res.get('status_code', 'Error')}"
                    )
                    self.broadcast("follow_up_result", res)
            else:
                self.log("Agent decided no further route probes needed.")

            if self.stop_event.is_set():
                self._handle_stopped(scan_id)
                return

            # Stage 2b: AI Vulnerability Synthesis
            self._update_stage(
                "vuln_analysis",
                "Stage 2b: Synthesizing comprehensive Vulnerability Audit Report...",
                80,
            )

            recon_summary = {
                "http_probes": scan_findings,
                "browser_traffic": browser_data,
            }

            def on_token_received(token: str, is_thinking: bool):
                with self._lock:
                    if not self.current_scan:
                        return
                    if is_thinking:
                        self.current_scan["thinking_stream"] += token
                    else:
                        self.current_scan["report_stream"] += token

                self.broadcast(
                    "stream_token", {"token": token, "is_thinking": is_thinking}
                )

            vuln_agent.on_token = on_token_received

            report = vuln_agent.analyze_vulnerabilities(
                recon_data=recon_summary,
                follow_up_findings=follow_up_results,
            )

            if self.stop_event.is_set():
                self._handle_stopped(scan_id)
                return

            # Complete
            duration = round(time.time() - self.current_scan["start_ts"], 1)
            with self._lock:
                if self.current_scan:
                    self.current_scan["status"] = "completed"
                    self.current_scan["stage"] = "completed"
                    self.current_scan["stage_title"] = "Assessment Completed Successfully"
                    self.current_scan["progress"] = 100
                    self.current_scan["finished_at"] = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    self.current_scan["report"] = report

            self.log(f"Pentest completed in {duration}s. Report generated.")
            self._save_scan_archive(self.current_scan)
            self.broadcast("scan_completed", self.current_scan)

        except Exception as exc:
            logger.exception("Error during scan execution")
            err_text = str(exc)
            with self._lock:
                if self.current_scan:
                    self.current_scan["status"] = "error"
                    self.current_scan["error"] = err_text
                    self.current_scan["stage_title"] = f"Error: {err_text}"
            self.log(f"Scan failed with error: {err_text}", "ERROR")
            self.broadcast("scan_error", {"error": err_text})

    def _handle_stopped(self, scan_id: str) -> None:
        with self._lock:
            if self.current_scan:
                self.current_scan["status"] = "stopped"
                self.current_scan["stage"] = "stopped"
                self.current_scan["stage_title"] = "Assessment Stopped by User"
                self.current_scan["finished_at"] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
        self.log("Assessment terminated by user.", "WARN")
        self._save_scan_archive(self.current_scan)
        self.broadcast("scan_stopped", self.get_status())

    def _save_scan_archive(self, scan_data: Optional[Dict[str, Any]]) -> None:
        if not scan_data:
            return
        try:
            scan_id = scan_data.get("scan_id", "scan_latest")
            json_file = SCANS_DIR / f"{scan_id}.json"
            md_file = SCANS_DIR / f"{scan_id}.md"

            # Clean copy for json
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(scan_data, f, indent=2, ensure_ascii=False)

            report_text = scan_data.get("report_stream") or scan_data.get("report") or ""
            with open(md_file, "w", encoding="utf-8") as f:
                f.write(
                    f"# John White Pentest Audit Report - {scan_data.get('target')}\n\n"
                    f"- **Scan ID:** `{scan_id}`\n"
                    f"- **Model:** `{scan_data.get('model')}`\n"
                    f"- **Date:** {scan_data.get('started_at')}\n"
                    f"- **Endpoints Probed:** {scan_data.get('counts', {}).get('probes', 0)}\n\n"
                    f"---\n\n"
                    f"{report_text}\n"
                )
        except Exception as e:
            logger.error("Failed to archive scan: %s", e)

    def list_saved_scans(self) -> List[Dict[str, Any]]:
        results = []
        for file in sorted(SCANS_DIR.glob("*.json"), reverse=True):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    results.append({
                        "scan_id": data.get("scan_id", file.stem),
                        "target": data.get("target"),
                        "model": data.get("model"),
                        "status": data.get("status"),
                        "started_at": data.get("started_at"),
                        "finished_at": data.get("finished_at"),
                        "counts": data.get("counts", {}),
                    })
            except Exception:
                pass
        return results

    def get_saved_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        target_file = SCANS_DIR / f"{scan_id}.json"
        if not target_file.exists():
            return None
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None


scan_manager = ScanManager()


class WebGUIHandler(SimpleHTTPRequestHandler):
    """Custom HTTP Request Handler serving the Web GUI dashboard, REST APIs,

    and Server-Sent Events stream.
    """

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        url_parsed = urllib.parse.urlparse(self.path)
        path = url_parsed.path

        if path == "/":
            return self._serve_index()

        if path == "/api/status":
            return self._send_json(scan_manager.get_status())

        if path == "/api/scan/current":
            snapshot = scan_manager.get_current_scan_snapshot()
            if snapshot:
                return self._send_json(snapshot)
            return self._send_json({"status": "idle"})

        if path == "/api/scan/stream":
            return self._handle_sse_stream()

        if path == "/api/ollama/models":
            return self._handle_get_ollama_models(url_parsed.query)

        if path == "/api/scans":
            return self._send_json(scan_manager.list_saved_scans())

        if path == "/api/report/out":
            out_file = Path.cwd() / "out.md"
            if out_file.exists():
                raw = out_file.read_text(encoding="utf-8", errors="replace")
                if "[Analysis Output]" in raw:
                    parts = raw.split("[Analysis Output]", 1)
                    thinking = parts[0].replace("[Thinking]", "").strip()
                    report = parts[1].strip()
                else:
                    thinking = ""
                    report = raw.strip()
                return self._send_json({"exists": True, "thinking": thinking, "report": report})
            return self._send_json({"exists": False, "thinking": "", "report": ""})

        match = re.match(r"^/api/scans/([^/]+)$", path)
        if match:
            scan_id = match.group(1)
            data = scan_manager.get_saved_scan(scan_id)
            if data:
                return self._send_json(data)
            return self._send_error_json(404, "Scan not found")

        match_rep = re.match(r"^/api/scans/([^/]+)/report$", path)
        if match_rep:
            scan_id = match_rep.group(1)
            md_file = SCANS_DIR / f"{scan_id}.md"
            if md_file.exists():
                content = md_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{scan_id}.md"'
                )
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            return self._send_error_json(404, "Report file not found")

        # Static file fallback
        static_file = STATIC_DIR / path.lstrip("/")
        if static_file.is_file() and static_file.resolve().is_relative_to(STATIC_DIR.resolve()):
            content_type = self.guess_type(str(static_file))
            try:
                data = static_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            except Exception:
                pass

        self._send_error_json(404, "Not Found")

    def do_POST(self):
        url_parsed = urllib.parse.urlparse(self.path)
        path = url_parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except json.JSONDecodeError:
            payload = {}

        if path == "/api/scan/start":
            target = payload.get("target", "http://localhost:3000")
            model = payload.get("model", "qwen3.5:0.8b")
            ollama_url = payload.get(
                "ollama_url", "http://localhost:11434/api/generate"
            )
            use_browser = bool(payload.get("browser", False))
            think = bool(payload.get("think", False))
            custom_paths = payload.get("custom_paths", [])

            res = scan_manager.start_scan(
                target=target,
                model=model,
                ollama_url=ollama_url,
                use_browser=use_browser,
                think=think,
                custom_paths=custom_paths,
            )
            if "error" in res:
                return self._send_json(res, status=400)
            return self._send_json(res)

        if path == "/api/scan/stop":
            return self._send_json(scan_manager.stop_scan())

        if path == "/api/target/check":
            target = payload.get("target", "")
            if not target:
                return self._send_error_json(400, "Target URL is required")
            try:
                resp = requests.get(target, timeout=4)
                return self._send_json({
                    "reachable": True,
                    "status_code": resp.status_code,
                    "server": resp.headers.get("Server", "Unknown"),
                    "title": (
                        re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE).group(1)
                        if re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                        else ""
                    ),
                })
            except Exception as e:
                return self._send_json({"reachable": False, "error": str(e)})

        if path == "/api/ollama/test":
            ollama_url = payload.get(
                "ollama_url", "http://localhost:11434/api/generate"
            )
            base_url = ollama_url.split("/api/")[0]
            try:
                resp = requests.get(f"{base_url}/api/version", timeout=3)
                if resp.status_code == 200:
                    return self._send_json({
                        "connected": True,
                        "version": resp.json().get("version", "unknown"),
                    })
                return self._send_json({
                    "connected": False,
                    "status_code": resp.status_code,
                })
            except Exception as e:
                return self._send_json({"connected": False, "error": str(e)})

        self._send_error_json(404, "Endpoint not found")

    def _handle_sse_stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        event_queue = scan_manager.add_subscriber()

        # Send initial snapshot sync
        snapshot = scan_manager.get_current_scan_snapshot()
        init_payload = {
            "event": "sync",
            "data": snapshot if snapshot else {"status": "idle"},
        }
        try:
            self.wfile.write(f"data: {json.dumps(init_payload)}\n\n".encode("utf-8"))
            self.wfile.flush()
        except Exception:
            scan_manager.remove_subscriber(event_queue)
            return

        try:
            while True:
                try:
                    message = event_queue.get(timeout=15.0)
                    self.wfile.write(f"data: {message}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # Keep-alive heartbeat
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            scan_manager.remove_subscriber(event_queue)

    def _handle_get_ollama_models(self, query_str: str):
        qs = urllib.parse.parse_qs(query_str)
        endpoint = qs.get(
            "endpoint", ["http://localhost:11434/api/generate"]
        )[0]
        base_url = endpoint.split("/api/")[0]

        try:
            resp = requests.get(f"{base_url}/api/tags", timeout=4)
            if resp.status_code == 200:
                models_data = resp.json().get("models", [])
                models = [m.get("name") for m in models_data if "name" in m]
                return self._send_json({"models": models, "connected": True})
            return self._send_json({
                "models": ["qwen3.5:0.8b", "qwen3.5:9b", "gemma-4-e4b-it:latest"],
                "connected": False,
                "error": f"Status {resp.status_code}",
            })
        except Exception as e:
            return self._send_json({
                "models": ["qwen3.5:0.8b", "qwen3.5:9b", "gemma-4-e4b-it:latest"],
                "connected": False,
                "error": str(e),
            })

    def _serve_index(self):
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():
            content = index_file.read_bytes()
        else:
            content = b"<h1>John White Pentest Suite - Web GUI UI file not found.</h1>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str):
        self._send_json({"error": message, "status": status}, status=status)

    def log_message(self, format, *args):
        # Silence default request access log spam unless error
        if args and str(args[1]).startswith(("4", "5")):
            super().log_message(format, *args)


def run_web_gui(
    host: str = "127.0.0.1",
    port: int = 5050,
    open_browser: bool = True,
) -> None:
    """Entrypoint to start the John White Web GUI server."""
    # Ensure port availability with fallback
    server = None
    actual_port = port
    for p in range(port, port + 20):
        try:
            server = ThreadingHTTPServer((host, p), WebGUIHandler)
            actual_port = p
            break
        except OSError:
            continue

    if not server:
        print(f"[-] Could not bind to {host}:{port} or subsequent ports.")
        sys.exit(1)

    url = f"http://{host}:{actual_port}"
    print("=" * 66)
    print("  JOHN WHITE - AUTOMATED PENTESTING WEB GUI")
    print(f"  Server running at: \033[1;36m{url}\033[0m")
    print("  Press Ctrl+C to stop the web server.")
    print("=" * 66)

    if open_browser:
        def _open():
            time.sleep(0.6)
            webbrowser.open(url)

        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down John White Web GUI server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="John White Pentest Web GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5050, help="Port (default: 5050)")
    parser.add_argument(
        "--no-browser", action="store_true", help="Do not auto-open browser"
    )
    args = parser.parse_args()

    run_web_gui(host=args.host, port=args.port, open_browser=not args.no_browser)

