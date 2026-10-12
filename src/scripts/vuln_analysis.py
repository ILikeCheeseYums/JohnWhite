import json
import logging
from typing import Any, Dict, List, Optional
import requests

from .recon import ReconAgent

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL_NAME = "qwen3.5:9b"


class VulnAnalysisAgent:
    """Stage 2: Vulnerability Analysis Agent.

    Analyzes responses from Stage 1 (ReconAgent), assesses vulnerability patterns
    (OWASP Top 10, misconfigurations, information leakage), and interactively
    requests additional specific probing from ReconAgent when needed.
    """

    def __init__(
        self,
        recon_agent: ReconAgent,
        ollama_url: str = DEFAULT_OLLAMA_URL,
        model_name: str = DEFAULT_MODEL_NAME,
        keep_alive: int = -1,
    ):
        self.recon_agent = recon_agent
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.keep_alive = keep_alive

    def _query_ollama(
        self,
        prompt: str,
        system_prompt: str,
        stream: bool = True,
        show_thinking: bool = True,
        timeout: int = 180,
    ) -> str:
        """Helper to invoke local LLM with keep_alive enabled to prevent reload overhead."""
        payload = {
            "model": self.model_name,
            "system": system_prompt,
            "prompt": prompt,
            "stream": stream,
            "keep_alive": self.keep_alive,
        }

        full_response = []
        try:
            response = requests.post(self.ollama_url, json=payload, stream=stream, timeout=timeout)
            if response.status_code != 200:
                err_msg = f"[-] Error: Ollama returned status {response.status_code}: {response.text}"
                print(f"\n{err_msg}")
                return err_msg

            if stream:
                in_thinking = False
                for line in response.iter_lines():
                    if line:
                        decoded = line.decode("utf-8")
                        try:
                            chunk = json.loads(decoded)
                            thinking_token = chunk.get("thinking", "")
                            token = chunk.get("response", "")

                            if thinking_token:
                                if show_thinking:
                                    if not in_thinking:
                                        print("\n[Thinking] ", end="", flush=True)
                                        in_thinking = True
                                    print(thinking_token, end="", flush=True)
                                else:
                                    print(".", end="", flush=True)

                            if token:
                                if in_thinking:
                                    print("\n\n[Analysis Output]\n", flush=True)
                                    in_thinking = False
                                print(token, end="", flush=True)
                                full_response.append(token)
                        except json.JSONDecodeError:
                            pass
                print()  # Final newline
                return "".join(full_response) if full_response else ""
            else:
                data = response.json()
                # For thinking models, response might be in response or thinking
                return data.get("response") or data.get("thinking") or ""

        except requests.exceptions.ConnectionError:
            err = f"[-] Could not connect to Ollama at {self.ollama_url}. Ensure Ollama is running."
            print(err)
            return err
        except Exception as exc:
            err = f"[-] Error querying LLM: {str(exc)}"
            print(err)
            return err

    def decide_follow_up_probes(self, initial_findings: List[Dict[str, Any]]) -> List[str]:
        """Asks the LLM which specific endpoints need deeper follow-up probing by ReconAgent."""
        system_prompt = (
            "You are a penetration testing coordinator specializing in reconnaissance and attack surface mapping. "
            "Inspect the initial scan summary and return ONLY a valid JSON list of up to 4 specific sub-paths or endpoints "
            "that warrant deeper investigation (e.g. ['/ftp/legal.md', '/rest/admin/users', '/rest/products/search?q=test']). "
            "Do not include any explanation, markdown formatting, or code fences—only the JSON array."
        )

        prompt = f"Initial Findings:\n{json.dumps(initial_findings, indent=2)}\n\nEndpoints to probe further:"
        
        # Stream to avoid blocking timeouts on thinking models
        print("    [Thinking...] ", end="", flush=True)
        res = self._query_ollama(prompt, system_prompt, stream=True, show_thinking=False, timeout=180)
        print()  # newline after streaming completes
        
        import re
        match = re.search(r"\[\s*\"[^\"]*\"(?:\s*,\s*\"[^\"]*\")*\s*\]", res)
        if match:
            try:
                endpoints = json.loads(match.group(0))
                if isinstance(endpoints, list):
                    return [str(e) for e in endpoints]
            except Exception:
                pass

        # Fallback to direct json loads
        cleaned = res.strip()
        if "```" in cleaned:
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
        cleaned = cleaned.strip()

        try:
            endpoints = json.loads(cleaned)
            if isinstance(endpoints, list):
                return [str(e) for e in endpoints]
        except Exception:
            pass

        return []

    def analyze_vulnerabilities(
        self,
        recon_data: Dict[str, Any],
        follow_up_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Correlates reconnaissance data, common vulnerabilities, and produces a vulnerability report."""
        system_prompt = (
            "You are a defensive Application Security Auditor analyzing reconnaissance findings from an authorized security assessment. "
            "Examine the discovered web routes, HTTP status codes, and server responses to identify potential security risks, "
            "such as exposed administrative interfaces, sensitive file exposure, missing authentication controls, and input validation risks. "
            "Provide a structured audit report covering:\n"
            "1. Attack Surface Summary (notable endpoints & status)\n"
            "2. Identified Security Risks & Vulnerability Indicators (Root cause & severity)\n"
            "3. Recommended Security Hardening & Remediation Steps"
        )

        # Build a concise, clean summary to avoid overwhelming the context window
        http_summary = []
        for p in recon_data.get("http_probes", []):
            if isinstance(p, dict):
                http_summary.append({
                    "endpoint": p.get("endpoint"),
                    "status_code": p.get("status_code"),
                    "content_type": p.get("content_type"),
                    "sample": (p.get("sample_body") or "")[:150],
                })

        traffic_summary = []
        browser_info = recon_data.get("browser_traffic", {})
        for req in browser_info.get("intercepted", [])[:10]:
            traffic_summary.append({
                "url": req.get("url"),
                "status": req.get("status"),
                "method": req.get("method"),
            })

        analysis_context = {
            "probed_endpoints": http_summary,
            "browser_traffic_sample": traffic_summary,
            "discovered_links": browser_info.get("extracted_links", [])[:10],
            "targeted_follow_ups": follow_up_findings or [],
        }

        prompt = (
            "Review these reconnaissance scan results and provide a comprehensive security risk assessment:\n\n"
            f"{json.dumps(analysis_context, indent=2)}"
        )

        print(f"\n[*] Stage 2: Consulting {self.model_name} for Vulnerability Analysis...\n")
        return self._query_ollama(prompt, system_prompt, stream=True, show_thinking=True, timeout=240)

