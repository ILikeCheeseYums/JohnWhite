import json
import logging
from typing import Any, Callable, Dict, List, Optional
import requests
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)

DEFAULT_TARGET_URL = "http://localhost:3000"


class ReconAgent:
    """Stage 1: Reconnaissance Agent.

    Capable of sending requests via HTTP, navigating via headless browser (Playwright),
    intercepting responses, detecting endpoints, and collecting response headers/metadata.
    """

    def __init__(self, base_url: str = DEFAULT_TARGET_URL):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.discovered_endpoints: List[str] = []
        self.intercepted_traffic: List[Dict[str, Any]] = []

    def probe_endpoint(self, endpoint: str, timeout: int = 5) -> Dict[str, Any]:
        """Probes a specific endpoint and returns response metadata."""
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"
        url = f"{self.base_url}{endpoint}"

        try:
            response = self.session.get(url, timeout=timeout)
            content_type = response.headers.get("Content-Type", "")

            result = {
                "endpoint": endpoint,
                "url": url,
                "status_code": response.status_code,
                "content_type": content_type,
                "headers": dict(response.headers),
                "content_length": len(response.content),
                "sample_body": (
                    response.text[:400]
                    if any(t in content_type.lower() for t in ["json", "html", "text", "javascript"])
                    else "[Binary/Non-text]"
                ),
            }

            if response.status_code < 400 and endpoint not in self.discovered_endpoints:
                self.discovered_endpoints.append(endpoint)

            return result
        except requests.exceptions.ConnectionError:
            return {"endpoint": endpoint, "error": f"Connection refused to {url}"}
        except Exception as exc:
            return {"endpoint": endpoint, "error": str(exc)}

    def quick_scan(
        self,
        custom_paths: Optional[List[str]] = None,
        on_probe: Optional[Callable[[Dict[str, Any]], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> List[Dict[str, Any]]:
        """Scans standard reconnaissance paths or a custom path list."""
        paths = custom_paths or [
            "/",
            "/api/Challenges",
            "/rest/products/search",
            "/rest/user/whoami",
            "/api/Feedbacks",
            "/rest/admin/application-configuration",
            "/assets/public/images/upload/",
            "/ftp",
        ]

        findings = []
        for path in paths:
            if should_stop and should_stop():
                break
            res = self.probe_endpoint(path)
            findings.append(res)
            if on_probe:
                try:
                    on_probe(res)
                except Exception:
                    pass
        return findings

    def browser_crawl_and_intercept(
        self,
        start_path: str = "/",
        wait_time_ms: int = 3000,
        on_intercept: Optional[Callable[[Dict[str, Any]], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Navigates to the application using a headless Chromium browser,

        intercepts network requests/responses, and extracts rendered links and forms.
        """
        full_url = f"{self.base_url}{start_path}"
        intercepted: List[Dict[str, Any]] = []
        page_links: List[str] = []
        page_forms: List[Dict[str, Any]] = []

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()

                def handle_response(response):
                    if should_stop and should_stop():
                        return
                    url = response.url
                    # Filter for target host traffic
                    if self.base_url in url:
                        try:
                            content_type = response.headers.get("content-type", "")
                            sample = ""
                            if any(t in content_type.lower() for t in ["json", "html", "text"]):
                                sample = response.text()[:250]
                            item = {
                                "url": url,
                                "status": response.status,
                                "method": response.request.method,
                                "content_type": content_type,
                                "sample_body": sample,
                            }
                            intercepted.append(item)
                            if on_intercept:
                                try:
                                    on_intercept(item)
                                except Exception:
                                    pass
                        except Exception:
                            pass

                page.on("response", handle_response)

                page.goto(full_url, wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(wait_time_ms)

                # Extract links on page
                links = page.eval_on_selector_all(
                    "a[href]", "elements => elements.map(e => e.getAttribute('href'))"
                )
                page_links = sorted(list({str(link) for link in links if link}))

                # Extract forms
                page_forms = page.eval_on_selector_all(
                    "form",
                    """elements => elements.map(f => ({
                        action: f.getAttribute('action') || '',
                        method: f.getAttribute('method') || 'GET',
                        inputs: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                            name: i.getAttribute('name') || i.getAttribute('id') || '',
                            type: i.getAttribute('type') || 'text'
                        }))
                    }))"""
                )

                browser.close()

            self.intercepted_traffic.extend(intercepted)
            return {
                "start_url": full_url,
                "intercepted_requests_count": len(intercepted),
                "intercepted": intercepted[:15],  # Cap sample summary
                "extracted_links": page_links[:20],
                "extracted_forms": page_forms,
            }
        except Exception as exc:
            return {
                "start_url": full_url,
                "error": f"Headless browser crawl failed: {str(exc)}",
            }
