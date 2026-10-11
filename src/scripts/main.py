import json
import requests

TARGET_BASE_URL = "http://localhost:3000"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen3.5:9b"  # Adjust to your exact local model tag if needed


class JuiceShopReconAgent:

  def __init__(self, base_url=TARGET_BASE_URL):
    self.base_url = base_url
    self.session = requests.Session()
    self.discovered_endpoints = []

  def tool_probe_endpoint(self, endpoint):
    """Tool: Sends an HTTP GET request to check if an endpoint exists and gathers metadata."""
    url = f"{self.base_url}{endpoint}"
    try:
      response = self.session.get(url, timeout=5)
      content_type = response.headers.get("Content-Type", "")

      result = {
          "endpoint": endpoint,
          "status_code": response.status_code,
          "content_type": content_type,
          "content_length": len(response.content),
          "sample_body": response.text[:300] if "json" in content_type or "html" in content_type else "[Binary/Non-text]"
      }

      if response.status_code < 400 and endpoint not in self.discovered_endpoints:
        self.discovered_endpoints.append(endpoint)

      return result
    except requests.exceptions.ConnectionError:
      return {"error": "Connection refused. Ensure Juice Shop is running."}

  def tool_quick_scan(self):
    """Tool: Runs a quick initial scan of high-value reconnaissance paths common in Juice Shop."""
    common_paths = [
        "/",
        "/api/Challenges",
        "/rest/products/search",
        "/rest/user/whoami",
        "/api/Feedbacks",
        "/rest/admin/application-configuration",
        "/assets/public/images/upload/",
        "/ftp"
    ]

    print("[*] Running initial reconnaissance sweep across common paths...")
    findings = []
    for path in common_paths:
      res = self.tool_probe_endpoint(path)
      findings.append(res)
      print(f"    [Probe] {path} -> Status: {res.get('status_code', 'Error')}")

    return findings

  def ask_qwen_for_recon_strategy(self, scan_summary):
    """Sends reconnaissance data to local Qwen model and streams the analysis response in real-time."""
    print(f"\n[*] Consulting local Qwen ({MODEL_NAME}) for analysis...\n")

    system_prompt = (
        "You are an expert Application Security Reconnaissance Assistant analyzing a local "
        "target (OWASP Juice Shop at http://localhost:3000). Your task is strictly limited "
        "to reconnaissance, asset discovery, and endpoint mapping. Analyze the scan findings "
        "provided below, identify exposed administrative or API routes, and suggest 3 logical "
        "next reconnaissance steps or parameters to investigate."
    )

    prompt = f"{system_prompt}\n\nScan Results Summary:\n{json.dumps(scan_summary, indent=2)}"

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": True,  # Enables streaming mode in Ollama
    }

    try:
      # stream=True allows reading chunked data as it arrives
      response = requests.post(OLLAMA_URL, json=payload, stream=True, timeout=90)

      if response.status_code != 200:
        print(f"[-] Error: Ollama returned status code {response.status_code}")
        return

      # Iterate over incoming lines of JSON chunks from Ollama
      for line in response.iter_lines():
        if line:
          decoded_line = line.decode('utf-8')
          try:
            chunk = json.loads(decoded_line)
            token = chunk.get("response", "")
            # Print each token immediately without buffering or adding newlines
            print(token, end="", flush=True)
          except json.JSONDecodeError:
            pass

      print()  # Final newline after stream completes
    except Exception as e:
      print(f"\n[-] Error communicating with Ollama: {str(e)}")

  def run(self):
    print("--- Starting Automated Reconnaissance Agent ---")

    # 1. Perform automated discovery sweep
    scan_results = self.tool_quick_scan()

    # 2. Stream findings analysis from local Qwen model
    print("\n--- Qwen Reconnaissance Report ---")
    self.ask_qwen_for_recon_strategy(scan_results)
    print("--- Reconnaissance Completed ---")


if __name__ == "__main__":
  agent = JuiceShopReconAgent()
  agent.run()
