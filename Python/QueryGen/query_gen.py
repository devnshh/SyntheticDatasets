#!/usr/bin/env python3
"""
Python CPG Query Generator
Generates and validates Joern CPGQL queries for Python code vulnerabilities.
Adapted from Java query generator.
"""

import os
import json
import shutil
import logging
import subprocess
import sys
import time
import fcntl
import argparse
import requests
import hashlib
from multiprocessing import Pool, Manager
import ast
from typing import Optional, Tuple, Dict, List

# ===== CONFIGURATION =====
NUM_WORKERS = 4
MAX_RETRIES = 5
JOERN_TIMEOUT = 120
DEFAULT_MAX_TOKENS = 4096

# API Configuration
LMSTUDIO_API_URL = "http://localhost:1234/v1/chat/completions"
GEMINI_MODEL = "gemini-2.0-flash"

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(SCRIPT_DIR, "input_data.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "valid_dataset.json")
SYSTEM_PROMPT_PATH = os.path.join(SCRIPT_DIR, "current_system_prompt.txt")

# Load system prompt
try:
    with open(SYSTEM_PROMPT_PATH, 'r') as f:
        SYSTEM_PROMPT = f.read()
except FileNotFoundError:
    SYSTEM_PROMPT = ""

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(SCRIPT_DIR, "pipeline.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ===== PYTHON VULNERABILITY PATTERNS =====
PYTHON_VULNERABILITY_PATTERNS = {
    "Command Injection": {
        "sources": ["input", "argv", "get", "getParameter", "environ", "read", "readline"],
        "sinks": ["system", "popen", "run", "call", "Popen", "check_output", "check_call", "spawn"],
        "secure_patterns": ["shlex.quote", "shell=False", "validate", "whitelist", "allowlist"],
        "indicators": ["os.system", "subprocess", "shell=True", "+ ", "format(", "f\""],
        "fallback_query": 'cpg.call.name("system|popen|run|call|Popen").where(_.argument.code(".*\\\\+.*|.*format.*|.*%.*"))',
        "examples": [
            'cpg.call.name("system").where(_.argument.isCall.name("input"))',
            'cpg.call.name("run|call|Popen").reachableByFlows(cpg.call.name("input|get"))'
        ]
    },
    "Deserialization": {
        "sources": ["read", "get_data", "data", "recv", "open"],
        "sinks": ["load", "loads", "decode", "unmarshal"],
        "secure_patterns": ["safe_load", "SafeLoader", "json.loads", "literal_eval"],
        "indicators": ["pickle", "marshal", "yaml.load", "jsonpickle", "Loader="],
        "fallback_query": 'cpg.call.name("load|loads").where(_.receiver.code("pickle|marshal|yaml"))',
        "examples": [
            'cpg.call.name("load").where(_.code(".*pickle.*|.*marshal.*"))',
            'cpg.call.name("loads").whereNot(_.argument.code(".*safe.*|.*Safe.*"))'
        ]
    },
    "SQL Injection": {
        "sources": ["input", "get", "form", "args", "getParameter", "argv"],
        "sinks": ["execute", "executemany", "raw", "executescript"],
        "secure_patterns": ["execute\\(.*,.*\\(", "execute\\(.*,.*\\[", "%s", "?", "parameterized"],
        "indicators": ["cursor", "execute", "SELECT", "INSERT", "UPDATE", "DELETE", "+ ", "format(", "f\""],
        "fallback_query": 'cpg.call.name("execute").where(_.argument.code(".*\\\\+.*|.*format.*|.*%[^s].*"))',
        "examples": [
            'cpg.call.name("execute").where(_.argument.code(".*\\\\+.*")).whereNot(_.argument.order(2))',
            'cpg.call.name("execute").reachableByFlows(cpg.call.name("input|get"))'
        ]
    },
    "Path Traversal": {
        "sources": ["input", "get", "args", "form", "argv", "getParameter"],
        "sinks": ["open", "read", "write", "join", "send_file", "send_from_directory"],
        "secure_patterns": ["secure_filename", "basename", "normpath", "realpath", "startswith", "abspath"],
        "indicators": ["open(", "os.path", "send_file", "../", "..\\\\"],
        "fallback_query": 'cpg.call.name("open|join").whereNot(_.method.ast.isCall.name(".*basename|secure_filename.*"))',
        "examples": [
            'cpg.call.name("open").reachableByFlows(cpg.call.name("input|get"))',
            'cpg.call.name("join").whereNot(_.method.ast.isCall.name("basename|secure_filename"))'
        ]
    },
    "Server-Side Template Injection (SSTI)": {
        "sources": ["input", "get", "args", "form", "getParameter"],
        "sinks": ["render", "render_template_string", "Template", "from_string"],
        "secure_patterns": ["render_template", "autoescape", "SandboxedEnvironment", "escape"],
        "indicators": ["Template(", "render_template_string", "jinja2", "{{"],
        "fallback_query": 'cpg.call.name("render_template_string|Template").reachableByFlows(cpg.call.name("input|get"))',
        "examples": [
            'cpg.call.name("render_template_string").reachableByFlows(cpg.call.name("get|input"))',
            'cpg.call.name("Template").reachableByFlows(cpg.call.name("get|args"))'
        ]
    },
    "SSRF": {
        "sources": ["input", "get", "args", "form", "getParameter", "argv"],
        "sinks": ["get", "post", "put", "delete", "request", "urlopen", "urlretrieve"],
        "secure_patterns": ["allowlist", "whitelist", "validate_url", "urlparse", "is_safe_url"],
        "indicators": ["requests.", "urllib", "urlopen", "http://", "https://"],
        "fallback_query": 'cpg.call.name("get|post|urlopen").reachableByFlows(cpg.call.name("input|get"))',
        "examples": [
            'cpg.call.name("get").where(_.receiver.code("requests")).reachableByFlows(cpg.call.name("input"))',
            'cpg.call.name("urlopen").reachableByFlows(cpg.call.name("get|args"))'
        ]
    },
    "Code Injection": {
        "sources": ["input", "get", "args", "form", "read", "argv"],
        "sinks": ["eval", "exec", "compile", "__import__", "execfile"],
        "secure_patterns": ["literal_eval", "ast.parse", "validate", "whitelist"],
        "indicators": ["eval(", "exec(", "compile(", "__import__"],
        "fallback_query": 'cpg.call.name("eval|exec").reachableByFlows(cpg.call.name("input|get"))',
        "examples": [
            'cpg.call.name("eval").reachableByFlows(cpg.call.name("input"))',
            'cpg.call.name("exec").whereNot(_.method.ast.isCall.name("validate|sanitize"))'
        ]
    },
    "Insecure Temporary Files": {
        "sources": [],
        "sinks": ["mktemp", "open"],
        "secure_patterns": ["mkstemp", "NamedTemporaryFile", "TemporaryFile", "TemporaryDirectory"],
        "indicators": ["tempfile.mktemp", "/tmp/", "temp_", "tmp_"],
        "fallback_query": 'cpg.call.name("mktemp").l ++ cpg.call.name("open").where(_.argument.code(".*/tmp/.*"))',
        "examples": [
            'cpg.call.name("mktemp")',
            'cpg.call.name("open").where(_.argument.code(".*/tmp/.*"))'
        ]
    },
    "Insecure YAML/XML Parsing": {
        "sources": ["read", "open", "get_data", "recv"],
        "sinks": ["load", "parse", "fromstring"],
        "secure_patterns": ["safe_load", "SafeLoader", "defusedxml", "defused"],
        "indicators": ["yaml.load", "yaml.unsafe_load", "Loader=", "xml.etree", "xml.dom"],
        "fallback_query": 'cpg.call.name("load").where(_.code(".*yaml.*")).whereNot(_.code(".*safe.*"))',
        "examples": [
            'cpg.call.name("load").where(_.code(".*yaml.*")).whereNot(_.argument.code(".*safe.*|.*Safe.*"))',
            'cpg.call.name("parse|fromstring").where(_.code(".*xml.*")).whereNot(_.code(".*defused.*"))'
        ]
    },
    "Hardcoded Secrets": {
        "sources": [],
        "sinks": [],
        "secure_patterns": ["environ", "getenv", "config", "secret_manager", "vault"],
        "indicators": ["password", "secret", "api_key", "token", "credential", "private_key"],
        "fallback_query": 'cpg.assignment.where(_.target.code(".*password|secret|api_key|token.*")).where(_.source.isLiteral)',
        "examples": [
            'cpg.assignment.where(_.target.code(".*password.*")).where(_.source.code("\\".*\\""))',
            'cpg.literal.code(".*[A-Za-z0-9]{20,}.*").where(_.inAssignment.target.code(".*key|token|secret.*"))'
        ]
    }
}


# Worker state
_worker_model = None
_worker_backend = None
_worker_max_tokens = None


def init_worker(backend: str, model_name: str, max_tokens: int):
    """Initialize worker process state."""
    global _worker_model, _worker_backend, _worker_max_tokens
    _worker_backend = backend
    _worker_model = model_name
    _worker_max_tokens = max_tokens


def get_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Generate and validate Python CPG queries")
    parser.add_argument("--backend", choices=["gemini", "lmstudio"], default="lmstudio",
                        help="LLM backend to use")
    parser.add_argument("--model", type=str, default=None,
                        help="Model name (optional, will auto-select)")
    parser.add_argument("--workers", type=int, default=NUM_WORKERS,
                        help="Number of parallel workers")
    parser.add_argument("--tokens", type=int, default=DEFAULT_MAX_TOKENS,
                        help="Maximum tokens for generation")
    parser.add_argument("--input", type=str, default=INPUT_FILE,
                        help="Input JSON file with code samples")
    parser.add_argument("--output", type=str, default=OUTPUT_FILE,
                        help="Output JSON file for valid queries")
    parser.add_argument("--target", type=int, default=0,
                        help="Target total samples (0 for no limit)")
    parser.add_argument("--per_vuln", type=int, default=0,
                        help="Max samples per vulnerability type (0 for no limit)")
    parser.add_argument("--balance", type=float, default=0.5,
                        help="Target ratio of vulnerable samples (0.0-1.0)")
    return parser.parse_args()


def select_lmstudio_model(specified_model: str = None) -> str:
    """Select model from LM Studio."""
    if specified_model:
        return specified_model
    
    try:
        response = requests.get("http://localhost:1234/v1/models", timeout=5)
        if response.status_code == 200:
            models = response.json().get("data", [])
            if models:
                model_id = models[0].get("id", "default")
                print(f"\nUsing LM Studio model: {model_id}")
                return model_id
    except Exception as e:
        logger.warning(f"Could not fetch models from LM Studio: {e}")
    
    return "qwen2.5-coder-14b-instruct"


def call_model(prompt: str, is_retry: bool = False) -> str:
    """Call the LLM model."""
    global _worker_backend, _worker_model, _worker_max_tokens
    
    if _worker_backend == "gemini":
        return call_gemini(prompt)
    else:
        return call_lmstudio(prompt, _worker_model, _worker_max_tokens)


def call_lmstudio(prompt: str, model: str, max_tokens: int) -> str:
    """Call LM Studio API."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": max_tokens
    }
    
    try:
        response = requests.post(LMSTUDIO_API_URL, json=payload, timeout=120)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        logger.error(f"LM Studio API error: {e}")
        return ""


def call_gemini(prompt: str) -> str:
    """Call Gemini API."""
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        # Try loading from .env file
        env_file = os.path.join(SCRIPT_DIR, ".env")
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                for line in f:
                    if line.startswith("GEMINI_API_KEY="):
                        api_key = line.split("=", 1)[1].strip()
                        break
    
    if not api_key:
        logger.error("GEMINI_API_KEY not found")
        return ""
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={api_key}"
    
    payload = {
        "contents": [{
            "parts": [{"text": f"{SYSTEM_PROMPT}\n\n{prompt}"}]
        }],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": DEFAULT_MAX_TOKENS
        }
    }
    
    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        result = response.json()
        return result["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return ""


def build_query_prompt(code: str, vulnerability: str, is_vulnerable: bool) -> str:
    """Build prompt for query generation."""
    patterns = PYTHON_VULNERABILITY_PATTERNS.get(vulnerability, {})
    
    sources = patterns.get("sources", ["input", "get", "args"])
    sinks = patterns.get("sinks", ["execute", "system", "eval"])
    secure = patterns.get("secure_patterns", [])
    examples = patterns.get("examples", [])
    
    status = "VULNERABLE" if is_vulnerable else "BENIGN/SECURE"
    if is_vulnerable:
        goal = "The query MUST find results (non-empty list) since this code contains a vulnerability."
    else:
        goal = "The query MUST return empty [] since this code is secure and properly sanitized."
    
    prompt = f"""Generate a Joern CPGQL query to detect {vulnerability} in Python code.

CODE STATUS: {status}
{goal}

PYTHON CODE:
```python
{code}
```

VULNERABILITY PATTERNS for {vulnerability}:
- Sources (user input): {", ".join(sources[:5])}
- Sinks (dangerous operations): {", ".join(sinks[:5])}
- Secure patterns to exclude: {", ".join(secure[:4])}

WORKING QUERY EXAMPLES:
{chr(10).join(f"  {ex}" for ex in examples)}

CRITICAL RULES:
1. Output ONLY valid JSON with a "queries" array
2. Queries must be syntactically valid Scala
3. Do NOT use .p, .l, or .toList at the end
4. Use cpg.call.name() for method calls
5. Last query should use reachableByFlows for taint analysis

EXPECTED OUTPUT FORMAT:
```json
{{
  "queries": [
    "val sources = cpg.call.name(\\"{sources[0]}|{sources[1] if len(sources) > 1 else sources[0]}\\").argument.l",
    "val sinks = cpg.call.name(\\"{sinks[0]}|{sinks[1] if len(sinks) > 1 else sinks[0]}\\").argument.l",
    "sinks.reachableByFlows(sources).l"
  ]
}}
```
"""
    return prompt


def build_retry_prompt(previous_response: str, error_type: str, code: str, 
                       vulnerability: str, is_vulnerable: bool, attempt: int) -> str:
    """Build retry prompt based on error type."""
    status = "VULNERABLE" if is_vulnerable else "BENIGN"
    
    if error_type == "false_negative":
        hint = f"""The query returned empty [] but this code IS VULNERABLE to {vulnerability}.
Make the query MORE SENSITIVE to find the vulnerability.
Look for:
- Direct taint flow from user input to dangerous sinks
- String concatenation or formatting in security-sensitive operations
- Missing input validation before dangerous operations"""
    
    elif error_type == "false_positive":
        hint = f"""The query found results but this code is BENIGN (properly secured).
Make the query MORE SPECIFIC to exclude secure patterns.
Use .whereNot() to filter out:
- Proper parameterization
- Input validation
- Secure API usage"""
    
    elif error_type == "execution_failed":
        hint = """The query failed to execute. Fix the syntax:
- Use cpg.call.name("method") not cpg.method
- Ensure all parentheses are balanced
- Use valid Scala/CPGQL syntax"""
    
    else:
        hint = "Please provide valid JSON with a 'queries' array."
    
    return f"""Your previous query attempt failed.

ERROR TYPE: {error_type}
CODE STATUS: {status}
ATTEMPT: {attempt}/{MAX_RETRIES}

{hint}

PYTHON CODE:
```python
{code}
```

Generate a corrected query now. Output ONLY valid JSON.
"""


def get_fallback_query(vulnerability: str, is_vulnerable: bool) -> list:
    """Get fallback query for a vulnerability type."""
    patterns = PYTHON_VULNERABILITY_PATTERNS.get(vulnerability, {})
    fallback = patterns.get("fallback_query", "")
    
    if fallback:
        return [fallback]
    
    # Generic fallback
    sources = patterns.get("sources", ["input"])
    sinks = patterns.get("sinks", ["system"])
    
    source_pattern = "|".join(sources[:3])
    sink_pattern = "|".join(sinks[:3])
    
    return [
        f'val sources = cpg.call.name("{source_pattern}").argument.l',
        f'val sinks = cpg.call.name("{sink_pattern}").argument.l',
        'sinks.reachableByFlows(sources).l'
    ]


def validate_query_syntax(query: str) -> Tuple[bool, str]:
    """Validate query syntax before execution."""
    # Check for common syntax issues
    if query.count('(') != query.count(')'):
        return False, "Unbalanced parentheses"
    
    if query.count('"') % 2 != 0:
        return False, "Unbalanced quotes"
    
    if query.count('{') != query.count('}'):
        return False, "Unbalanced braces"
    
    # Check for forbidden patterns
    forbidden = [".p", ".l.l", "toList.toList", "println"]
    for pattern in forbidden:
        if pattern in query:
            return False, f"Forbidden pattern: {pattern}"
    
    return True, ""


def parse_llm_response(response: str) -> list:
    """Parse LLM response to extract queries."""
    # Try to extract JSON from markdown code blocks
    json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
    if json_match:
        response = json_match.group(1)
    
    # Try to find JSON object
    json_match = re.search(r'\{[^{}]*"queries"\s*:\s*\[.*?\]\s*\}', response, re.DOTALL)
    if json_match:
        response = json_match.group(0)
    
    try:
        data = json.loads(response)
        if isinstance(data, dict):
            return data.get("queries", [])
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    
    # Try as Python literal
    try:
        data = ast.literal_eval(response)
        if isinstance(data, dict):
            return data.get("queries", [])
        if isinstance(data, list):
            return data
    except (ValueError, SyntaxError):
        pass
    
    return []


def run_joern_script(code: str, queries: list, workspace: str) -> Optional[str]:
    """Execute queries in Joern and return result."""
    # Clean workspace
    if os.path.exists(workspace):
        shutil.rmtree(workspace)
    os.makedirs(workspace)
    
    # Write Python code
    code_file = os.path.join(workspace, "code.py")
    with open(code_file, 'w') as f:
        f.write(code)
    
    # Build Joern script
    queries_block = "\n    ".join(queries[:-1]) if len(queries) > 1 else ""
    last_query = queries[-1] if queries else "cpg.call.l"
    
    # Ensure last query ends with .l for JSON serialization
    if not last_query.rstrip().endswith('.l'):
        last_query = last_query.rstrip() + '.l'
    
    script_content = f'''
importCode("{code_file}")
try {{
    {queries_block}
    val res = ({last_query.replace('.l', '')}).toJson
    println("JOERN_JSON_START")
    println(res)
    println("JOERN_JSON_END")
}} catch {{
    case e: Exception => 
        println("JOERN_ERROR_START")
        println(e.getMessage)
        println("JOERN_ERROR_END")
}}
'''
    
    script_file = os.path.join(workspace, "query.sc")
    with open(script_file, 'w') as f:
        f.write(script_content)
    
    try:
        result = subprocess.run(
            ["joern", "--script", script_file],
            capture_output=True,
            text=True,
            timeout=JOERN_TIMEOUT,
            cwd=workspace
        )
        
        output = result.stdout + result.stderr
        
        # Extract JSON result
        json_match = re.search(r"JOERN_JSON_START\s*(.*?)\s*JOERN_JSON_END", output, re.DOTALL)
        if json_match:
            return json_match.group(1).strip()
        
        # Check for error
        error_match = re.search(r"JOERN_ERROR_START\s*(.*?)\s*JOERN_ERROR_END", output, re.DOTALL)
        if error_match:
            logger.warning(f"Joern error: {error_match.group(1)}")
            return None
        
        return None
        
    except subprocess.TimeoutExpired:
        logger.warning("Joern execution timed out")
        return None
    except Exception as e:
        logger.error(f"Joern execution error: {e}")
        return None


def format_output_queries(queries: list) -> str:
    """Format queries for output JSON with single quotes."""
    items = []
    for q in queries:
        escaped = q.replace('\\', '\\\\').replace("'", "\\'")
        items.append(f"'{escaped}'")
    return "[" + ", ".join(items) + "]"


# File lock for thread-safe writing
_file_lock = None


def save_entry_immediately(entry: dict):
    """Save a single entry to output file immediately."""
    global OUTPUT_FILE
    
    lock_file = OUTPUT_FILE + ".lock"
    
    with open(lock_file, 'w') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            # Read existing data
            if os.path.exists(OUTPUT_FILE):
                with open(OUTPUT_FILE, 'r') as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = []
            else:
                data = []
            
            # Append new entry
            data.append(entry)
            
            # Write back
            with open(OUTPUT_FILE, 'w') as f:
                json.dump(data, f, indent=2)
                
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def increment_counter(vulnerability: str, is_vulnerable: bool, counters):
    """Increment shared counter for balancing."""
    key = "vulnerable" if is_vulnerable else "benign"
    
    if vulnerability not in counters[key]:
        counters[key][vulnerability] = 0
    counters[key][vulnerability] += 1
    
    total_key = "total_vulnerable" if is_vulnerable else "total_benign"
    counters[total_key] += 1


def should_skip_item(vulnerability: str, is_vulnerable: bool, counters, limits) -> bool:
    """Check if we should skip this item based on limits."""
    key = "vulnerable" if is_vulnerable else "benign"
    
    # Check per-vulnerability limit
    if limits.get("per_vuln", 0) > 0:
        current = counters[key].get(vulnerability, 0)
        if current >= limits["per_vuln"]:
            return True
    
    # Check target balance
    target = limits.get("target", 0)
    if target > 0:
        total = counters["total_vulnerable"] + counters["total_benign"]
        if total >= target:
            return True
    
    return False


def format_balance_stats(counters) -> str:
    """Format current balance statistics."""
    vul = counters.get("total_vulnerable", 0)
    ben = counters.get("total_benign", 0)
    total = vul + ben
    ratio = vul / total * 100 if total > 0 else 0
    return f"VUL:{vul} BEN:{ben} ({ratio:.1f}%)"


def prioritize_work_items(data: list, limits: dict, current_vul: int, current_ben: int) -> list:
    """Prioritize items to balance vulnerable/benign ratio."""
    # Separate by status
    vulnerable = [d for d in data if d.get("status", "").lower() == "vulnerable"]
    benign = [d for d in data if d.get("status", "").lower() == "benign"]
    
    # Group by vulnerability type
    def group_by_vuln(items):
        groups = {}
        for item in items:
            vuln = item.get("vulnerability", "Unknown")
            if vuln not in groups:
                groups[vuln] = []
            groups[vuln].append(item)
        return groups
    
    vul_groups = group_by_vuln(vulnerable)
    ben_groups = group_by_vuln(benign)
    
    # Round-robin through groups
    def round_robin(groups):
        result = []
        keys = list(groups.keys())
        while any(groups[k] for k in keys):
            for k in keys:
                if groups[k]:
                    result.append(groups[k].pop(0))
        return result
    
    sorted_vulnerable = round_robin(vul_groups)
    sorted_benign = round_robin(ben_groups)
    
    # Calculate targets
    target_ratio = limits.get("balance", 0.5)
    target_total = limits.get("target", 1000)
    
    target_vul = int(target_total * target_ratio)
    target_ben = target_total - target_vul
    
    needed_vul = max(0, target_vul - current_vul)
    needed_ben = max(0, target_ben - current_ben)
    
    total_current = current_vul + current_ben
    current_ratio = current_vul / total_current if total_current > 0 else 0.5
    vul_deficit = target_ratio - current_ratio
    
    logger.info(f"Current: VUL:{current_vul} BEN:{current_ben} ({current_ratio*100:.1f}% vulnerable)")
    logger.info(f"Target: {target_ratio*100:.0f}% vulnerable. Deficit: {vul_deficit*100:+.1f}%")
    
    result = []
    vul_idx = 0
    ben_idx = 0
    
    # Front-load underrepresented category
    if vul_deficit > 0.02:
        catch_up_count = min(
            int(abs(vul_deficit) * total_current) + 5,
            len(sorted_vulnerable),
            needed_vul
        )
        logger.info(f"Prioritizing {catch_up_count} vulnerable items first")
        for _ in range(catch_up_count):
            if vul_idx < len(sorted_vulnerable):
                result.append(sorted_vulnerable[vul_idx])
                vul_idx += 1
                
    elif vul_deficit < -0.02:
        catch_up_count = min(
            int(abs(vul_deficit) * total_current) + 5,
            len(sorted_benign),
            needed_ben
        )
        logger.info(f"Prioritizing {catch_up_count} benign items first")
        for _ in range(catch_up_count):
            if ben_idx < len(sorted_benign):
                result.append(sorted_benign[ben_idx])
                ben_idx += 1
    
    # Interleave remaining
    while vul_idx < len(sorted_vulnerable) or ben_idx < len(sorted_benign):
        if vul_idx < len(sorted_vulnerable):
            result.append(sorted_vulnerable[vul_idx])
            vul_idx += 1
        if ben_idx < len(sorted_benign):
            result.append(sorted_benign[ben_idx])
            ben_idx += 1
    
    logger.info(f"Prioritized: {len(sorted_vulnerable)} vulnerable, {len(sorted_benign)} benign")
    
    return result


# Global references for shared state
_shared_counters = None
_shared_limits = None


def worker_initializer(counters, limits, backend: str, model_name: str, max_tokens: int):
    """Initialize worker with shared counters and model."""
    global _shared_counters, _shared_limits
    _shared_counters = counters
    _shared_limits = limits
    init_worker(backend, model_name, max_tokens)


def process_item_with_counters(args: Tuple[int, Dict, int]) -> Tuple[int, Optional[str]]:
    """Process a single item with access to shared counters."""
    global _shared_counters, _shared_limits
    
    idx, item, total = args
    
    code = item['code']
    vulnerability = item['vulnerability']
    is_vulnerable = item['status'].lower() == 'vulnerable'
    status_str = "VUL" if is_vulnerable else "BEN"
    
    # Check limits
    if _shared_limits and should_skip_item(vulnerability, is_vulnerable, _shared_counters, _shared_limits):
        logger.info(f"[{idx+1}/{total}] SKIP: {vulnerability[:25]}... ({status_str}) - limit reached")
        return (idx, None)
    
    workspace = f"/tmp/joern_worker_py_{os.getpid()}"
    
    logger.info(f"[{idx+1}/{total}] Processing: {vulnerability[:30]}... ({status_str})")
    
    result_queries = None
    
    try:
        # Generate initial query
        prompt = build_query_prompt(code, vulnerability, is_vulnerable)
        current_response_text = call_model(prompt)
        
        for attempt in range(1, MAX_RETRIES + 1):
            queries = parse_llm_response(current_response_text)
            
            if not queries:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Could not parse queries")
                if attempt < MAX_RETRIES:
                    if attempt >= 3:
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                        logger.info(f"[{idx+1}/{total}] Using fallback query")
                    else:
                        current_response_text = call_model(build_retry_prompt(
                            current_response_text, "invalid_format", code, vulnerability, is_vulnerable, attempt
                        ))
                        continue
                else:
                    continue
            
            # Validate syntax
            all_valid = True
            for q in queries:
                is_valid, error_msg = validate_query_syntax(q)
                if not is_valid:
                    logger.warning(f"[{idx+1}/{total}] Validation failed: {error_msg}")
                    all_valid = False
                    break
            
            if not all_valid:
                if attempt < MAX_RETRIES:
                    if attempt >= 3:
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                    else:
                        current_response_text = call_model(build_retry_prompt(
                            current_response_text, "execution_failed", code, vulnerability, is_vulnerable, attempt
                        ))
                        continue
                else:
                    continue
            
            result = run_joern_script(code, queries, workspace)
            
            if result is None:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Execution failed")
                if attempt < MAX_RETRIES:
                    if attempt >= 4:
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                    else:
                        current_response_text = call_model(build_retry_prompt(
                            current_response_text, "execution_failed", code, vulnerability, is_vulnerable, attempt
                        ))
                continue
            
            try:
                data = json.loads(result)
                if not isinstance(data, list):
                    data = [data]
                is_empty = len(data) == 0
                
                if is_vulnerable:
                    if is_empty:
                        logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: False negative")
                        if attempt < MAX_RETRIES:
                            current_response_text = call_model(build_retry_prompt(
                                current_response_text, "false_negative", code, vulnerability, is_vulnerable, attempt
                            ))
                        continue
                    else:
                        result_queries = queries
                        break
                else:
                    if not is_empty:
                        logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: False positive")
                        if attempt < MAX_RETRIES:
                            current_response_text = call_model(build_retry_prompt(
                                current_response_text, "false_positive", code, vulnerability, is_vulnerable, attempt
                            ))
                        continue
                    else:
                        result_queries = queries
                        break
                        
            except json.JSONDecodeError:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Invalid JSON from Joern")
                if attempt < MAX_RETRIES:
                    current_response_text = call_model(build_retry_prompt(
                        current_response_text, "invalid_json_joern", code, vulnerability, is_vulnerable, attempt
                    ))
                continue
        
        if result_queries is None:
            logger.error(f"[{idx+1}/{total}] ✗ FAILED after {MAX_RETRIES} attempts")
        else:
            # Increment counters
            if _shared_counters is not None:
                increment_counter(vulnerability, is_vulnerable, _shared_counters)
            
            stats = format_balance_stats(_shared_counters) if _shared_counters else ""
            logger.info(f"[{idx+1}/{total}] ✓ SUCCESS | {stats}")
            
            # Save result
            formatted_queries = format_output_queries(result_queries)
            entry = {
                "instruction": f"Write a Joern CPG query to detect {vulnerability}.",
                "input": code,
                "output": f"```json\n{{\n  \"queries\": {formatted_queries}\n}}\n```"
            }
            save_entry_immediately(entry)
        
    except Exception as e:
        logger.error(f"[{idx+1}/{total}] ✗ Error: {e}")
    finally:
        if os.path.exists(workspace):
            try:
                shutil.rmtree(workspace)
            except:
                pass
    
    return (idx, result_queries)


# Import re for regex
import re


def main():
    global NUM_WORKERS, INPUT_FILE, OUTPUT_FILE
    
    args = get_args()
    
    NUM_WORKERS = args.workers
    INPUT_FILE = args.input
    OUTPUT_FILE = args.output
    backend = args.backend
    
    # Select model
    if backend == "lmstudio":
        model_name = select_lmstudio_model(args.model)
    else:
        model_name = args.model if args.model else GEMINI_MODEL
        print(f"\nUsing Gemini model: {model_name}")
    
    # Load existing output
    existing_entries = []
    existing_vulnerable = {}
    existing_benign = {}
    total_existing_vul = 0
    total_existing_ben = 0
    
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                existing_entries = json.load(f)
            
            # Parse existing entries
            for entry in existing_entries:
                instruction = entry.get("instruction", "")
                input_code = entry.get("input", "")
                
                match = re.search(r"detect (.+?)\.", instruction)
                vuln_type = match.group(1) if match else "Unknown"
                
                # Determine if vulnerable or benign
                secure_patterns = ["safe_load", "secure_filename", "parameterized", "validate", 
                                  "literal_eval", "shlex.quote", "allowlist", "whitelist"]
                is_benign = any(pattern in input_code for pattern in secure_patterns)
                
                if is_benign:
                    existing_benign[vuln_type] = existing_benign.get(vuln_type, 0) + 1
                    total_existing_ben += 1
                else:
                    existing_vulnerable[vuln_type] = existing_vulnerable.get(vuln_type, 0) + 1
                    total_existing_vul += 1
            
            print(f"\n📦 Loaded {len(existing_entries)} existing entries from {OUTPUT_FILE}")
            print(f"   Existing balance: VUL:{total_existing_vul} BEN:{total_existing_ben}")
            
        except (json.JSONDecodeError, Exception) as e:
            print(f"⚠️  Could not load existing data: {e}. Starting fresh.")
            existing_entries = []
    
    # Build processed hashes
    processed_hashes = set()
    for entry in existing_entries:
        input_code = entry.get("input", "")
        code_hash = hashlib.md5(input_code.encode()).hexdigest()
        processed_hashes.add(code_hash)
    
    # Initialize output file
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(existing_entries, f, indent=2)
    
    # Load input data
    with open(INPUT_FILE, 'r') as f:
        data = json.load(f)
    
    original_count = len(data)
    
    # Filter processed items
    unprocessed_data = []
    skipped_count = 0
    for item in data:
        code = item.get('code', '')
        code_hash = hashlib.md5(code.encode()).hexdigest()
        if code_hash in processed_hashes:
            skipped_count += 1
        else:
            unprocessed_data.append(item)
    
    data = unprocessed_data
    total = len(data)
    
    if skipped_count > 0:
        print(f"⏭️  Skipping {skipped_count} already-processed items")
        print(f"   Remaining to process: {total} items")
    
    # Setup shared counters
    manager = Manager()
    
    vul_dict = manager.dict()
    for k, v in existing_vulnerable.items():
        vul_dict[k] = v
    
    ben_dict = manager.dict()
    for k, v in existing_benign.items():
        ben_dict[k] = v
    
    counters = manager.dict({
        "vulnerable": vul_dict,
        "benign": ben_dict,
        "total_vulnerable": total_existing_vul,
        "total_benign": total_existing_ben
    })
    
    limits = {
        "target": args.target,
        "per_vuln": args.per_vuln,
        "balance": args.balance
    }
    
    print(f"\n{'='*60}")
    print(f"Configuration:")
    print(f"  Backend: {backend}")
    print(f"  Model: {model_name}")
    print(f"  Workers: {NUM_WORKERS}")
    print(f"  Max Tokens: {args.tokens}")
    print(f"  Max Retries: {MAX_RETRIES}")
    print(f"  Input: {INPUT_FILE} ({total} items)")
    print(f"  Output: {OUTPUT_FILE}")
    if args.target > 0:
        print(f"  Target: {args.target} samples")
        print(f"  Balance: {args.balance*100:.0f}% vulnerable / {(1-args.balance)*100:.0f}% benign")
    if args.per_vuln > 0:
        print(f"  Per-Vuln Limit: {args.per_vuln}")
    print(f"{'='*60}\n")
    
    logger.info(f"Loaded {total} items. Using {backend} with model: {model_name}")
    logger.info(f"Processing with {NUM_WORKERS} parallel workers...")
    
    # Prioritize items
    prioritized_data = prioritize_work_items(data, limits, total_existing_vul, total_existing_ben)
    
    # Prepare work items
    work_items = [(idx, item, total) for idx, item in enumerate(prioritized_data)]
    
    # Process in parallel
    start_time = time.time()
    
    with Pool(
        processes=NUM_WORKERS,
        initializer=worker_initializer,
        initargs=(counters, limits, backend, model_name, args.tokens)
    ) as pool:
        pool.map(process_item_with_counters, work_items)
    
    elapsed = time.time() - start_time
    
    # Final statistics
    logger.info("=" * 60)
    logger.info(f"Completed in {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    logger.info(f"Final Balance: {format_balance_stats(counters)}")
    logger.info(f"Results saved to {OUTPUT_FILE}")
    
    # Print breakdown
    print(f"\n{'='*60}")
    print("Per-Vulnerability Breakdown:")
    print("-" * 40)
    all_vulns = set(list(counters["vulnerable"].keys()) + list(counters["benign"].keys()))
    for vuln in sorted(all_vulns):
        v_count = counters["vulnerable"].get(vuln, 0)
        b_count = counters["benign"].get(vuln, 0)
        print(f"  {vuln[:35]:35s} VUL:{v_count:3d} BEN:{b_count:3d}")
    print("-" * 40)
    print(f"  {'TOTAL':35s} VUL:{counters['total_vulnerable']:3d} BEN:{counters['total_benign']:3d}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
