#!/usr/bin/env python3
"""
Parallel CPG Query Generator with streaming output.
Supports both Gemini API and LM Studio local models.
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
from typing import Optional, Dict, Tuple, Any

# Configuration
NUM_WORKERS = 2  # Reduced for local models to prevent memory pressure
MAX_RETRIES = 5  # Increased for better success rate
JOERN_TIMEOUT = 60  # seconds per Joern execution
DEFAULT_MAX_TOKENS = 2000  # Token limit for LLM responses
INPUT_FILE = "input_data.json"
OUTPUT_FILE = "valid_dataset.json"
PROGRESS_FILE = "progress.jsonl"  # Streaming results
PROCESSED_FILE = "processed_hashes.json"  # Track already-processed code hashes

# API Endpoints
GEMINI_MODEL = "gemini-3-flash-preview"
LMSTUDIO_API_URL = "http://127.0.0.1:1234/v1"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [PID:%(process)d] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("pipeline.log")
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# JAVA VULNERABILITY PATTERNS - Optimized for Joern CPG Queries
# ============================================================================

JAVA_VULNERABILITY_PATTERNS = {
    "SQL Injection": {
        "sources": ["getParameter", "nextLine", "readLine", "getQueryString", "getInputStream"],
        "sinks": ["executeQuery", "executeUpdate", "execute", "createStatement"],
        "secure_patterns": ["setString", "setInt", "setLong", "PreparedStatement", "prepareStatement"],
        "indicators": ["Statement", "+", "concat", "String.format"],
        "fallback_query": 'cpg.call.name("executeQuery|executeUpdate|execute").where(_.argument.code(".*\\\\+.*"))',
        "examples": [
            'cpg.call.name("executeQuery").where(_.argument.code(".*\\\\+.*"))',
            'cpg.call.name("createStatement").method.ast.isCall.name("executeQuery")'
        ]
    },
    "Command Injection": {
        "sources": ["getParameter", "nextLine", "readLine", "Scanner", "System.in"],
        "sinks": ["exec", "start", "ProcessBuilder", "Runtime.exec"],
        "secure_patterns": ["ProcessBuilder.*--", "allowlist", "whitelist", "validate"],
        "indicators": ["exec", "ProcessBuilder", "bash", "cmd", "sh"],
        "fallback_query": 'cpg.call.name("exec|start").reachableByFlows(cpg.call.name("getParameter|nextLine"))',
        "examples": [
            'cpg.call.name("start").where(_.argument.reachableBy(cpg.call.name("nextLine")))',
            'cpg.call.methodFullName(".*Runtime.exec.*").argument'
        ]
    },
    "Path Traversal": {
        "sources": ["getParameter", "request.getParameter", "args"],
        "sinks": ["File", "FileInputStream", "FileOutputStream", "Paths.get", "resolve", "readAllBytes"],
        "secure_patterns": ["startsWith", "normalize", "toRealPath", "canonicalize", "getCanonicalPath"],
        "indicators": ["File", "Path", "Paths", "FileInputStream"],
        "fallback_query": 'cpg.call.name("<init>").where(_.typeFullName(".*File.*")).argument',
        "examples": [
            'cpg.call.name("resolve").whereNot(_.method.ast.isCall.name("startsWith"))',
            'cpg.call.name("<init>").where(_.typeFullName("java.io.File"))'
        ]
    },
    "Broken Access Control": {
        "sources": ["getParameter", "getAttribute", "getUserId", "getSession"],
        "sinks": ["findById", "getById", "load", "query", "get"],
        "secure_patterns": ["authorize", "checkPermission", "isAuthorized", "hasRole", "canAccess"],
        "indicators": ["repository", "dao", "service", "findBy"],
        "fallback_query": 'cpg.call.name("findById|getById|load").whereNot(_.method.ast.isCall.name(".*check.*|.*authorize.*"))',
        "examples": [
            'cpg.call.name("findById").whereNot(_.method.ast.isCall.name("authorize"))',
            'cpg.method.name(".*get.*").parameter.whereNot(_.method.ast.isCall.name("check"))'
        ]
    },
    "Insecure Deserialization": {
        "sources": ["getInputStream", "FileInputStream", "ByteArrayInputStream", "ObjectInputStream"],
        "sinks": ["readObject", "readUnshared", "XMLDecoder"],
        "secure_patterns": ["ValidatingObjectInputStream", "resolveClass", "allowlist", "ObjectInputFilter"],
        "indicators": ["ObjectInputStream", "readObject", "Serializable"],
        "fallback_query": 'cpg.call.name("readObject").whereNot(_.method.ast.isCall.name("resolveClass"))',
        "examples": [
            'cpg.call.name("readObject")',
            'cpg.call.name("<init>").where(_.typeFullName(".*ObjectInputStream.*"))'
        ]
    },
    "XXE (XML External Entity)": {
        "sources": ["getInputStream", "parse", "DocumentBuilder"],
        "sinks": ["parse", "newDocumentBuilder", "SAXParser.parse"],
        "secure_patterns": ["setFeature", "FEATURE_SECURE_PROCESSING", "setExpandEntityReferences"],
        "indicators": ["DocumentBuilderFactory", "SAXParser", "XMLReader", "parse"],
        "fallback_query": 'cpg.call.name("parse").whereNot(_.method.ast.isCall.name("setFeature"))',
        "examples": [
            'cpg.call.name("parse").whereNot(_.method.ast.isCall.name("setFeature"))',
            'cpg.call.name("newDocumentBuilder")'
        ]
    },
    "Log Injection": {
        "sources": ["getParameter", "nextLine", "readLine", "request.getParameter"],
        "sinks": ["info", "debug", "warn", "error", "log", "println", "severe"],
        "secure_patterns": ["sanitize", "escape", "encode", "replace", "matches"],
        "indicators": ["logger", "log", "Logger", "println"],
        "fallback_query": 'cpg.call.name("info|debug|warn|error|severe").argument.reachableByFlows(cpg.call.name("getParameter"))',
        "examples": [
            'cpg.call.name("info").where(_.argument.reachableBy(cpg.parameter))',
            'cpg.call.name("println").argument'
        ]
    },
    "Open Redirect": {
        "sources": ["getParameter", "request.getParameter", "getAttribute"],
        "sinks": ["sendRedirect", "forward", "setHeader.*Location"],
        "secure_patterns": ["allowlist", "whitelist", "startsWith", "contains", "ALLOWED"],
        "indicators": ["redirect", "sendRedirect", "forward", "Location"],
        "fallback_query": 'cpg.call.name("sendRedirect").argument.reachableByFlows(cpg.call.name("getParameter"))',
        "examples": [
            'cpg.call.name("sendRedirect").whereNot(_.method.ast.isCall.name(".*valid.*|.*allowed.*"))',
            'cpg.call.name("sendRedirect").argument'
        ]
    },
    "TOCTOU (Time-of-check to Time-of-use)": {
        "sources": ["exists", "canRead", "canWrite", "isFile", "isDirectory"],
        "sinks": ["createNewFile", "delete", "read", "write", "mkdir"],
        "secure_patterns": ["synchronized", "lock", "atomic", "Files.move"],
        "indicators": ["exists", "canWrite", "Thread.sleep", "wait"],
        "fallback_query": 'cpg.call.name("exists|canWrite").method.ast.isCall.name("createNewFile|delete|write")',
        "examples": [
            'cpg.call.name("exists").method.ast.isCall.name("createNewFile")',
            'cpg.call.name("canWrite").method.ast.isCall.name("write")'
        ]
    }
}


# ============================================================================
# QUERY PRE-VALIDATION
# ============================================================================

def validate_query_syntax(query: str) -> tuple:
    """Validate query syntax before execution. Returns (is_valid, error_message)."""
    errors = []
    
    # Check for forbidden patterns at the end
    if query.strip().endswith('.p') or query.strip().endswith('.l') or query.strip().endswith('.toList'):
        errors.append("Remove .p, .l, or .toList from end")
    
    # Check for invalid method names commonly confused
    invalid_patterns = [
        ('.methodName(', "Use .name() instead of .methodName()"),
        ('.calls(', "Use .call (singular) instead of .calls"),
        ('.methods(', "Use .method (singular) instead of .methods"),
        ('cpg.call(', "Use cpg.call.name() not cpg.call()"),
    ]
    for pattern, fix in invalid_patterns:
        if pattern in query:
            errors.append(fix)
    
    # Check balanced parentheses
    if query.count('(') != query.count(')'):
        errors.append("Unbalanced parentheses")
    
    # Check balanced quotes
    double_quotes = query.count('"') - query.count('\\"')
    if double_quotes % 2 != 0:
        errors.append("Unbalanced double quotes")
    
    return (len(errors) == 0, "; ".join(errors) if errors else "")


def get_fallback_query(vulnerability: str, is_vulnerable: bool) -> list:
    """Return proven fallback queries for the vulnerability type."""
    patterns = JAVA_VULNERABILITY_PATTERNS.get(vulnerability, {})
    fallback = patterns.get("fallback_query", 'cpg.call')
    
    if is_vulnerable:
        return [fallback]
    else:
        # For benign code, add whereNot to exclude secure patterns
        secure = patterns.get("secure_patterns", ["validate"])
        secure_pattern = "|".join(secure[:2])  # Use first 2 patterns
        return [f'{fallback}.whereNot(_.method.ast.isCall.name(".*{secure_pattern}.*"))']


# ============================================================================
# OPTIMIZED CPG QUERY PROMPTS
# ============================================================================

def build_query_prompt(code: str, vulnerability: str, is_vulnerable: bool) -> str:
    """Build an optimized prompt for Java CPG query generation."""
    
    patterns = JAVA_VULNERABILITY_PATTERNS.get(vulnerability, {})
    sources = patterns.get("sources", ["getParameter"])
    sinks = patterns.get("sinks", ["call"])
    secure = patterns.get("secure_patterns", ["validate"])
    examples = patterns.get("examples", ['cpg.call.name("sink")'])
    
    status = "VULNERABLE" if is_vulnerable else "SECURE"
    
    if is_vulnerable:
        goal = """Your query MUST return NON-EMPTY results because this code IS vulnerable.
Focus on finding the taint flow from source to sink WITHOUT security checks."""
    else:
        goal = """Your query MUST return EMPTY [] because this code has security controls.
Use whereNot() to exclude paths that have sanitization/validation."""
    
    source_list = "|".join(sources[:3])
    sink_list = "|".join(sinks[:3])
    secure_list = "|".join(secure[:2])
    
    prompt = f"""Generate a Joern CPGQL query to detect {vulnerability} in Java code.

CODE STATUS: {status}
{goal}

JAVA CODE:
{code}

VULNERABILITY PATTERNS for {vulnerability}:
- Sources (user input): {", ".join(sources[:4])}
- Sinks (dangerous operations): {", ".join(sinks[:4])}
- Secure patterns to exclude: {", ".join(secure[:3])}

WORKING QUERY EXAMPLES:
{chr(10).join(f"  {ex}" for ex in examples)}

CRITICAL RULES:
1. Output ONLY valid JSON with a "queries" array
2. Queries must be syntactically valid Scala
3. Do NOT use .p, .l, or .toList at the end
4. Use cpg.call.name() not cpg.call() or cpg.methodName()
5. Last query should use reachableByFlows for taint analysis

EXPECTED OUTPUT FORMAT:
```json
{{
  "queries": [
    "val sources = cpg.call.name(\\"{source_list}\\").argument.l",
    "val sinks = cpg.call.name(\\"{sink_list}\\").argument.l",
    "sinks.reachableByFlows(sources).l"
  ]
}}
```
"""
    return prompt


def build_retry_prompt(original_response: str, error_type: str, code: str, vulnerability: str, is_vulnerable: bool, attempt: int = 1) -> str:
    """Build a targeted retry prompt based on the specific error type."""
    
    patterns = JAVA_VULNERABILITY_PATTERNS.get(vulnerability, {})
    fallback = patterns.get("fallback_query", 'cpg.call')
    
    error_guidance = {
        "execution_failed": f"""The query had SYNTAX ERRORS and failed to execute in Joern.

COMMON FIXES:
- Use cpg.call.name() not cpg.call() or cpg.methodName()
- Remove .p, .l, or .toList from end
- Check balanced parentheses and quotes
- Use double backslashes in regex: \\\\ not \\

SIMPLE WORKING PATTERN:
{fallback}""",

        "false_negative": f"""The query returned [] but the code IS VULNERABLE.
Your query was TOO STRICT and missed the vulnerability.

FIX: Make the query LESS restrictive:
- Remove complex filters
- Use broader method name patterns
- Try a simpler data flow query

SIMPLER APPROACH:
{fallback}""",

        "false_positive": f"""The query found results but the code is SECURE.
Your query produced a FALSE POSITIVE.

FIX: Add whereNot() to exclude security patterns:
- .whereNot(_.method.ast.isCall.name(".*{patterns.get('secure_patterns', ['validate'])[0]}.*"))

EXAMPLE:
{fallback}.whereNot(_.method.ast.isCall.name(".*validate.*|.*sanitize.*"))""",

        "invalid_format": """Could not parse your response as JSON.

OUTPUT MUST BE VALID JSON:
```json
{
  "queries": ["query1", "query2", "query3"]
}
```""",

        "invalid_json_joern": """Joern returned invalid JSON output.
Your query syntax may be incorrect or the query structure is wrong.

ENSURE:
- Queries end with .l to materialize results
- No print statements in queries
- Valid Scala syntax"""
    }
    
    guidance = error_guidance.get(error_type, "Query failed. Try a simpler approach.")
    
    # On later attempts, suggest using the fallback
    if attempt >= 3:
        guidance += f"""

IMPORTANT: After multiple failures, try this proven pattern:
{{
  "queries": ["{fallback}"]
}}"""
    
    prompt = f"""RETRY ATTEMPT {attempt}: Previous query failed.

ERROR TYPE: {error_type}
{guidance}

PREVIOUS RESPONSE (FAILED):
{original_response[:500]}...

CODE TO ANALYZE:
{code[:1000]}...

VULNERABILITY: {vulnerability}
STATUS: {"VULNERABLE - query MUST find results" if is_vulnerable else "SECURE - query MUST return empty []"}

OUTPUT VALID JSON:
"""
    return prompt


# ============================================================================
# API HANDLERS
# ============================================================================

def get_args():
    parser = argparse.ArgumentParser(description="Generate CPG Queries with Joern Validation")
    parser.add_argument("--backend", type=str, choices=["gemini", "lmstudio"], default="gemini",
                        help="Backend to use: 'gemini' or 'lmstudio'")
    parser.add_argument("--model", type=str, default=None,
                        help="Model name to use (bypasses interactive selection). For LM Studio use model ID like 'qwen/qwen2.5-coder-14b'")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers")
    parser.add_argument("--tokens", type=int, default=2000, help="Max tokens for LLM response (default: 2000)")
    parser.add_argument("--input", type=str, default="input_data.json", help="Input JSON file")
    parser.add_argument("--output", type=str, default="valid_dataset.json", help="Output JSON file")
    # Balanced sampling arguments
    parser.add_argument("--target", type=int, default=0, help="Target number of samples (0 = no limit)")
    parser.add_argument("--per-vuln", type=int, default=0, dest="per_vuln", help="Max samples per vulnerability type (0 = no limit)")
    parser.add_argument("--balance", type=float, default=0.5, help="Target vulnerable ratio (0.5 = 50/50)")
    return parser.parse_args()


def get_lmstudio_models():
    """Fetch available models from LM Studio API."""
    try:
        response = requests.get(f"{LMSTUDIO_API_URL}/models", timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Filter out embedding models
            return [m["id"] for m in data.get("data", []) if "embed" not in m["id"].lower()]
    except Exception as e:
        print(f"Warning: Could not connect to LM Studio: {e}")
    return []


def select_lmstudio_model(preselected: str = None):
    """Interactive model selection for LM Studio."""
    print("\n" + "="*50)
    print("LM Studio Backend Selected")
    print("="*50)
    print("\nFetching available models from LM Studio...")
    
    models = get_lmstudio_models()
    
    if not models:
        print("ERROR: No models found. Is LM Studio running at http://127.0.0.1:1234?")
        sys.exit(1)
    
    print(f"\nAvailable Models ({len(models)}):")
    for idx, m in enumerate(models, 1):
        print(f"  {idx}. {m}")
    
    # If model was pre-selected via --model argument
    if preselected:
        if preselected in models:
            print(f"\nUsing pre-selected model: {preselected}")
            return preselected
        else:
            # Try to match by number
            try:
                idx = int(preselected) - 1
                if 0 <= idx < len(models):
                    print(f"\nUsing model #{preselected}: {models[idx]}")
                    return models[idx]
            except ValueError:
                pass
            print(f"\nWARNING: Model '{preselected}' not found. Using first available.")
            return models[0]
    
    # Auto-select first model (skip interactive input which has issues)
    print(f"\nAuto-selecting first model: {models[0]}")
    print("(Use --model argument to specify a different model)")
    return models[0]


def save_result_immediately(idx: int, code: str, query: Optional[str], total: int):
    """Save result to progress file immediately with file locking."""
    result = {
        "index": idx,
        "input": code,
        "output": query if query else "FAILED",
        "total": total
    }
    
    # Use file locking to prevent race conditions
    with open(PROGRESS_FILE, 'a') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write(json.dumps(result) + "\n")
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def init_gemini():
    """Initialize Gemini client - called once per worker process."""
    import google.generativeai as genai
    from dotenv import load_dotenv
    load_dotenv()
    
    api_key = os.getenv("GEMINI_API_KEY")
    genai.configure(api_key=api_key)
    return genai.GenerativeModel(GEMINI_MODEL)


def call_gemini(model, prompt: str) -> str:
    """Call Gemini API synchronously."""
    import google.generativeai as genai
    
    for attempt in range(3):
        try:
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(temperature=0.2)
            )
            text = response.text.strip()
            
            # Clean markdown if present
            if "```" in text:
                # Extract content between code blocks
                import re
                match = re.search(r'```(?:scala|java)?\s*(.*?)```', text, re.DOTALL)
                if match:
                    text = match.group(1).strip()
                else:
                    # Remove any remaining backticks
                    text = text.replace("```scala", "").replace("```java", "").replace("```", "").strip()
            
            return text
        except Exception as e:
            if "429" in str(e):
                time.sleep(2 ** attempt)
            else:
                raise
    raise Exception("Gemini retries exhausted")


def call_lmstudio(model_name: str, prompt: str, max_tokens: int = 2000) -> str:
    """Call LM Studio API synchronously."""
    payload = {
        "model": model_name,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "max_tokens": max_tokens
    }
    
    for attempt in range(3):
        try:
            response = requests.post(
                f"{LMSTUDIO_API_URL}/chat/completions",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=180  # Longer timeout for local models
            )
            
            if response.status_code != 200:
                raise Exception(f"LM Studio error: {response.status_code} - {response.text}")
            
            data = response.json()
            if 'choices' in data and len(data['choices']) > 0:
                text = data['choices'][0]['message']['content'].strip()
                
                # Remove thinking tags if present (for reasoning models)
                if "</think>" in text:
                    text = text.split("</think>")[-1].strip()
                
                # Clean markdown if present
                if "```" in text:
                    import re
                    match = re.search(r'```(?:scala|java|json)?\s*(.*?)```', text, re.DOTALL)
                    if match:
                        text = match.group(1).strip()
                    else:
                        text = text.replace("```scala", "").replace("```java", "").replace("```json", "").replace("```", "").strip()
                
                return text
            else:
                raise Exception("No choices in response")
                
        except Exception as e:
            if attempt < 2:
                time.sleep(2 ** attempt)
            else:
                raise
    
    raise Exception("LM Studio retries exhausted")


def run_joern_script(code: str, queries: list, workspace: str) -> Optional[str]:
    """Execute Joern queries via CLI and return JSON result."""
    # Clean workspace
    if os.path.exists(workspace):
        shutil.rmtree(workspace)
    os.makedirs(workspace, exist_ok=True)
    
    # Write code file
    code_file = os.path.join(workspace, "target.java")
    with open(code_file, "w") as f:
        f.write(code)
    
    # Create Joern script
    # Join all queries, ensure last one outputs JSON
    queries_block = "\n".join(queries[:-1])
    last_query = queries[-1]
    
    script_content = f'''
importCode("{code_file}")
try {{
    {queries_block}
    val res = ({last_query}).toJson
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
    with open(script_file, "w") as f:
        f.write(script_content)
    
    # Run Joern
    try:
        result = subprocess.run(
            ["joern", "--script", script_file],
            capture_output=True,
            text=True,
            timeout=JOERN_TIMEOUT
        )
        output = result.stdout
        
        if "JOERN_JSON_START" in output:
            json_str = output.split("JOERN_JSON_START")[1].split("JOERN_JSON_END")[0].strip()
            return json_str
        elif "JOERN_ERROR_START" in output:
            return None
        else:
            return None
            
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


# Worker initialization for multiprocessing
_worker_model = None
_worker_backend = None
_worker_model_name = None
_worker_max_tokens = 2000

def init_worker(backend: str, model_name: str, max_tokens: int = 2000):
    """Initialize worker with the appropriate model."""
    global _worker_model, _worker_backend, _worker_model_name, _worker_max_tokens
    _worker_backend = backend
    _worker_model_name = model_name
    _worker_max_tokens = max_tokens
    
    if backend == "gemini":
        _worker_model = init_gemini()
    else:
        _worker_model = None  # LM Studio uses HTTP, no persistent client needed


def call_model(prompt: str) -> str:
    """Call the appropriate model based on backend."""
    global _worker_model, _worker_backend, _worker_model_name, _worker_max_tokens
    
    if _worker_backend == "gemini":
        return call_gemini(_worker_model, prompt)
    else:
        return call_lmstudio(_worker_model_name, prompt, _worker_max_tokens)



def save_entry_immediately(data_entry: Dict):
    """Securely append entry to valid_dataset.json using file locking."""
    # Initialize file if not exists
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'w') as f:
            json.dump([], f)
            
    with open(OUTPUT_FILE, 'r+') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            content = f.read()
            if not content:
                current_data = []
            else:
                try:
                    current_data = json.loads(content)
                except:
                    current_data = []
            
            # Check for duplicates or updates (optional, here we append)
            current_data.append(data_entry)
            
            f.seek(0)
            f.truncate()
            json.dump(current_data, f, indent=2)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)



def format_output_queries(queries: list) -> str:
    """Format queries list using single quotes for the elements to match sample dataset."""
    items = []
    for q in queries:
        # Escape backslashes and single quotes
        # We want the string content to look like: 'val x = "foo"'
        # So we escape \ to \\ and ' to \'
        escaped = q.replace('\\', '\\\\').replace("'", "\\'")
        items.append(f"'{escaped}'")
    return "[" + ", ".join(items) + "]"


def parse_llm_response(response: str) -> list:
    """Parse list of strings from LLM response which might be JSON or Python list string."""
    try:
        data = json.loads(response)
        if isinstance(data, dict):
            return data.get("queries", [])
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
        
    try:
        # Try evaluating as python literal (handles single quotes)
        data = ast.literal_eval(response)
        if isinstance(data, dict):
            return data.get("queries", [])
        if isinstance(data, list):
            return data
    except (ValueError, SyntaxError):
        pass
        
    return []


# ============================================================================
# BALANCED SAMPLING HELPERS
# ============================================================================

def should_skip_item(vulnerability: str, is_vulnerable: bool, counters: Dict, limits: Dict) -> bool:
    """Check if this item's category has reached its limit."""
    if limits["target"] == 0 and limits["per_vuln"] == 0:
        return False  # No limits set
    
    category = "vulnerable" if is_vulnerable else "benign"
    
    # Check total target
    if limits["target"] > 0:
        total = counters["total_vulnerable"] + counters["total_benign"]
        if total >= limits["target"]:
            return True
    
    # Check per-vulnerability limit
    if limits["per_vuln"] > 0:
        current = counters[category].get(vulnerability, 0)
        if current >= limits["per_vuln"]:
            return True
    
    # Check balance ratio (don't let one category get too far ahead)
    if limits["target"] > 0:
        target_vul = int(limits["target"] * limits["balance"])
        target_ben = limits["target"] - target_vul
        
        if is_vulnerable and counters["total_vulnerable"] >= target_vul:
            return True
        if not is_vulnerable and counters["total_benign"] >= target_ben:
            return True
    
    return False


def increment_counter(vulnerability: str, is_vulnerable: bool, counters: Dict) -> None:
    """Increment the appropriate counter after successful processing."""
    category = "vulnerable" if is_vulnerable else "benign"
    
    # Increment per-vulnerability counter
    if vulnerability not in counters[category]:
        counters[category][vulnerability] = 0
    counters[category][vulnerability] = counters[category].get(vulnerability, 0) + 1
    
    # Increment total counter
    if is_vulnerable:
        counters["total_vulnerable"] = counters.get("total_vulnerable", 0) + 1
    else:
        counters["total_benign"] = counters.get("total_benign", 0) + 1


def format_balance_stats(counters: Dict) -> str:
    """Format current balance statistics for logging."""
    vul = counters.get("total_vulnerable", 0)
    ben = counters.get("total_benign", 0)
    total = vul + ben
    ratio = vul / total * 100 if total > 0 else 0
    return f"VUL:{vul} BEN:{ben} ({ratio:.1f}% vulnerable)"


def prioritize_work_items(data: list, limits: Dict, current_vul: int = 0, current_ben: int = 0) -> list:
    """
    Sort work items to prioritize underrepresented categories and balance across vulnerability types.
    This ensures the target balance ratio is achieved as quickly as possible.
    
    Strategy:
    1. Calculate how many of each category we need to reach target balance
    2. Front-load the underrepresented category to catch up
    3. Then alternate normally based on target ratio
    4. Within each category, round-robin across vulnerability types
    """
    if limits["target"] == 0 and limits["per_vuln"] == 0:
        return data  # No limits, keep original order
    
    # Separate by status
    vulnerable_items = [item for item in data if item.get('status', '').lower() == 'vulnerable']
    benign_items = [item for item in data if item.get('status', '').lower() != 'vulnerable']
    
    # Group by vulnerability type for round-robin distribution
    def group_by_vuln(items):
        groups = {}
        for item in items:
            vuln = item.get('vulnerability', 'Unknown')
            if vuln not in groups:
                groups[vuln] = []
            groups[vuln].append(item)
        return groups
    
    vul_groups = group_by_vuln(vulnerable_items)
    ben_groups = group_by_vuln(benign_items)
    
    # Round-robin within each category to spread across vulnerability types
    def round_robin(groups):
        result = []
        iterators = {k: iter(v) for k, v in groups.items()}
        while iterators:
            exhausted = []
            for vuln, it in list(iterators.items()):
                try:
                    result.append(next(it))
                except StopIteration:
                    exhausted.append(vuln)
            for vuln in exhausted:
                del iterators[vuln]
        return result
    
    sorted_vulnerable = round_robin(vul_groups)
    sorted_benign = round_robin(ben_groups)
    
    # Calculate target counts and current deficit
    target_ratio = limits.get("balance", 0.5)
    target_total = limits.get("target", 1000)
    
    target_vul = int(target_total * target_ratio)
    target_ben = target_total - target_vul
    
    # How many more of each do we need?
    needed_vul = max(0, target_vul - current_vul)
    needed_ben = max(0, target_ben - current_ben)
    
    # Calculate current ratio and deficit
    total_current = current_vul + current_ben
    current_ratio = current_vul / total_current if total_current > 0 else 0.5
    
    # Determine which category needs to catch up
    vul_deficit = target_ratio - current_ratio  # Positive = need more vulnerable
    
    logger.info(f"Current: VUL:{current_vul} BEN:{current_ben} ({current_ratio*100:.1f}% vulnerable)")
    logger.info(f"Target: {target_ratio*100:.0f}% vulnerable. Deficit: {vul_deficit*100:+.1f}%")
    
    result = []
    vul_idx = 0
    ben_idx = 0
    
    # Phase 1: Front-load the underrepresented category to catch up
    if vul_deficit > 0.02:  # Need more vulnerable (>2% deficit)
        # Calculate how many extra vulnerable to process first
        catch_up_count = min(
            int(abs(vul_deficit) * total_current) + 5,  # Deficit + buffer
            len(sorted_vulnerable),
            needed_vul
        )
        logger.info(f"Prioritizing {catch_up_count} vulnerable items first to catch up")
        
        for _ in range(catch_up_count):
            if vul_idx < len(sorted_vulnerable):
                result.append(sorted_vulnerable[vul_idx])
                vul_idx += 1
                
    elif vul_deficit < -0.02:  # Need more benign (>2% deficit)
        catch_up_count = min(
            int(abs(vul_deficit) * total_current) + 5,
            len(sorted_benign),
            needed_ben
        )
        logger.info(f"Prioritizing {catch_up_count} benign items first to catch up")
        
        for _ in range(catch_up_count):
            if ben_idx < len(sorted_benign):
                result.append(sorted_benign[ben_idx])
                ben_idx += 1
    
    # Phase 2: Interleave remaining items 1:1 (since target is 50/50)
    while vul_idx < len(sorted_vulnerable) or ben_idx < len(sorted_benign):
        if vul_idx < len(sorted_vulnerable):
            result.append(sorted_vulnerable[vul_idx])
            vul_idx += 1
        if ben_idx < len(sorted_benign):
            result.append(sorted_benign[ben_idx])
            ben_idx += 1
    
    logger.info(f"Prioritized work items: {len(sorted_vulnerable)} vulnerable, {len(sorted_benign)} benign")
    
    return result





def process_single_item(args: Tuple[int, Dict, int, str, str, int]) -> Tuple[int, Optional[str]]:
    """
    Process a single item. This runs in a separate process.
    Returns (index, query_or_none)
    """
    idx, item, total, backend, model_name, max_tokens = args
    
    # Initialize worker model if not done
    init_worker(backend, model_name, max_tokens)
    
    code = item['code']
    vulnerability = item['vulnerability']
    is_vulnerable = item['status'].lower() == 'vulnerable'
    status_str = "VUL" if is_vulnerable else "BEN"
    
    workspace = f"/tmp/joern_worker_{os.getpid()}"
    
    logger.info(f"[{idx+1}/{total}] Processing: {vulnerability[:30]}... ({status_str})")
    
    result_queries = None
    
    try:
        # Generate initial query with comprehensive prompt
        prompt = build_query_prompt(code, vulnerability, is_vulnerable)
        current_response_text = call_model(prompt)
        
        for attempt in range(1, MAX_RETRIES + 1):
            queries = parse_llm_response(current_response_text)
            
            if not queries:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Could not parse queries from response")
                if attempt < MAX_RETRIES:
                    # Use fallback on later attempts
                    if attempt >= 3:
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                        logger.info(f"[{idx+1}/{total}] Using fallback query for attempt {attempt}")
                    else:
                        current_response_text = call_model(build_retry_prompt(
                            current_response_text, "invalid_format", code, vulnerability, is_vulnerable, attempt
                        ))
                        continue
                else:
                    continue
            
            # Pre-validate queries before sending to Joern
            all_valid = True
            for q in queries:
                is_valid, error_msg = validate_query_syntax(q)
                if not is_valid:
                    logger.warning(f"[{idx+1}/{total}] Query validation failed: {error_msg}")
                    all_valid = False
                    break
            
            if not all_valid:
                if attempt < MAX_RETRIES:
                    # Try to get a fixed query
                    if attempt >= 3:
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                        logger.info(f"[{idx+1}/{total}] Using fallback query after validation failure")
                    else:
                        current_response_text = call_model(build_retry_prompt(
                            current_response_text, "execution_failed", code, vulnerability, is_vulnerable, attempt
                        ))
                        continue
                else:
                    continue

            result = run_joern_script(code, queries, workspace)
            
            if result is None:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Query execution failed")
                if attempt < MAX_RETRIES:
                    if attempt >= 4:
                        # Last resort: use the simplest fallback
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                        logger.info(f"[{idx+1}/{total}] Using fallback query after execution failure")
                    else:
                        retry_prompt = build_retry_prompt(
                            current_response_text, "execution_failed", code, vulnerability, is_vulnerable, attempt
                        )
                        current_response_text = call_model(retry_prompt)
                continue
            
            try:
                data = json.loads(result)
                if not isinstance(data, list):
                    data = [data]
                is_empty = len(data) == 0
                
                if is_vulnerable:
                    if is_empty:
                        logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: False negative (query returned [] for vulnerable code)")
                        if attempt < MAX_RETRIES:
                            retry_prompt = build_retry_prompt(
                                current_response_text, "false_negative", code, vulnerability, is_vulnerable, attempt
                            )
                            current_response_text = call_model(retry_prompt)
                        continue
                    else:
                        # Success - query found the vulnerability
                        logger.info(f"[{idx+1}/{total}] ✓ SUCCESS")
                        result_queries = queries
                        break
                else:
                    if not is_empty:
                        logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: False positive (query found results for benign code)")
                        if attempt < MAX_RETRIES:
                            retry_prompt = build_retry_prompt(
                                current_response_text, "false_positive", code, vulnerability, is_vulnerable, attempt
                            )
                            current_response_text = call_model(retry_prompt)
                        continue
                    else:
                        # Success - query correctly returned empty for benign code
                        logger.info(f"[{idx+1}/{total}] ✓ SUCCESS")
                        result_queries = queries
                        break
                        
            except json.JSONDecodeError:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Invalid JSON output from Joern")
                if attempt < MAX_RETRIES:
                    retry_prompt = build_retry_prompt(
                        current_response_text, "invalid_json_joern", code, vulnerability, is_vulnerable, attempt
                    )
                    current_response_text = call_model(retry_prompt)
                continue
        
        if result_queries is None:
            logger.error(f"[{idx+1}/{total}] ✗ FAILED after {MAX_RETRIES} attempts")
        else:
            # Save successful result immediately
            # Use single-quoted list format for better readability/compatibility
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
        # Cleanup
        if os.path.exists(workspace):
            try:
                shutil.rmtree(workspace)
            except:
                pass
    
    return (idx, result_queries)


# Global references for shared state (set by initializer)
_shared_counters = None
_shared_limits = None

def worker_initializer(counters, limits, backend: str, model_name: str, max_tokens: int):
    """Initialize worker with shared counters and model."""
    global _shared_counters, _shared_limits
    _shared_counters = counters
    _shared_limits = limits
    init_worker(backend, model_name, max_tokens)


def process_item_with_counters(args: Tuple[int, Dict, int]) -> Tuple[int, Optional[str]]:
    """
    Process a single item with access to shared counters.
    """
    global _shared_counters, _shared_limits
    
    idx, item, total = args
    
    code = item['code']
    vulnerability = item['vulnerability']
    is_vulnerable = item['status'].lower() == 'vulnerable'
    status_str = "VUL" if is_vulnerable else "BEN"
    
    # Check if we should skip this item based on limits
    if _shared_limits and should_skip_item(vulnerability, is_vulnerable, _shared_counters, _shared_limits):
        logger.info(f"[{idx+1}/{total}] SKIP: {vulnerability[:25]}... ({status_str}) - limit reached")
        return (idx, None)
    
    workspace = f"/tmp/joern_worker_{os.getpid()}"
    
    logger.info(f"[{idx+1}/{total}] Processing: {vulnerability[:30]}... ({status_str})")
    
    result_queries = None
    
    try:
        # Generate initial query with comprehensive prompt
        prompt = build_query_prompt(code, vulnerability, is_vulnerable)
        current_response_text = call_model(prompt)
        
        for attempt in range(1, MAX_RETRIES + 1):
            queries = parse_llm_response(current_response_text)
            
            if not queries:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Could not parse queries from response")
                if attempt < MAX_RETRIES:
                    if attempt >= 3:
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                        logger.info(f"[{idx+1}/{total}] Using fallback query for attempt {attempt}")
                    else:
                        current_response_text = call_model(build_retry_prompt(
                            current_response_text, "invalid_format", code, vulnerability, is_vulnerable, attempt
                        ))
                        continue
                else:
                    continue
            
            # Pre-validate queries before sending to Joern
            all_valid = True
            for q in queries:
                is_valid, error_msg = validate_query_syntax(q)
                if not is_valid:
                    logger.warning(f"[{idx+1}/{total}] Query validation failed: {error_msg}")
                    all_valid = False
                    break
            
            if not all_valid:
                if attempt < MAX_RETRIES:
                    if attempt >= 3:
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                        logger.info(f"[{idx+1}/{total}] Using fallback query after validation failure")
                    else:
                        current_response_text = call_model(build_retry_prompt(
                            current_response_text, "execution_failed", code, vulnerability, is_vulnerable, attempt
                        ))
                        continue
                else:
                    continue

            result = run_joern_script(code, queries, workspace)
            
            if result is None:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Query execution failed")
                if attempt < MAX_RETRIES:
                    if attempt >= 4:
                        queries = get_fallback_query(vulnerability, is_vulnerable)
                        logger.info(f"[{idx+1}/{total}] Using fallback query after execution failure")
                    else:
                        retry_prompt = build_retry_prompt(
                            current_response_text, "execution_failed", code, vulnerability, is_vulnerable, attempt
                        )
                        current_response_text = call_model(retry_prompt)
                continue
            
            try:
                data = json.loads(result)
                if not isinstance(data, list):
                    data = [data]
                is_empty = len(data) == 0
                
                if is_vulnerable:
                    if is_empty:
                        logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: False negative (query returned [] for vulnerable code)")
                        if attempt < MAX_RETRIES:
                            retry_prompt = build_retry_prompt(
                                current_response_text, "false_negative", code, vulnerability, is_vulnerable, attempt
                            )
                            current_response_text = call_model(retry_prompt)
                        continue
                    else:
                        # Success - query found the vulnerability
                        result_queries = queries
                        break
                else:
                    if not is_empty:
                        logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: False positive (query found results for benign code)")
                        if attempt < MAX_RETRIES:
                            retry_prompt = build_retry_prompt(
                                current_response_text, "false_positive", code, vulnerability, is_vulnerable, attempt
                            )
                            current_response_text = call_model(retry_prompt)
                        continue
                    else:
                        # Success - query correctly returned empty for benign code
                        result_queries = queries
                        break
                        
            except json.JSONDecodeError:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Invalid JSON output from Joern")
                if attempt < MAX_RETRIES:
                    retry_prompt = build_retry_prompt(
                        current_response_text, "invalid_json_joern", code, vulnerability, is_vulnerable, attempt
                    )
                    current_response_text = call_model(retry_prompt)
                continue
        
        if result_queries is None:
            logger.error(f"[{idx+1}/{total}] ✗ FAILED after {MAX_RETRIES} attempts")
        else:
            # Increment counters on success
            if _shared_counters is not None:
                increment_counter(vulnerability, is_vulnerable, _shared_counters)
            
            # Log success with balance stats
            stats = format_balance_stats(_shared_counters) if _shared_counters else ""
            logger.info(f"[{idx+1}/{total}] ✓ SUCCESS | {stats}")
            
            # Save successful result immediately
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
        # Cleanup
        if os.path.exists(workspace):
            try:
                shutil.rmtree(workspace)
            except:
                pass
    
    return (idx, result_queries)



def main():
    global NUM_WORKERS, INPUT_FILE, OUTPUT_FILE
    
    args = get_args()
    
    # Update globals from args
    NUM_WORKERS = args.workers
    INPUT_FILE = args.input
    OUTPUT_FILE = args.output
    backend = args.backend
    
    # Select model based on backend
    if backend == "lmstudio":
        model_name = select_lmstudio_model(args.model)
    else:
        model_name = args.model if args.model else GEMINI_MODEL
        print(f"\nUsing Gemini model: {model_name}")
    
    # Load existing output data if present
    existing_entries = []
    existing_vulnerable = {}
    existing_benign = {}
    total_existing_vul = 0
    total_existing_ben = 0
    
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r') as f:
                existing_entries = json.load(f)
            
            # Parse existing entries to count vulnerabilities
            for entry in existing_entries:
                instruction = entry.get("instruction", "")
                input_code = entry.get("input", "")
                
                # Extract vulnerability type from instruction
                # Format: "Write a Joern CPG query to detect {vulnerability}."
                import re
                match = re.search(r"detect (.+?)\.", instruction)
                vuln_type = match.group(1) if match else "Unknown"
                
                # Determine if vulnerable or benign based on query patterns
                # Vulnerable queries typically find results, benign return empty
                output = entry.get("output", "")
                
                # We need to check the input code for status hints
                # Check for common secure patterns in the input code
                secure_patterns = ["PreparedStatement", "setString", "setFeature", "ALLOWED", "whitelist", "allowlist", "normalize", "startsWith", "ObjectInputFilter"]
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
    
    # Build set of already-processed code hashes from existing entries
    processed_hashes = set()
    for entry in existing_entries:
        input_code = entry.get("input", "")
        code_hash = hashlib.md5(input_code.encode()).hexdigest()
        processed_hashes.add(code_hash)
    
    # Initialize output file with existing data (or empty if none)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(existing_entries, f, indent=2)
    
    # Load input data
    with open(INPUT_FILE, 'r') as f:
        data = json.load(f)
    
    original_count = len(data)
    
    # Filter out already-processed items
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
    
    # Setup shared counters using Manager, initialized with existing counts
    manager = Manager()
    
    # Create nested manager dicts for per-vuln counts
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
    print(f"  Output: {OUTPUT_FILE} (streaming updates)")
    if args.target > 0:
        print(f"  Target: {args.target} samples")
        print(f"  Balance: {args.balance*100:.0f}% vulnerable / {(1-args.balance)*100:.0f}% benign")
    if args.per_vuln > 0:
        print(f"  Per-Vuln Limit: {args.per_vuln}")
    print(f"{'='*60}\n")
    
    logger.info(f"Loaded {total} items. Using {backend} with model: {model_name}")
    logger.info(f"Processing with {NUM_WORKERS} parallel workers...")
    
    # Prioritize items to balance categories and vulnerability types
    # Pass current counts so it can front-load underrepresented category
    prioritized_data = prioritize_work_items(data, limits, total_existing_vul, total_existing_ben)
    
    # Prepare arguments: (index, item, total)
    work_items = [(idx, item, total) for idx, item in enumerate(prioritized_data)]
    
    # Process in parallel using multiprocessing Pool with initializer
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
    
    # Print per-vulnerability breakdown
    print(f"\n{'='*60}")
    print("Per-Vulnerability Breakdown:")
    print("-" * 40)
    all_vulns = set(list(counters["vulnerable"].keys()) + list(counters["benign"].keys()))
    for vuln in sorted(all_vulns):
        v_count = counters["vulnerable"].get(vuln, 0)
        b_count = counters["benign"].get(vuln, 0)
        print(f"  {vuln[:30]:30s} VUL:{v_count:3d} BEN:{b_count:3d}")
    print("-" * 40)
    print(f"  {'TOTAL':30s} VUL:{counters['total_vulnerable']:3d} BEN:{counters['total_benign']:3d}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

