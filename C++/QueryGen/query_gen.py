#!/usr/bin/env python3
"""
C++ CPG Query Generator
Generates and validates Joern CPGQL queries for C++ code vulnerabilities.
Adapted from Python query generator.
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
import re
from multiprocessing import Pool, Manager
import ast
from typing import Optional, Tuple, Dict, List

# ===== CONFIGURATION =====
NUM_WORKERS = 4
MAX_RETRIES = 3
JOERN_TIMEOUT = 60
DEFAULT_MAX_TOKENS = 4096

# API Configuration
LMSTUDIO_API_URL = "http://localhost:1234/v1/chat/completions"

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


# ===== C++ VULNERABILITY PATTERNS =====
CPP_VULNERABILITY_PATTERNS = {
    "Buffer Overflow": {
        "sources": ["fgets", "read", "recv", "scanf", "gets", "getenv", "argv"],
        "sinks": ["strcpy", "sprintf", "strcat", "memcpy", "gets", "scanf"],
        "secure_patterns": ["strncpy", "snprintf", "strncat", "memcpy_s", "scanf_s", "fgets"],
        "indicators": ["strcpy", "sprintf", "buffer", "char[]", "memcpy"],
        "fallback_query": 'cpg.call.name("strcpy|sprintf|strcat|gets").where(_.argument.code(".*argv.*|.*getenv.*|.*fgets.*"))',
        "examples": [
            'cpg.call.name("strcpy").where(_.argument.reachableBy(cpg.call.name("fgets|recv|read")))',
            'cpg.call.name("sprintf").whereNot(_.method.ast.isCall.name("snprintf"))'
        ]
    },
    "Command Injection": {
        "sources": ["getenv", "argv", "fgets", "recv", "read", "scanf"],
        "sinks": ["system", "popen", "exec", "execl", "execv", "execve", "fork"],
        "secure_patterns": ["allowlist", "whitelist", "validate", "sanitize", "escape"],
        "indicators": ["system(", "popen(", "exec", "shell", "cmd"],
        "fallback_query": 'cpg.call.name("system|popen|exec.*").where(_.argument.code(".*getenv.*|.*argv.*"))',
        "examples": [
            'cpg.call.name("system").where(_.argument.reachableBy(cpg.call.name("getenv|fgets")))',
            'cpg.call.name("popen").reachableByFlows(cpg.identifier.name("argv"))'
        ]
    },
    "Format String Vulnerability": {
        "sources": ["argv", "fgets", "getenv", "recv", "read"],
        "sinks": ["printf", "fprintf", "sprintf", "snprintf", "syslog", "vsprintf"],
        "secure_patterns": ["%s", "format_string_literal"],
        "indicators": ["printf(", "fprintf(", "syslog("],
        "fallback_query": 'cpg.call.name("printf|fprintf|syslog").where(_.argument(0).isIdentifier)',
        "examples": [
            'cpg.call.name("printf").where(_.argument(0).reachableBy(cpg.call.name("fgets")))',
            'cpg.call.name("syslog").whereNot(_.argument.code(".*%s.*"))'
        ]
    },
    "SQL Injection": {
        "sources": ["argv", "getenv", "fgets", "recv", "read"],
        "sinks": ["sqlite3_exec", "mysql_query", "PQexec", "execute"],
        "secure_patterns": ["sqlite3_prepare", "sqlite3_bind", "prepared_statement", "parameterized"],
        "indicators": ["sqlite3_exec", "mysql_query", "+", "sprintf"],
        "fallback_query": 'cpg.call.name("sqlite3_exec|mysql_query").where(_.argument.code(".*\\\\+.*|.*sprintf.*"))',
        "examples": [
            'cpg.call.name("sqlite3_exec").where(_.argument.code(".*\\\\+.*"))',
            'cpg.call.name("sqlite3_exec").whereNot(_.method.ast.isCall.name("sqlite3_prepare"))'
        ]
    },
    "Path Traversal": {
        "sources": ["argv", "getenv", "fgets", "recv"],
        "sinks": ["fopen", "open", "ifstream", "ofstream", "freopen", "opendir"],
        "secure_patterns": ["realpath", "basename", "validate", "canonicalize", "startsWith"],
        "indicators": ["fopen", "open", "File", "path"],
        "fallback_query": 'cpg.call.name("fopen|open").where(_.argument(0).reachableBy(cpg.call.name("getenv|fgets")))',
        "examples": [
            'cpg.call.name("fopen").whereNot(_.method.ast.isCall.name("realpath|basename"))',
            'cpg.call.name("open").where(_.argument.reachableBy(cpg.identifier.name("argv")))'
        ]
    },
    "Use-After-Free": {
        "sources": ["free", "delete"],
        "sinks": ["*", "->"],
        "secure_patterns": ["nullptr", "NULL", "= 0"],
        "indicators": ["free(", "delete ", "ptr", "->"],
        "fallback_query": 'cpg.call.name("free").method.ast.isCall.where(_.lineNumber > cpg.call.name("free").lineNumber)',
        "examples": [
            'cpg.call.name("free").method.ast.isIdentifier.name(cpg.call.name("free").argument.code)',
            'cpg.call.name("free").whereNot(_.method.ast.isLiteral.code("nullptr|NULL"))'
        ]
    },
    "Integer Overflow": {
        "sources": ["argv", "atoi", "strtol", "strtoul", "recv", "read"],
        "sinks": ["malloc", "calloc", "new", "array_index"],
        "secure_patterns": ["check", "validate", "SIZE_MAX", "overflow"],
        "indicators": ["malloc(", "calloc(", "new[", "atoi("],
        "fallback_query": 'cpg.call.name("malloc|calloc").where(_.argument.isCall.name("atoi|strtol"))',
        "examples": [
            'cpg.call.name("malloc").where(_.argument.isCall.name("atoi"))',
            'cpg.call.name("calloc").whereNot(_.method.ast.isCall.name(".*check.*"))'
        ]
    },
    "Double Free": {
        "sources": ["free", "delete"],
        "sinks": ["free", "delete"],
        "secure_patterns": ["= nullptr", "= NULL", "= 0"],
        "indicators": ["free(", "delete "],
        "fallback_query": 'cpg.call.name("free").where(_.argument.code(cpg.call.name("free").argument.code))',
        "examples": [
            'cpg.call.name("free").method.call.name("free").where(_.argument.code.matches(cpg.call.name("free").argument.code.head))',
            'cpg.method.call.name("free").l.groupBy(_.argument.code).filter(_._2.size > 1)'
        ]
    },
    "Null Pointer Dereference": {
        "sources": ["malloc", "calloc", "fopen", "new"],
        "sinks": ["*", "->", "."],
        "secure_patterns": ["!= nullptr", "!= NULL", "!= 0", "if ("],
        "indicators": ["ptr", "->", "malloc", "fopen"],
        "fallback_query": 'cpg.call.name("malloc|fopen").method.ast.isCall.whereNot(_.method.ast.isControlStructure)',
        "examples": [
            'cpg.call.name("malloc").whereNot(_.method.ast.isControlStructure.code(".*!= NULL.*"))',
            'cpg.call.name("fopen").method.ast.isCall.name("fread|fwrite")'
        ]
    },
    "Memory Leak": {
        "sources": ["malloc", "calloc", "realloc", "new"],
        "sinks": ["return", "exit", "abort"],
        "secure_patterns": ["free", "delete", "smart_ptr", "unique_ptr", "shared_ptr"],
        "indicators": ["malloc(", "new ", "return"],
        "fallback_query": 'cpg.call.name("malloc|calloc").whereNot(_.method.ast.isCall.name("free"))',
        "examples": [
            'cpg.call.name("malloc").whereNot(_.method.ast.isCall.name("free"))',
            'cpg.call.name("new").method.whereNot(_.ast.isCall.name("delete"))'
        ]
    }
}


# ===== WORKING QUERY TEMPLATES =====
# Multiple varied templates per vulnerability to avoid overfitting
# Each template uses different query patterns to teach the model variety
WORKING_QUERY_TEMPLATES = {
    "Buffer Overflow": {
        "vulnerable": [
            # Template 1: Security Grade (Combined Array Check + Taint)
            ['cpg.call.name("strcpy|strcat|sprintf").where(_.argument(1).isIdentifier.refsTo.collectAll[Local].typeFullName(".*\\\\[.*\\\\]")).where(_.argument(2).reachableBy(cpg.parameter)).l'],
            # Template 2: Taint flow from valid sources
            ['val sources = cpg.call.name("fgets|recv|read|getenv").argument.l',
             'val sinks = cpg.call.name("strcpy|strcat|sprintf|memcpy").argument.l',
             'sinks.reachableByFlows(sources).l'],
            # Template 3: Unsafe copy into fixed-size array (FIXED SYNTAX)
            ['cpg.call.name("strcpy|strcat|sprintf").where(_.argument(1).isIdentifier.refsTo.collectAll[Local].typeFullName(".*\\\\[.*\\\\]")).l'],
            # Template 4: Argument coming from parameter
            ['cpg.call.name("strcpy|memcpy").where(_.argument(2).reachableBy(cpg.parameter)).l'],
        ],
        "benign": [
            ['cpg.call.name("strcpy|strcat|sprintf|memcpy|gets|scanf").where(_.argument(1).reachableBy(cpg.parameter)).l'],
            ['val sources = cpg.call.name("fgets|recv|read|getenv|argv").argument.l',
             'val sinks = cpg.call.name("strcpy|strcat|sprintf|memcpy").argument.l',
             'sinks.reachableByFlows(sources).l'],
        ]
    },
    "Command Injection": {
        "vulnerable": [
            # Template 1: Taint flow from valid sources
            ['val sources = cpg.call.name("getenv|fgets|recv|read").argument.l',
             'val sinks = cpg.call.name("system|popen|exec.*").argument.l',
             'sinks.reachableByFlows(sources).l'],
            # Template 2: Direct call with argument from input
            ['cpg.call.name("system|popen").where(_.argument(1).reachableBy(cpg.call.name("getenv|fgets"))).l'],
        ],
        "benign": [
            ['cpg.call.name("system|popen|exec.*").where(_.argument(1).reachableBy(cpg.parameter)).l'],
            ['val sources = cpg.call.name("getenv|fgets|recv|read").argument.l',
             'val sinks = cpg.call.name("system|popen|exec.*").argument.l',
             'sinks.reachableByFlows(sources).l'],
        ]
    },
    "SQL Injection": {
        "vulnerable": [
            # Template 1: Concatenation in query string
            ['cpg.call.name("sqlite3_exec|mysql_query").where(_.argument(1).code(".*\\\\+.*|.*sprintf.*")).l'],
            # Template 2: Taint flow to execute
            ['val sources = cpg.call.name("fgets|argv|getenv").argument.l',
             'val sinks = cpg.call.name("sqlite3_exec|mysql_query").argument.l',
             'sinks.reachableByFlows(sources).l'],
        ],
        "benign": [
            ['cpg.call.name("sqlite3_exec|mysql_query").where(_.argument(1).code(".*\\\\+.*|.*sprintf.*")).l'],
            ['val sources = cpg.call.name("fgets|argv|getenv").argument.l',
             'val sinks = cpg.call.name("sqlite3_exec|mysql_query").argument.l',
             'sinks.reachableByFlows(sources).l'],
        ]
    },
    "Path Traversal": {
        "vulnerable": [
            ['cpg.call.name("fopen|open").where(_.argument(0).reachableBy(cpg.parameter)).l'],
            ['cpg.call.name("fopen|open").whereNot(_.method.ast.isCall.name("realpath|basename")).l'],
        ],
        "benign": [
            ['cpg.call.name("fopen|open").where(_.argument(0).reachableBy(cpg.parameter)).l'],
            ['cpg.call.name("fopen|open").whereNot(_.method.ast.isCall.name("realpath|basename")).l'],
        ]
    },
    "Use-After-Free": {
        "vulnerable": [
            ['cpg.call.name("free").method.ast.isIdentifier.where(_.name == cpg.call.name("free").argument(1).code.head).l'],
            ['cpg.call.name("free").argument(1).reachableBy(cpg.call.name("malloc")).l'],
        ],
        "benign": [
            ['cpg.call.name("free").method.assignment.target.code(".*").where(_.source.code("NULL|nullptr")).l'],
        ]
    },
    "Integer Overflow": {
        "vulnerable": [
            ['cpg.call.name("malloc|calloc").where(_.argument(0).reachableBy(cpg.call.name("atoi"))).l'],
            ['cpg.call.name("malloc").where(_.argument(0).code(".*\\\\*.*\\\\+.*")).l'],
        ],
        "benign": [
            ['cpg.call.name("malloc|calloc").where(_.argument(0).reachableBy(cpg.call.name("atoi"))).l'],
            ['cpg.call.name("malloc").where(_.argument(0).code(".*\\\\*.*\\\\+.*")).l'],
        ]
    },
    "Double Free": {
        "vulnerable": [
            ['cpg.method.call.name("free").groupBy(_.argument.code).filter(_._2.size > 1).l'],
            ['cpg.call.name("free").postDominatedBy.isCall.name("free").l'],
        ],
        "benign": [
            ['cpg.call.name("free").postDominatedBy.isAssignment.where(_.source.code("NULL|nullptr")).l'],
        ]
    },
    "Null Pointer Dereference": {
        "vulnerable": [
            ['cpg.call.name("malloc").whereNot(_.method.ast.isControlStructure).l'],
            ['cpg.call.name("malloc").postDominatedBy.whereNot(_.isControlStructure).l'],
        ],
        "benign": [
            ['cpg.call.name("malloc").whereNot(_.method.ast.isControlStructure).l'],
            ['cpg.call.name("malloc").postDominatedBy.whereNot(_.isControlStructure).l'],
        ]
    },
    "Memory Leak": {
        "vulnerable": [
            ['cpg.call.name("malloc|calloc").whereNot(_.method.ast.isCall.name("free")).l'],
            ['cpg.call.name("new").method.whereNot(_.ast.isCall.name("delete")).l'],
        ],
        "benign": [
            ['cpg.call.name("malloc|calloc").whereNot(_.method.ast.isCall.name("free")).l'],
            ['cpg.call.name("new").method.whereNot(_.ast.isCall.name("delete")).l'],
        ]
    },
    "Format String Vulnerability": {
        "vulnerable": [
            ['cpg.call.name("printf|sprintf").where(_.argument(0).reachableBy(cpg.parameter)).l'],
            ['cpg.call.name("printf").whereNot(_.argument(0).isLiteral).l'],
        ],
        "benign": [
            ['cpg.call.name("printf|sprintf").where(_.argument(0).reachableBy(cpg.parameter)).l'],
            ['cpg.call.name("printf").whereNot(_.argument(0).isLiteral).l'],
        ]
    }
}


def analyze_code_patterns(code: str, vulnerability: str) -> dict:
    """Pre-analyze code to find actual dangerous patterns present."""
    patterns = CPP_VULNERABILITY_PATTERNS.get(vulnerability, {})
    
    found_sinks = []
    found_sources = []
    found_secure = []
    
    # Find actual sink calls in the code
    for sink in patterns.get("sinks", []):
        if re.search(rf'\b{re.escape(sink)}\s*[\(\[]', code):
            found_sinks.append(sink)
    
    # Find actual source calls in the code
    for source in patterns.get("sources", []):
        if re.search(rf'\b{re.escape(source)}\s*[\(\[]', code):
            found_sources.append(source)
    
    # Find secure patterns in the code
    for secure in patterns.get("secure_patterns", []):
        if re.search(rf'\b{re.escape(secure)}', code):
            found_secure.append(secure)
    
    # For C++, function parameters are often sources
    has_param_input = bool(re.search(r'const\s+char\s*\*|char\s*\*\s+\w+', code))
    if has_param_input and not found_sources:
        found_sources.append("parameter")
    
    return {
        "found_sinks": found_sinks,
        "found_sources": found_sources,
        "found_secure": found_secure,
        "has_param_input": has_param_input,
        "sink_pattern": "|".join(found_sinks) if found_sinks else "|".join(patterns.get("sinks", [])[:3]),
        "source_pattern": "|".join(found_sources) if found_sources else "parameter",
    }


# Worker state
_worker_model = None
_worker_max_tokens = None



def init_worker(model_name: str, max_tokens: int):
    """Initialize worker process state."""
    global _worker_model, _worker_max_tokens
    _worker_model = model_name
    _worker_max_tokens = max_tokens


def get_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Generate and validate C++ CPG queries")
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
    global _worker_model, _worker_max_tokens
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


def build_query_prompt(code: str, vulnerability: str, is_vulnerable: bool) -> str:
    """Build prompt for query generation with code analysis."""
    patterns = CPP_VULNERABILITY_PATTERNS.get(vulnerability, {})
    
    # Analyze actual code patterns
    analysis = analyze_code_patterns(code, vulnerability)
    
    sources = patterns.get("sources", ["argv", "fgets", "getenv"])
    sinks = patterns.get("sinks", ["system", "strcpy", "malloc"])
    secure = patterns.get("secure_patterns", [])
    
    # Get working template examples
    status_key = "vulnerable" if is_vulnerable else "benign"
    templates = WORKING_QUERY_TEMPLATES.get(vulnerability, {}).get(status_key, [])
    template_examples = []
    if templates:
        for t in templates[:2]:  # Show first 2 templates
            template_examples.append(" | ".join(t))
            
    # Prepare example block safely to avoid f-string backslash issues
    example_block = "\n".join([f"  {ex}" for ex in template_examples]) if template_examples else '  cpg.call.name("dangerous_function").l'
    
    status = "VULNERABLE" if is_vulnerable else "BENIGN/SECURE"
    
    # Customize goal based on vulnerability type
    if is_vulnerable:
        if analysis["found_sinks"]:
            goal = f"""The query MUST find results since this code contains {vulnerability}.
DETECTED DANGEROUS CALLS: {', '.join(analysis['found_sinks'])}
Simply finding these calls with cpg.call.name() can work!"""
        else:
            goal = "The query MUST find results (non-empty list) since this code contains a vulnerability."
    else:
        goal = "The query MUST return empty [] since this code is secure and properly sanitized."
    
    prompt = f"""Generate a Joern CPGQL query to detect {vulnerability} in C++ code.

CODE STATUS: {status}
{goal}

C++ CODE:
```cpp
{code}
```

DETECTED PATTERNS IN THIS CODE:
- Dangerous sinks found: {', '.join(analysis['found_sinks']) if analysis['found_sinks'] else 'None detected'}
- Input sources found: {', '.join(analysis['found_sources']) if analysis['found_sources'] else 'Function parameters'}
- Secure patterns found: {', '.join(analysis['found_secure']) if analysis['found_secure'] else 'None'}

PROVEN WORKING QUERIES for {vulnerability}:
{example_block}

CRITICAL RULES:
1. Output ONLY valid JSON with a "queries" array
2. Queries must be syntactically valid Scala
3. Do NOT use .p at the end (use .l instead)
4. Use cpg.call.name("function_name") for function calls
5. **JSON MUST USE DOUBLE QUOTES**: ["query"] NOT ['query']
6. **ROBUSTNESS**: Queries must check types/sizes/flows, not just function presence.
   - BAD: cpg.call.name("strcpy").l
   - GOOD: cpg.call.name("strcpy").where(_.argument(1).isIdentifier).l
7. If you need multiple statements, output them as SEPARATE strings in the "queries" array.
   The LAST string must be a traversal expression (no "val" assignments in it).

EXPECTED OUTPUT FORMAT:
```json
{{
  "queries": [
    "cpg.call.name(\\"{analysis['sink_pattern']}\\").where(_.argument(1).isIdentifier).l",
    "val sinks = cpg.call.name(\\"{analysis['sink_pattern']}\\").argument.l; sinks.reachableByFlows(sources).l"
  ]
}}
```
"""
    return prompt



def build_retry_prompt(previous_response: str, error_type: str, code: str, 
                       vulnerability: str, is_vulnerable: bool, attempt: int) -> str:
    """Build retry prompt based on error type with enhanced feedback."""
    status = "VULNERABLE" if is_vulnerable else "BENIGN"
    analysis = analyze_code_patterns(code, vulnerability)
    
    found_sinks = analysis.get("found_sinks", [])
    found_sources = analysis.get("found_sources", [])
    
    feedback = ""
    if error_type == "false_negative":
        feedback = f"""The query failed to find the vulnerability.
ANALYSIS:
- This code IS VULNERABLE to {vulnerability}.
- Actual sinks found in code: {', '.join(found_sinks) if found_sinks else 'None (check for indirect calls)'}
- Actual sources found in code: {', '.join(found_sources) if found_sources else 'None (likely Function Parameters)'}

SUGGESTION:
1. Ensure you are tracking flow from the correct source to the correct sink.
2. If sinks are present, try a simpler query first: cpg.call.name("{'|'.join(found_sinks)}")...
3. If source is a parameter, use reachableBy(cpg.parameter)."""
    
    elif error_type == "false_positive":
        feedback = f"""The query incorrectly flagged benign code.
ANALYSIS:
- This code is SECURE/BENIGN.
- You must make the query STRICTER to exclude this pattern.

SUGGESTION:
1. Use .whereNot(...) to exclude the detailed secure pattern.
2. Check for validation logic (e.g., checks on size, length, or specific values)."""
    
    elif error_type == "execution_failed":
        feedback = """The query failed to execute in Joern.
COMMON ISSUES:
1. Invalid syntax (e.g., missing parenthesis).
2. Using invalid steps (e.g., .p which is forbidden).
3. Incorrect property names.

SUGGESTION:
- Use standard steps: .call, .name, .argument, .reachableBy, .refsTo
- Verify all parentheses match."""
    
    else:
        feedback = "Please provide valid JSON with a 'queries' array."
    
    return f"""Your previous query attempt failed.

ERROR TYPE: {error_type}
CODE STATUS: {status}
ATTEMPT: {attempt}/{MAX_RETRIES}

{feedback}

C++ CODE:
```cpp
{code}
```

Generate a corrected query now. Output ONLY valid JSON.
"""


def get_fallback_query(vulnerability: str, is_vulnerable: bool, code: str = "") -> list:
    """Get fallback query based on actual code patterns."""
    import random
    templates = WORKING_QUERY_TEMPLATES.get(vulnerability, {}).get("vulnerable" if is_vulnerable else "benign", [])
    
    if not templates:
        return ['cpg.call.name("DATA_MISSING").l']

    # Smart selection based on code analysis
    if code and is_vulnerable:
        analysis = analyze_code_patterns(code, vulnerability)
        logger.info(f"FALLBACK DEBUG: sources={analysis.get('found_sources')}, pattern={analysis.get('source_pattern')}, brackets={'[' in code}")
        
        if vulnerability == "Buffer Overflow":
            # Priority 1: Security Grade (Combined Array Check + Parameter Taint)
            # Template 1: ['cpg.call("strcpy...").where(_.argument(1)...).where(_.argument(2)...).l']
            if ("parameter" in analysis.get("found_sources", []) or analysis.get("source_pattern") == "parameter") and \
               ("[" in code and "]" in code):
                if len(templates) > 0:
                     logger.info("FALLBACK: Selected Template 0 (Security Grade)")
                     return templates[0]

            # Priority 2: Source is a parameter (Template 4)
            if "parameter" in analysis.get("found_sources", []) or analysis.get("source_pattern") == "parameter":
                if len(templates) > 3:
                     return templates[3]
            
            # Priority 3: Dest is array (Template 3)
            if "[" in code and "]" in code and len(templates) > 2:
                 return templates[2]

    # Default to random selection for variety if no specific pattern matched
    logger.info("FALLBACK: Random selection")
    return random.choice(templates)



def validate_query_syntax(query: str) -> Tuple[bool, str]:
    """Validate query syntax before execution."""
    if query.count('(') != query.count(')'):
        return False, "Unbalanced parentheses"
    
    if query.count('"') % 2 != 0:
        return False, "Unbalanced quotes"
    
    if query.count('{') != query.count('}'):
        return False, "Unbalanced braces"
    
    forbidden = [".l.l", "toList.toList", "println"]
    for pattern in forbidden:
        if pattern in query:
            return False, f"Forbidden pattern: {pattern}"
    
    return True, ""


def parse_llm_response(response: str) -> list:
    """Parse LLM response to extract queries."""
    # Remove <think> blocks
    if "</think>" in response:
        response = response.split("</think>")[-1].strip()
    response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL)
    
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


def split_query_statements(query: str) -> List[str]:
    """Split a query string into statements, respecting quoted strings."""
    parts = []
    buf = []
    in_str = False
    escape = False
    for ch in query:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            buf.append(ch)
            continue
        if not in_str and (ch == ';' or ch == '\n'):
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def normalize_queries(queries: list) -> List[str]:
    """Flatten and normalize query statements."""
    flat: List[str] = []
    for q in queries:
        if not isinstance(q, str):
            continue
        if ";" in q or "\n" in q:
            flat.extend(split_query_statements(q))
        else:
            q = q.strip()
            if q:
                flat.append(q)
    return [q for q in flat if q]


def run_joern_script(code: str, queries: list, workspace: str) -> Optional[str]:
    """Execute queries in Joern and return result."""
    if os.path.exists(workspace):
        shutil.rmtree(workspace)
    os.makedirs(workspace)
    
    # Write C++ code
    code_file = os.path.join(workspace, "code.cpp")
    with open(code_file, 'w') as f:
        f.write(code)
    
    # Build Joern script
    queries = normalize_queries(queries)
    if not queries:
        return None

    # Find last traversal (non-val assignment) to execute
    last_idx = None
    for i in range(len(queries) - 1, -1, -1):
        if not re.match(r'^\s*val\s+\w+\s*=', queries[i]):
            last_idx = i
            break
    if last_idx is None:
        logger.warning("No traversal found in queries")
        return None

    queries_block = "\n    ".join([q for i, q in enumerate(queries) if i != last_idx])
    last_query = queries[last_idx]
    
    # Ensure we use .toJson on the traversal, so remove trailing .l if present
    # CRITICAL FIX: Only remove the LAST instance of .l, don't use replace() which does all
    last_query = re.sub(r'\.l\s*$', '', last_query.strip())
        
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
    
    script_path = os.path.join(workspace, "query.sc")
    with open(script_path, 'w') as f:
        f.write(script_content)
    


    # Run Joern
    try:
        cmd = ["joern", "--script", script_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=JOERN_TIMEOUT,
            cwd=workspace
        )
        
        output = result.stdout + result.stderr
        
        json_match = re.search(r"JOERN_JSON_START\s*(.*?)\s*JOERN_JSON_END", output, re.DOTALL)
        if json_match:
            return json_match.group(1).strip()
        
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
    """Format queries for output JSON with strict double quotes."""
    return json.dumps(queries)


def save_entry_immediately(entry: dict):
    """Save a single entry to output file immediately."""
    global OUTPUT_FILE
    
    lock_file = OUTPUT_FILE + ".lock"
    
    with open(lock_file, 'w') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            if os.path.exists(OUTPUT_FILE):
                with open(OUTPUT_FILE, 'r') as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = []
            else:
                data = []
            
            data.append(entry)
            
            with open(OUTPUT_FILE, 'w') as f:
                # Ensure double quotes by using default json dumper
                json.dump(data, f, indent=2, ensure_ascii=True)
                
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
    
    if limits.get("per_vuln", 0) > 0:
        current = counters[key].get(vulnerability, 0)
        if current >= limits["per_vuln"]:
            return True
    
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


# Global references for shared state
_shared_counters = None
_shared_limits = None


def worker_initializer(counters, limits, model_name: str, max_tokens: int):
    """Initialize worker with shared counters and model."""
    global _shared_counters, _shared_limits
    _shared_counters = counters
    _shared_limits = limits
    init_worker(model_name, max_tokens)


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
    
    workspace = f"/tmp/joern_worker_cpp_{os.getpid()}"
    
    logger.info(f"[{idx+1}/{total}] Processing: {vulnerability[:30]}... ({status_str})")
    
    result_queries = None
    
    try:
        prompt = build_query_prompt(code, vulnerability, is_vulnerable)
        current_response_text = call_model(prompt)
        
        for attempt in range(1, MAX_RETRIES + 1):
            queries = parse_llm_response(current_response_text)
            
            if not queries:
                logger.warning(f"[{idx+1}/{total}] Retry {attempt}/{MAX_RETRIES}: Could not parse queries")
                if attempt < MAX_RETRIES:
                    current_response_text = call_model(build_retry_prompt(
                        current_response_text, "invalid_format", code, vulnerability, is_vulnerable, attempt
                    ))
                    continue
                else:
                    continue
            
            all_valid = True
            for q in queries:
                is_valid, error_msg = validate_query_syntax(q)
                if not is_valid:
                    logger.warning(f"[{idx+1}/{total}] Validation failed: {error_msg}")
                    all_valid = False
                    break
            
            if not all_valid:
                if attempt < MAX_RETRIES:
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
            # SAFETY NET: Last resort fallback strategy
            logger.info(f"[{idx+1}/{total}] LLM failed. Attempting fallback strategy...")
            
            # Get smart fallback
            queries = get_fallback_query(vulnerability, is_vulnerable, code)
            
            # Execute fallback
            result = run_joern_script(code, queries, workspace)
            
            if result:
                try:
                    data = json.loads(result)
                    if not isinstance(data, list):
                        data = [data]
                    is_empty = len(data) == 0
                    
                    # Verify fallback validity
                    if is_vulnerable and not is_empty:
                        logger.info(f"[{idx+1}/{total}] Fallback strategy SUCCESS (True Positive)")
                        result_queries = queries
                    elif not is_vulnerable and is_empty:
                        logger.info(f"[{idx+1}/{total}] Fallback strategy SUCCESS (True Negative)")
                        result_queries = queries
                    else:
                        logger.warning(f"[{idx+1}/{total}] Fallback strategy failed verification (Vuln={is_vulnerable}, Empty={is_empty})")
                except json.JSONDecodeError:
                    logger.warning(f"[{idx+1}/{total}] Fallback result invalid JSON")
            else:
                 logger.warning(f"[{idx+1}/{total}] Fallback execution failed")

        if result_queries is None:
            logger.error(f"[{idx+1}/{total}] ✗ FAILED after {MAX_RETRIES} attempts + fallback")
        else:
            if _shared_counters is not None:
                increment_counter(vulnerability, is_vulnerable, _shared_counters)
            
            stats = format_balance_stats(_shared_counters) if _shared_counters else ""
            logger.info(f"[{idx+1}/{total}] ✓ SUCCESS | {stats}")
            
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


def main():
    global NUM_WORKERS, INPUT_FILE, OUTPUT_FILE
    
    args = get_args()
    
    NUM_WORKERS = args.workers
    INPUT_FILE = args.input
    OUTPUT_FILE = args.output
    
    # Select model
    model_name = select_lmstudio_model(args.model)
    
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
            
            for entry in existing_entries:
                instruction = entry.get("instruction", "")
                input_code = entry.get("input", "")
                
                match = re.search(r"detect (.+?)\.", instruction)
                vuln_type = match.group(1) if match else "Unknown"
                
                secure_patterns = ["strncpy", "snprintf", "realpath", "validate", 
                                  "sqlite3_prepare", "bounds", "nullptr", "NULL"]
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
    
    logger.info(f"Loaded {total} items. Using LM Studio with model: {model_name}")
    logger.info(f"Processing with {NUM_WORKERS} parallel workers...")
    
    # Prepare work items
    work_items = [(idx, item, total) for idx, item in enumerate(data)]
    
    # Process in parallel
    start_time = time.time()
    
    with Pool(
        processes=NUM_WORKERS,
        initializer=worker_initializer,
        initargs=(counters, limits, model_name, args.tokens)
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
