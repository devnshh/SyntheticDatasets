#!/usr/bin/env python3
"""
C++ Code Dataset Generator for CPG Analysis
Generates C++ code samples with security vulnerabilities for training.
Adapted from Java/Python dataset generators.
"""

import os
import random
import requests
import json
import time
import re
import argparse
import sys

# Import mutation engine
from mutators import apply_all_mutations

# Configuration
API_URL = "http://localhost:1234/v1/chat/completions"
MODEL_NAME = "deepseek/deepseek-r1-0528-qwen3-8b"
MAX_TOKENS = 8192

VULNERABILITIES_LIST = [
    "Buffer Overflow",
    "Command Injection",
    "Format String Vulnerability",
    "SQL Injection",
    "Path Traversal",
    "Use-After-Free",
    "Integer Overflow",
    "Double Free",
    "Null Pointer Dereference",
    "Memory Leak"
]

INDUSTRIES = [
    "Aerospace & Avionics", "High-Frequency Trading", "Genomics & BioTech",
    "Oil & Gas SCADA Systems", "Autonomous Vehicle Telemetry", "Satellite Communication",
    "Smart Grid Energy Management", "Blockchain & DeFi Bridges", "Hospital Triage & EHR",
    "Supply Chain Cold Storage", "Nuclear Power Plant Monitoring", "Telecommunications 5G Core",
    "Military Logistics & Inventory", "Cloud Infrastructure Orchestration", "IoT Home Automation",
    "Railway Signaling Systems", "Maritime Shipping & Port Control", "Pharmaceutical Drug Trials",
    "University Research Data Systems", "Legal Case Management", "Insurance Actuary Analysis",
    "Video Streaming Content Delivery", "Casino Gaming & Betting", "Weather Forecasting Stations",
    "Emergency Response (911/Dispatch)", "Waste Management Systems", "Water Treatment Facilities",
    "Semiconductor Manufacturing", "Airline Booking & Flight Ops", "Stock Exchange Clearing House"
]

# Load System Prompt from file
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SYSTEM_PROMPT_PATH = os.path.join(SCRIPT_DIR, "system_prompt.txt")

try:
    with open(SYSTEM_PROMPT_PATH, "r") as f:
        SYSTEM_PROMPT_BASE = f.read()
except FileNotFoundError:
    print("Warning: system_prompt.txt not found. Using fallback.")
    SYSTEM_PROMPT_BASE = """
    You are a Secure Code Generator. Objective: C++ code snippets with specific security properties.
    Output only the requested format.
    """

def get_args():
    parser = argparse.ArgumentParser(description="Generate C++ Security Dataset")
    parser.add_argument("--vuln_variants", type=int, default=2, help="Number of vulnerability types to select")
    parser.add_argument("--vuln_samples", type=int, default=1, help="Number of vulnerable samples per variant")
    parser.add_argument("--safe_samples", type=int, default=1, help="Number of benign samples per variant")
    parser.add_argument("--output", type=str, default="dataset.json", help="Output JSON filename")
    parser.add_argument("--tokens", type=int, default=8192, help="Max tokens for generation")
    return parser.parse_args()

def get_available_models():
    try:
        url = API_URL.replace("/chat/completions", "/models")
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return [m["id"] for m in data.get("data", [])]
    except Exception as e:
        print(f"Warning: Could not fetch models: {e}")
    return []

def select_model(default_model):
    print("\nFetching available models...")
    models = get_available_models()
    
    if not models:
        print(f"No models found via API. Using default: {default_model}")
        return default_model
        
    print(f"\nAvailable Models:")
    for idx, m in enumerate(models):
        print(f"{idx + 1}. {m}")
    
    print(f"{len(models) + 1}. Custom / Default ({default_model})")
    
    while True:
        try:
            choice = input(f"\nSelect model (1-{len(models) + 1}): ").strip()
            if not choice:
                return default_model
                
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                selected = models[idx]
                print(f"Selected: {selected}")
                return selected
            elif idx == len(models):
                return default_model
            else:
                print("Invalid selection.")
        except ValueError:
            print("Please enter a number.")

def clean_response(content, mutation_state=None):
    """
    Clean LLM response and optionally apply mutations.
    mutation_state: dict with 'total', 'mutated', 'max_ratio' keys
    Returns: (raw_content, cleaned_code, was_mutated)
    """
    # 1. Remove <think> blocks (for reasoning models)
    if "</think>" in content:
        content = content.split("</think>")[-1].strip()
    content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
    
    # 2. Try extracting from markdown first (cpp, c++, c)
    code_match = re.search(r'```(?:cpp|c\+\+|c)(.*?)```', content, re.DOTALL | re.IGNORECASE)
    if code_match:
        code = code_match.group(1).strip()
    else:
        # Try generic code block
        code_match = re.search(r'```(.*?)```', content, re.DOTALL)
        if code_match:
            code = code_match.group(1).strip()
        else:
            code = content
    
    # 3. Look for C++ class or function definition with brace balancing
    # Try to find a class definition first
    class_pattern = re.compile(r'(class\s+\w+)', re.MULTILINE)
    func_pattern = re.compile(r'((?:int|void|char|bool|float|double|auto|string|std::\w+)\s+\w+\s*\([^)]*\)\s*\{)', re.MULTILINE)
    
    class_match = class_pattern.search(code)
    func_match = func_pattern.search(code)
    
    if class_match:
        start_idx = class_match.start()
        # Find opening brace
        open_brace_idx = code.find('{', class_match.end())
        if open_brace_idx != -1:
            # Balance braces
            stack = 0
            end_idx = -1
            for i, char in enumerate(code[open_brace_idx:], start=open_brace_idx):
                if char == '{':
                    stack += 1
                elif char == '}':
                    stack -= 1
                    if stack == 0:
                        end_idx = i + 1
                        break
            if end_idx != -1:
                code = code[start_idx:end_idx]
    elif not func_match:
        # If no class or function found, try to extract any reasonable block
        if '{' in code and '}' in code:
            # Find first function-like pattern
            first_brace = code.find('{')
            if first_brace > 0:
                # Try to find function signature before brace
                line_start = code.rfind('\n', 0, first_brace)
                if line_start == -1:
                    line_start = 0
                # Balance from first brace
                stack = 0
                end_idx = -1
                for i, char in enumerate(code[first_brace:], start=first_brace):
                    if char == '{':
                        stack += 1
                    elif char == '}':
                        stack -= 1
                        if stack == 0:
                            end_idx = i + 1
                            break
                if end_idx != -1:
                    code = code[line_start:end_idx]
    
    # 4. Remove C++ comments
    code = re.sub(r'//.*', '', code)  # Line comments
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # Block comments
    
    # 5. Cleanup - remove empty lines
    lines = [line for line in code.splitlines() if line.strip()]
    code = "\n".join(lines)
    
    # 6. Apply mutations ONLY if under 10% threshold
    was_mutated = False
    if mutation_state is not None:
        total = mutation_state.get('total', 0)
        mutated = mutation_state.get('mutated', 0)
        max_ratio = mutation_state.get('max_ratio', 0.10)
        
        can_mutate = (total == 0) or (mutated / (total + 1) < max_ratio)
        
        if can_mutate:
            try:
                mutated_code = apply_all_mutations(code, mutation_probability=0.7)
                if mutated_code != code:
                    code = mutated_code
                    was_mutated = True
            except Exception:
                pass
    
    if len(code) < 50:
        return content, "", False
        
    return content, code, was_mutated

def extract_class_names(code):
    """Extract class names from C++ code."""
    pattern = re.compile(r'\bclass\s+(\w+)', re.MULTILINE)
    return pattern.findall(code)

def extract_function_names(code):
    """Extract function names from C++ code."""
    pattern = re.compile(r'(?:void|int|bool|char|float|double|auto|string|std::\w+)\s+(\w+)\s*\(', re.MULTILINE)
    return pattern.findall(code)

def compute_code_hash(code):
    """Compute a normalized hash for similarity detection."""
    import hashlib
    # Normalize: remove whitespace, lowercase
    normalized = re.sub(r'\s+', '', code.lower())
    # Remove variable names (simplified)
    normalized = re.sub(r'\b[a-z_][a-z0-9_]*\b', 'VAR', normalized)
    return hashlib.md5(normalized.encode()).hexdigest()[:16]

def is_too_similar(new_code, existing_dataset, threshold=0.7):
    """Check if new code is too similar to existing samples."""
    new_hash = compute_code_hash(new_code)
    new_normalized = re.sub(r'\s+', ' ', new_code.lower().strip())
    
    for entry in existing_dataset[-50:]:  # Check last 50 entries for performance
        existing_code = entry.get("code", "")
        existing_hash = compute_code_hash(existing_code)
        
        # Fast hash check
        if new_hash == existing_hash:
            return True
        
        # Check for same class name
        new_classes = set(extract_class_names(new_code))
        existing_classes = set(extract_class_names(existing_code))
        if new_classes and existing_classes and new_classes == existing_classes:
            return True
    
    return False

def generate_sample(sample_id, vulnerability, is_vulnerable, selected_model, max_tokens, used_names=None, attempt=1):
    status_str = "VULNERABLE" if is_vulnerable else "BENIGN"
    
    # Pick a random industry seed
    industry = random.choice(INDUSTRIES)
    
    # Build anti-repetition list
    avoid_names_str = ""
    if used_names and len(used_names) > 0:
        # Get last 20 names to avoid
        recent_names = list(used_names)[-20:]
        avoid_names_str = f"""
**CRITICAL - DO NOT USE THESE NAMES (already used):**
{', '.join(recent_names)}

You MUST invent a COMPLETELY DIFFERENT class/function name.
"""
    
    # Random creativity seeds
    creativity_seeds = [
        f"Use a {random.choice(['Manager', 'Handler', 'Controller', 'Service', 'Engine', 'Processor', 'Worker', 'Client', 'Server', 'Gateway', 'Bridge', 'Adapter', 'Factory', 'Builder', 'Monitor', 'Analyzer', 'Validator', 'Parser', 'Formatter'])} pattern.",
        f"The system handles {random.choice(['real-time', 'batch', 'streaming', 'event-driven', 'scheduled', 'on-demand', 'async', 'concurrent', 'distributed'])} operations.",
        f"Focus on {random.choice(['data ingestion', 'transformation', 'validation', 'storage', 'retrieval', 'analysis', 'reporting', 'alerting', 'logging', 'auditing', 'encryption', 'compression', 'serialization', 'caching'])}.",
    ]
    
    if is_vulnerable:
        instruction = f"""
Generate a C++ code snippet containing a **{vulnerability}** vulnerability.

**INDUSTRY CONTEXT:** {industry}

**MANDATORY UNIQUENESS RULES:**
1. Create a UNIQUE class name that I haven't seen before
2. DO NOT use generic names like DataProcessor, TelemetryProcessor, or Manager
3. {random.choice(creativity_seeds)}
4. Invent a specific subsystem name for this exact industry

{avoid_names_str}

**VULNERABILITY REQUIREMENTS:**
- The vulnerability MUST be exploitable and clear.
- Structure: Source -> Sink flow.
- NO COMMENTS in the code (no // or /* */ comments anywhere).
"""
    else:
        instruction = f"""
Generate a C++ code snippet that is **SECURE** against **{vulnerability}**.

**INDUSTRY CONTEXT:** {industry}

**MANDATORY UNIQUENESS RULES:**
1. Create a UNIQUE class name that I haven't seen before
2. DO NOT use generic names like DataProcessor, TelemetryProcessor, or Manager
3. {random.choice(creativity_seeds)}
4. Invent a specific subsystem name for this exact industry

{avoid_names_str}

**SECURITY REQUIREMENTS:**
- Implement proper validation, bounds checking, or secure APIs.
- NO COMMENTS in the code (no // or /* */ comments anywhere).
"""

    prompt = f"""
{instruction}

Sample ID: {sample_id}
Language: C++
Category: {vulnerability}
Status: {status_str}
Attempt: {attempt}

Requirements:
- Single self-contained C++ class (50-200 lines).
- UNIQUE class and method names - be creative!
- Include necessary #include directives.
- NO comments at all.

Output Format:
```cpp
<code here>
```
"""

    # Higher temperature for more diversity
    temp = 1.0 + (attempt * 0.1)  # Increase with retries
    if temp > 1.5:
        temp = 1.5
    
    payload = {
        "model": selected_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_BASE},
            {"role": "user", "content": prompt}
        ],
        "temperature": temp,
        "max_tokens": max_tokens
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers={"Content-Type": "application/json"}, timeout=300)
        if response.status_code != 200:
            print(f"Error {response.status_code}: {response.text}")
            return None
            
        data = response.json()
        if 'choices' in data and len(data['choices']) > 0:
            return data['choices'][0]['message']['content']
    except Exception as e:
        print(f"Exception: {e}")
        return None
    return None

def parse_metadata(content):
    meta = {}
    for line in content.splitlines():
        if line.startswith("### "):
            parts = line.replace("### ", "").split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                val = parts[1].strip()
                meta[key] = val
    return meta


def count_existing_samples(dataset):
    """Count existing samples per vulnerability type and status."""
    counts = {}
    for entry in dataset:
        vuln = entry.get("vulnerability", "Unknown")
        status = entry.get("status", "unknown")
        
        if vuln not in counts:
            counts[vuln] = {"vulnerable": 0, "benign": 0}
        
        if status == "vulnerable":
            counts[vuln]["vulnerable"] += 1
        elif status == "benign":
            counts[vuln]["benign"] += 1
    
    return counts

def main():
    args = get_args()
    
    # Select variants
    if args.vuln_variants > len(VULNERABILITIES_LIST):
        print(f"Requested {args.vuln_variants} variants but only {len(VULNERABILITIES_LIST)} available.")
        selected_vulns = VULNERABILITIES_LIST
    else:
        selected_vulns = random.sample(VULNERABILITIES_LIST, args.vuln_variants)
        
    print(f"\n{'='*60}")
    print(f"TARGET Configuration:")
    print(f"   Vulnerability types: {args.vuln_variants}")
    print(f"   Vulnerable samples per type: {args.vuln_samples}")
    print(f"   Benign samples per type: {args.safe_samples}")
    print(f"{'='*60}")
    print(f"\nSelected Variants: {selected_vulns}")
    
    # Interactive Model Selection
    global_model = select_model(MODEL_NAME)
    print(f"Using Model: {global_model}")
    
    # Load existing dataset if available
    output_path = os.path.join(SCRIPT_DIR, args.output)
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                dataset = json.load(f)
            existing_count = len(dataset)
            
            existing_counts = count_existing_samples(dataset)
            
            print(f"\n{'='*60}")
            print(f"EXISTING DATASET LOADED: {existing_count} total samples")
            print(f"{'='*60}")
            
            print(f"\nExisting samples per vulnerability:")
            for vuln in selected_vulns:
                vuln_counts = existing_counts.get(vuln, {"vulnerable": 0, "benign": 0})
                print(f"   {vuln}:")
                print(f"      Vulnerable: {vuln_counts['vulnerable']}/{args.vuln_samples} (need {max(0, args.vuln_samples - vuln_counts['vulnerable'])} more)")
                print(f"      Benign: {vuln_counts['benign']}/{args.safe_samples} (need {max(0, args.safe_samples - vuln_counts['benign'])} more)")
            
            global_counter = existing_count + 1
            print(f"\nStarting ID counter from: {global_counter}")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"Could not load existing dataset: {e}. Starting fresh.")
            dataset = []
            existing_counts = {}
            global_counter = 1
    else:
        print(f"\n{'='*60}")
        print(f"No existing dataset found. Starting fresh.")
        print(f"Starting ID counter from: 1")
        print(f"{'='*60}\n")
        dataset = []
        existing_counts = {}
        global_counter = 1
    
    # Track used class/function names for diversity
    used_names = set()
    
    # Extract names from existing dataset
    for entry in dataset:
        code = entry.get("code", "")
        used_names.update(extract_class_names(code))
        used_names.update(extract_function_names(code))
    
    print(f"Tracking {len(used_names)} existing class/function names to avoid duplicates")
    
    total_generated = 0
    total_skipped = 0
    total_rejected = 0  # Track rejected duplicates
    
    # Mutation tracking - limit to 10% of total samples
    mutation_state = {
        'total': len(dataset),
        'mutated': 0,
        'max_ratio': 0.10
    }
    
    print(f"Mutation limit: {mutation_state['max_ratio']*100:.0f}% of total samples")
    
    for vuln in selected_vulns:
        print(f"\n{'-'*40}")
        print(f"Processing Group: {vuln}")
        print(f"{'-'*40}")
        
        vuln_counts = existing_counts.get(vuln, {"vulnerable": 0, "benign": 0})
        existing_vulnerable = vuln_counts["vulnerable"]
        existing_benign = vuln_counts["benign"]
        
        vuln_needed = max(0, args.vuln_samples - existing_vulnerable)
        benign_needed = max(0, args.safe_samples - existing_benign)
        
        print(f"  Current: {existing_vulnerable} vulnerable, {existing_benign} benign")
        print(f"  Need to generate: {vuln_needed} vulnerable, {benign_needed} benign")
        
        total_skipped += (args.vuln_samples - vuln_needed) + (args.safe_samples - benign_needed)
        
        # Generate Vulnerable samples
        if vuln_needed == 0:
            print(f"  Vulnerable samples complete for {vuln}")
        else:
            generated_for_vuln = 0
            consecutive_failures = 0
            max_consecutive_failures = 10  # Give up after 10 consecutive failures
            
            while generated_for_vuln < vuln_needed and consecutive_failures < max_consecutive_failures:
                sample_id = f"CPP-{global_counter:04d}"
                current_count = existing_vulnerable + generated_for_vuln + 1
                print(f"  Generating {sample_id} [VULNERABLE] ({current_count}/{args.vuln_samples})...")
                
                # Retry loop for diversity
                max_attempts = 5
                success = False
                
                for attempt in range(1, max_attempts + 1):
                    raw_content = generate_sample(
                        sample_id, vuln, is_vulnerable=True, 
                        selected_model=global_model, max_tokens=args.tokens,
                        used_names=used_names, attempt=attempt
                    )
                    
                    if not raw_content:
                        print(f"    Attempt {attempt}: No API response")
                        continue
                    
                    cleaned_content, code_block, was_mutated = clean_response(raw_content, mutation_state)
                    
                    if not code_block:
                        print(f"    Attempt {attempt}: Empty code extracted")
                        continue
                    
                    # Check for duplicates
                    new_classes = extract_class_names(code_block)
                    if new_classes:
                        duplicate_names = set(new_classes) & used_names
                        if duplicate_names:
                            print(f"    Attempt {attempt}: REJECTED - duplicate class names: {duplicate_names}")
                            total_rejected += 1
                            continue
                    
                    # Check for similarity
                    if is_too_similar(code_block, dataset):
                        print(f"    Attempt {attempt}: REJECTED - too similar to existing code")
                        total_rejected += 1
                        continue
                    
                    # SUCCESS - add to dataset
                    entry = {
                        "language": "C++",
                        "vulnerability": vuln,
                        "status": "vulnerable",
                        "code": code_block
                    }
                    dataset.append(entry)
                    global_counter += 1
                    total_generated += 1
                    generated_for_vuln += 1
                    consecutive_failures = 0  # Reset on success
                    
                    # Update tracking
                    used_names.update(new_classes)
                    used_names.update(extract_function_names(code_block))
                    
                    mutation_state['total'] = len(dataset)
                    if was_mutated:
                        mutation_state['mutated'] += 1
                    
                    if vuln not in existing_counts:
                        existing_counts[vuln] = {"vulnerable": 0, "benign": 0}
                    existing_counts[vuln]["vulnerable"] += 1
                    
                    try:
                        with open(output_path, "w") as f:
                            json.dump(dataset, f, indent=2)
                        mutated_indicator = " [MUTATED]" if was_mutated else ""
                        print(f"    Saved (Total: {len(dataset)}){mutated_indicator}")
                    except Exception as e:
                        print(f"    Error saving dataset: {e}")
                    
                    success = True
                    break
                
                if not success:
                    consecutive_failures += 1
                    print(f"    [RETRY] Could not generate unique sample after {max_attempts} attempts (failures: {consecutive_failures}/{max_consecutive_failures})")
                
                time.sleep(1)
            
            if consecutive_failures >= max_consecutive_failures:
                print(f"  [WARNING] Gave up after {max_consecutive_failures} consecutive failures for {vuln}")


        # Generate Benign samples
        if benign_needed == 0:
            print(f"  Benign samples complete for {vuln}")
        else:
            generated_for_benign = 0
            consecutive_failures = 0
            max_consecutive_failures = 10  # Give up after 10 consecutive failures
            
            while generated_for_benign < benign_needed and consecutive_failures < max_consecutive_failures:
                sample_id = f"CPP-{global_counter:04d}"
                current_count = existing_benign + generated_for_benign + 1
                print(f"  Generating {sample_id} [BENIGN] ({current_count}/{args.safe_samples})...")
                
                # Retry loop for diversity
                max_attempts = 5
                success = False
                
                for attempt in range(1, max_attempts + 1):
                    raw_content = generate_sample(
                        sample_id, vuln, is_vulnerable=False, 
                        selected_model=global_model, max_tokens=args.tokens,
                        used_names=used_names, attempt=attempt
                    )
                    
                    if not raw_content:
                        print(f"    Attempt {attempt}: No API response")
                        continue
                    
                    cleaned_content, code_block, was_mutated = clean_response(raw_content, mutation_state)
                    
                    if not code_block:
                        print(f"    Attempt {attempt}: Empty code extracted")
                        continue
                    
                    # Check for duplicates
                    new_classes = extract_class_names(code_block)
                    if new_classes:
                        duplicate_names = set(new_classes) & used_names
                        if duplicate_names:
                            print(f"    Attempt {attempt}: REJECTED - duplicate class names: {duplicate_names}")
                            total_rejected += 1
                            continue
                    
                    # Check for similarity
                    if is_too_similar(code_block, dataset):
                        print(f"    Attempt {attempt}: REJECTED - too similar to existing code")
                        total_rejected += 1
                        continue
                    
                    # SUCCESS - add to dataset
                    entry = {
                        "language": "C++",
                        "vulnerability": vuln,
                        "status": "benign",
                        "code": code_block
                    }
                    dataset.append(entry)
                    global_counter += 1
                    total_generated += 1
                    generated_for_benign += 1
                    consecutive_failures = 0  # Reset on success
                    
                    # Update tracking
                    used_names.update(new_classes)
                    used_names.update(extract_function_names(code_block))
                    
                    mutation_state['total'] = len(dataset)
                    if was_mutated:
                        mutation_state['mutated'] += 1
                    
                    if vuln not in existing_counts:
                        existing_counts[vuln] = {"vulnerable": 0, "benign": 0}
                    existing_counts[vuln]["benign"] += 1
                    
                    try:
                        with open(output_path, "w") as f:
                            json.dump(dataset, f, indent=2)
                        mutated_indicator = " [MUTATED]" if was_mutated else ""
                        print(f"    Saved (Total: {len(dataset)}){mutated_indicator}")
                    except Exception as e:
                        print(f"    Error saving dataset: {e}")
                    
                    success = True
                    break
                
                if not success:
                    consecutive_failures += 1
                    print(f"    [RETRY] Could not generate unique sample after {max_attempts} attempts (failures: {consecutive_failures}/{max_consecutive_failures})")
                
                time.sleep(1)
            
            if consecutive_failures >= max_consecutive_failures:
                print(f"  [WARNING] Gave up after {max_consecutive_failures} consecutive failures for {vuln}")


    # Final statistics
    mutation_ratio = (mutation_state['mutated'] / mutation_state['total'] * 100) if mutation_state['total'] > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"   Total samples in dataset: {len(dataset)}")
    print(f"   Samples generated this run: {total_generated}")
    print(f"   Samples skipped (already existed): {total_skipped}")
    print(f"   Samples rejected (duplicates): {total_rejected}")
    print(f"   Mutated samples: {mutation_state['mutated']}/{mutation_state['total']} ({mutation_ratio:.1f}%)")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
