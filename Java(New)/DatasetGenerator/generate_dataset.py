import os
import random
import requests
import json
import time
import re
import argparse
import sys
from mutators import apply_all_mutations

# Configuration
API_URL = "http://localhost:1234/v1/chat/completions"
# Assume running from within the directory or passed explicitly
MODEL_NAME = "deepseek/deepseek-r1-0528-qwen3-8b"
MAX_TOKENS = 8192  # Increased to prevent truncation of thinking + code

VULNERABILITIES_LIST = [
    "SQL Injection",
    "Command Injection",
    "Insecure Deserialization",
    "Path Traversal",
    "Broken Access Control",
    "Log Injection",
    "Open Redirect",
    "XXE (XML External Entity)",
    "TOCTOU (Time-of-check to Time-of-use)"
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
try:
    with open("system_prompt.txt", "r") as f:
        SYSTEM_PROMPT_BASE = f.read()
except FileNotFoundError:
    print("Warning: system_prompt.txt not found. Using fallback.")
    SYSTEM_PROMPT_BASE = """
    You are a Secure Code Generator. Objective: Java code snippets with specific security properties.
    Output only the requested format.
    """

def get_args():
    parser = argparse.ArgumentParser(description="Generate Java Security Dataset")
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
    # 1. Remove <think> blocks
    if "</think>" in content:
        content = content.split("</think>")[-1].strip()
    content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
    
    # 2. Try extracting from markdown first
    code_match = re.search(r'```java(.*?)```', content, re.DOTALL)
    if code_match:
        content = code_match.group(1).strip()
    
    # 3. Strict Parsing for Java Class
    # We look for: class ClassName [extends X] [implements Y] {
    # We will iterate through all "class X" matches to find one that looks valid.
    
    class_pattern = re.compile(r'(public\s+|final\s+|abstract\s+)*class\s+(\w+)', re.MULTILINE)
    
    potential_matches = list(class_pattern.finditer(content))
    
    valid_code = ""
    
    for match in potential_matches:
        start_idx = match.start()
        # Look for the opening brace '{'
        open_brace_idx = content.find('{', match.end())
        
        if open_brace_idx == -1:
            continue # No opening brace, not a valid class
            
        # Check text between class name and '{'
        # It should only contain whitespace, 'extends', 'implements', and type names.
        intermediate = content[match.end():open_brace_idx].strip()
        
        # Simple heuristic: if intermediate text has words that are not keywords or types, it's likely chat.
        # Valid: "extends Base", "implements A, B", ""
        # Invalid: "without relying on", "which is vulnerable"
        
        is_valid_syntax = True
        if intermediate:
            # We allow broad matching for strictness: just ensure likely keywords are present if words exist
            # But simpler: if it contains many words that aren't extends/implements, fail.
            # actually better: allow it if it matches a java signature regex
            sig_check = re.match(r'^((extends\s+[\w<>,\s]+)|(implements\s+[\w<>,\s]+))+$', intermediate)
            # This is hard to get perfect. 
            # Alternative: simpler check. The "class without..." has "without".
            # Let's check for specific bad words or just length? 
            # Let's assume if it's more than 100 chars between class and {, it's suspicious?
            if len(intermediate) > 200: 
                is_valid_syntax = False
            
            # Check for common chat words that wouldn't likely be in a class signature
            bad_words = ["without", "using", "relying", "example", "is", "can", "note"]
            for w in bad_words:
                if w in intermediate.split():
                    is_valid_syntax = False
                    break
        
        if not is_valid_syntax:
            continue

        # Found a likely valid class start. Now balance braces.
        stack = 0
        end_idx = -1
        
        # We start parsing from the open_brace_idx
        for i, char in enumerate(content[open_brace_idx:], start=open_brace_idx):
            if char == '{':
                stack += 1
            elif char == '}':
                stack -= 1
                if stack == 0:
                    end_idx = i + 1
                    break
        
        if end_idx != -1:
            # We found a balanced block!
            # Extract from the start of the class keyword (match.start()) to end_idx
            valid_code = content[match.start():end_idx]
            break # Stop at first valid class
    
    if not valid_code:
        # If we didn't find a valid class via regex, try one last desperation check on the whole content
        # ONLY if the content is small and looks like code (has imports, has class)
        if "public class" in content and "{" in content and "}" in content:
             # Just try to balance from the first {
             # But this caused the issue before.
             return content, "", False 
        return content, "", False


    # 4. Remove Comments
    valid_code = re.sub(r'//.*', '', valid_code)
    valid_code = re.sub(r'/\*.*?\*/', '', valid_code, flags=re.DOTALL)
    
    # 5. Cleanup
    lines = [line for line in valid_code.splitlines() if line.strip()]
    valid_code = "\n".join(lines)
    
    # 6. Apply mutations ONLY if under 10% threshold
    was_mutated = False
    if mutation_state is not None:
        total = mutation_state.get('total', 0)
        mutated = mutation_state.get('mutated', 0)
        max_ratio = mutation_state.get('max_ratio', 0.10)
        
        can_mutate = (total == 0) or (mutated / (total + 1) < max_ratio)
        
        if can_mutate:
            try:
                mutated_code = apply_all_mutations(valid_code, mutation_probability=0.7)
                if mutated_code != valid_code:
                    valid_code = mutated_code
                    was_mutated = True
            except Exception:
                pass
    
    if len(valid_code) < 50:
        return content, "", False
        
    return content, valid_code, was_mutated

def generate_sample(sample_id, vulnerability, is_vulnerable, selected_model, max_tokens):
    status_str = "VULNERABLE" if is_vulnerable else "BENIGN"
    
    # Pick a random industry seed to urge the model toward diversity
    industry = random.choice(INDUSTRIES)
    
    # We ask the model to invent the specific scenario
    if is_vulnerable:
        instruction = f"""
        Generate a Java code snippet containing a **{vulnerability}** vulnerability.
        
        **CONTEXT DIRECTIVE:**
        - Industry: **{industry}**
        - **CREATIVE TASK:** Invent a specific, realistic subsystem or module name relevant to this industry (e.g., if Aerospace, use 'OrbitTrajectoryCalculator'; if Finance, use 'HighFreqOrderMatcher').
        - **Avoid generic** names like 'UserManager' or 'ProductSearch' unless absolutely specific to the industry.
        
        **VULNERABILITY REQUIREMENTS:**
        - The vulnerability MUST be exploitable and clear.
        - Structure: Source -> Sink flow.
        """
    else:
        instruction = f"""
        Generate a Java code snippet that is **SECURE** against **{vulnerability}**.
        
        **CONTEXT DIRECTIVE:**
        - Industry: **{industry}**
        - **CREATIVE TASK:** Invent a specific, realistic subsystem or module name relevant to this industry. 
        - **Avoid generic** names like 'UserManager'.
        
        **SECURITY REQUIREMENTS:**
        - Implement proper validation, sanitization, or secure APIs to prevent the vulnerability.
        - The code should functionally resemble a realistic scenario where this vulnerability might usually appear, but fixed.
        """

    prompt = f"""
    {instruction}
    
    Sample ID: {sample_id}
    Language: Java
    Category: {vulnerability}
    Status: {status_str}
    
    Requirements:
    - Single self-contained Java class.
    - 50-200 lines.
    - Realistic enterprise scenario.
    - NO boilerplate.
    
    Output Format:
    ```java
    <code here>
    ```
    """

    
    payload = {
        "model": selected_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_BASE},
            {"role": "user", "content": prompt}
        ],
        "temperature": 1.0,
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
    print(f"🎯 TARGET Configuration:")
    print(f"   Vulnerability types: {args.vuln_variants}")
    print(f"   Vulnerable samples per type: {args.vuln_samples}")
    print(f"   Benign samples per type: {args.safe_samples}")
    print(f"{'='*60}")
    print(f"\nSelected Variants: {selected_vulns}")
    
    # Interactive Model Selection - Default Behavior
    global_model = select_model(MODEL_NAME)
    print(f"Using Model: {global_model}")
    
    # Load existing dataset if available
    if os.path.exists(args.output):
        try:
            with open(args.output, "r") as f:
                dataset = json.load(f)
            existing_count = len(dataset)
            
            # Count existing samples per vulnerability and status
            existing_counts = count_existing_samples(dataset)
            
            print(f"\n{'='*60}")
            print(f"📦 EXISTING DATASET LOADED: {existing_count} total samples")
            print(f"{'='*60}")
            
            # Display existing counts for selected vulnerabilities
            print(f"\n📊 Existing samples per vulnerability:")
            for vuln in selected_vulns:
                vuln_counts = existing_counts.get(vuln, {"vulnerable": 0, "benign": 0})
                print(f"   {vuln}:")
                print(f"      Vulnerable: {vuln_counts['vulnerable']}/{args.vuln_samples} (need {max(0, args.vuln_samples - vuln_counts['vulnerable'])} more)")
                print(f"      Benign: {vuln_counts['benign']}/{args.safe_samples} (need {max(0, args.safe_samples - vuln_counts['benign'])} more)")
            
            # Start counter from existing count + 1
            global_counter = existing_count + 1
            print(f"\n🔢 Starting ID counter from: {global_counter}")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"Could not load existing dataset: {e}. Starting fresh.")
            dataset = []
            existing_counts = {}
            global_counter = 1
    else:
        print(f"\n{'='*60}")
        print(f"📄 No existing dataset found. Starting fresh.")
        print(f"🔢 Starting ID counter from: 1")
        print(f"{'='*60}\n")
        dataset = []
        existing_counts = {}
        global_counter = 1
    
    total_generated = 0
    total_skipped = 0
    
    # Mutation tracking - limit to 10% of total samples
    mutation_state = {
        'total': len(dataset),
        'mutated': 0,
        'max_ratio': 0.10
    }
    
    print(f"Mutation limit: {mutation_state['max_ratio']*100:.0f}% of total samples")
    
    for vuln in selected_vulns:
        print(f"\n{'─'*40}")
        print(f"Processing Group: {vuln}")
        print(f"{'─'*40}")
        
        # Get existing counts for this vulnerability
        vuln_counts = existing_counts.get(vuln, {"vulnerable": 0, "benign": 0})
        existing_vulnerable = vuln_counts["vulnerable"]
        existing_benign = vuln_counts["benign"]
        
        # Calculate how many more we need to generate
        vuln_needed = max(0, args.vuln_samples - existing_vulnerable)
        benign_needed = max(0, args.safe_samples - existing_benign)
        
        print(f"  📈 Current: {existing_vulnerable} vulnerable, {existing_benign} benign")
        print(f"  📝 Need to generate: {vuln_needed} vulnerable, {benign_needed} benign")
        
        # Track skipped
        total_skipped += (args.vuln_samples - vuln_needed) + (args.safe_samples - benign_needed)
        
        # Generator for Vulnerable (only generate what's needed)
        if vuln_needed == 0:
            print(f"  ✅ Vulnerable samples complete for {vuln}")
        else:
            for i in range(vuln_needed):
                sample_id = f"JAVA-{global_counter:04d}"
                current_count = existing_vulnerable + i + 1
                print(f"  Generating {sample_id} [VULNERABLE] ({current_count}/{args.vuln_samples})...")
                
                raw_content = generate_sample(sample_id, vuln, is_vulnerable=True, selected_model=global_model, max_tokens=args.tokens)
                if raw_content:
                    cleaned_content, code_block, was_mutated = clean_response(raw_content, mutation_state)
                    metadata = parse_metadata(cleaned_content)
                    
                    if code_block:
                        entry = {
                            "language": "Java",
                            "vulnerability": vuln,
                            "status": "vulnerable",
                            "code": code_block
                        }
                        dataset.append(entry)
                        global_counter += 1
                        total_generated += 1
                        
                        # Update mutation tracking
                        mutation_state['total'] = len(dataset)
                        if was_mutated:
                            mutation_state['mutated'] += 1
                        
                        # Update counts
                        if vuln not in existing_counts:
                            existing_counts[vuln] = {"vulnerable": 0, "benign": 0}
                        existing_counts[vuln]["vulnerable"] += 1
                        
                        # Incremental Save
                        try:
                            with open(args.output, "w") as f:
                                json.dump(dataset, f, indent=2)
                            mutated_indicator = " [MUTATED]" if was_mutated else ""
                            print(f"    Saved (Total: {len(dataset)}){mutated_indicator}")
                        except Exception as e:
                            print(f"    Error saving dataset: {e}")
                    else:
                        print(f"    [WARNING] Empty Code extracted! Raw length: {len(raw_content)}.")
                else:
                    print("    Failed (No response from API).")
                time.sleep(1)

        # Generator for Benign (only generate what's needed)
        if benign_needed == 0:
            print(f"  ✅ Benign samples complete for {vuln}")
        else:
            for i in range(benign_needed):
                sample_id = f"JAVA-{global_counter:04d}"
                current_count = existing_benign + i + 1
                print(f"  Generating {sample_id} [BENIGN] ({current_count}/{args.safe_samples})...")
                
                raw_content = generate_sample(sample_id, vuln, is_vulnerable=False, selected_model=global_model, max_tokens=args.tokens)
                if raw_content:
                    cleaned_content, code_block, was_mutated = clean_response(raw_content, mutation_state)
                    metadata = parse_metadata(cleaned_content)
                    
                    if code_block:
                        entry = {
                            "language": "Java",
                            "vulnerability": vuln,
                            "status": "benign",
                            "code": code_block
                        }
                        dataset.append(entry)
                        global_counter += 1
                        total_generated += 1
                        
                        # Update mutation tracking
                        mutation_state['total'] = len(dataset)
                        if was_mutated:
                            mutation_state['mutated'] += 1
                        
                        # Update counts
                        if vuln not in existing_counts:
                            existing_counts[vuln] = {"vulnerable": 0, "benign": 0}
                        existing_counts[vuln]["benign"] += 1
                        
                        # Incremental Save
                        try:
                            with open(args.output, "w") as f:
                                json.dump(dataset, f, indent=2)
                            mutated_indicator = " [MUTATED]" if was_mutated else ""
                            print(f"    Saved (Total: {len(dataset)}){mutated_indicator}")
                        except Exception as e:
                            print(f"    Error saving dataset: {e}")
                    else:
                        print(f"    [WARNING] Empty Code extracted! Raw length: {len(raw_content)}.")
                else:
                    print("    Failed (No response from API).")
                time.sleep(1)

    # Calculate mutation statistics
    mutation_ratio = (mutation_state['mutated'] / mutation_state['total'] * 100) if mutation_state['total'] > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"   Total samples in dataset: {len(dataset)}")
    print(f"   Samples generated this run: {total_generated}")
    print(f"   Samples skipped (already existed): {total_skipped}")
    print(f"   Mutated samples: {mutation_state['mutated']}/{mutation_state['total']} ({mutation_ratio:.1f}%)")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
