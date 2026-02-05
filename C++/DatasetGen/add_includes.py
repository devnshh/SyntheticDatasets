#!/usr/bin/env python3
"""
Post-processing script to add #include statements to C++ code samples.
Analyzes each code sample and adds appropriate includes based on usage.
"""

import json
import re
import os
import argparse

# Mapping of C++ features/types to their required includes
INCLUDE_MAPPINGS = {
    # I/O streams
    r'\bstd::cout\b': '<iostream>',
    r'\bstd::cin\b': '<iostream>',
    r'\bstd::cerr\b': '<iostream>',
    r'\bstd::endl\b': '<iostream>',
    r'\bcout\b': '<iostream>',
    r'\bcin\b': '<iostream>',
    r'\bcerr\b': '<iostream>',
    
    # String
    r'\bstd::string\b': '<string>',
    r'\bstring\b(?!\s*\*)': '<string>',
    
    # File streams
    r'\bstd::ifstream\b': '<fstream>',
    r'\bstd::ofstream\b': '<fstream>',
    r'\bstd::fstream\b': '<fstream>',
    r'\bifstream\b': '<fstream>',
    r'\bofstream\b': '<fstream>',
    
    # C-style file I/O
    r'\bFILE\s*\*': '<cstdio>',
    r'\bfopen\b': '<cstdio>',
    r'\bfclose\b': '<cstdio>',
    r'\bfread\b': '<cstdio>',
    r'\bfwrite\b': '<cstdio>',
    r'\bfprintf\b': '<cstdio>',
    r'\bfscanf\b': '<cstdio>',
    r'\bfseek\b': '<cstdio>',
    r'\bftell\b': '<cstdio>',
    r'\bsprintf\b': '<cstdio>',
    r'\bsnprintf\b': '<cstdio>',
    r'\bprintf\b': '<cstdio>',
    
    # String manipulation (C-style)
    r'\bstrcpy\b': '<cstring>',
    r'\bstrncpy\b': '<cstring>',
    r'\bstrcat\b': '<cstring>',
    r'\bstrncat\b': '<cstring>',
    r'\bstrlen\b': '<cstring>',
    r'\bstrcmp\b': '<cstring>',
    r'\bstrncmp\b': '<cstring>',
    r'\bmemcpy\b': '<cstring>',
    r'\bmemset\b': '<cstring>',
    r'\bmemmove\b': '<cstring>',
    r'\bstd::strcpy\b': '<cstring>',
    r'\bstd::strncpy\b': '<cstring>',
    r'\bstd::strlen\b': '<cstring>',
    r'\bstd::memcpy\b': '<cstring>',
    r'\bstd::memset\b': '<cstring>',
    
    # Containers
    r'\bstd::vector\b': '<vector>',
    r'\bstd::map\b': '<map>',
    r'\bstd::unordered_map\b': '<unordered_map>',
    r'\bstd::set\b': '<set>',
    r'\bstd::unordered_set\b': '<unordered_set>',
    r'\bstd::list\b': '<list>',
    r'\bstd::deque\b': '<deque>',
    r'\bstd::queue\b': '<queue>',
    r'\bstd::stack\b': '<stack>',
    r'\bstd::array\b': '<array>',
    r'\bstd::pair\b': '<utility>',
    r'\bstd::tuple\b': '<tuple>',
    
    # Algorithms
    r'\bstd::sort\b': '<algorithm>',
    r'\bstd::find\b': '<algorithm>',
    r'\bstd::copy\b': '<algorithm>',
    r'\bstd::transform\b': '<algorithm>',
    r'\bstd::for_each\b': '<algorithm>',
    r'\bstd::min\b': '<algorithm>',
    r'\bstd::max\b': '<algorithm>',
    
    # Memory
    r'\bstd::unique_ptr\b': '<memory>',
    r'\bstd::shared_ptr\b': '<memory>',
    r'\bstd::weak_ptr\b': '<memory>',
    r'\bstd::make_unique\b': '<memory>',
    r'\bstd::make_shared\b': '<memory>',
    r'\bmalloc\b': '<cstdlib>',
    r'\bfree\b': '<cstdlib>',
    r'\brealloc\b': '<cstdlib>',
    r'\bcalloc\b': '<cstdlib>',
    
    # Threading
    r'\bstd::thread\b': '<thread>',
    r'\bstd::mutex\b': '<mutex>',
    r'\bstd::lock_guard\b': '<mutex>',
    r'\bstd::unique_lock\b': '<mutex>',
    r'\bstd::condition_variable\b': '<condition_variable>',
    r'\bstd::async\b': '<future>',
    r'\bstd::future\b': '<future>',
    
    # Numeric types
    r'\bsize_t\b': '<cstddef>',
    r'\bint8_t\b': '<cstdint>',
    r'\bint16_t\b': '<cstdint>',
    r'\bint32_t\b': '<cstdint>',
    r'\bint64_t\b': '<cstdint>',
    r'\buint8_t\b': '<cstdint>',
    r'\buint16_t\b': '<cstdint>',
    r'\buint32_t\b': '<cstdint>',
    r'\buint64_t\b': '<cstdint>',
    
    # Other utilities
    r'\bstd::exception\b': '<exception>',
    r'\bstd::runtime_error\b': '<stdexcept>',
    r'\bstd::invalid_argument\b': '<stdexcept>',
    r'\bstd::out_of_range\b': '<stdexcept>',
    r'\bstd::chrono\b': '<chrono>',
    r'\bstd::regex\b': '<regex>',
    r'\bstd::function\b': '<functional>',
    r'\bstd::bind\b': '<functional>',
    r'\bstd::optional\b': '<optional>',
    r'\bstd::variant\b': '<variant>',
    r'\bstd::any\b': '<any>',
    r'\bstd::filesystem\b': '<filesystem>',
    r'\bstd::stringstream\b': '<sstream>',
    r'\bstd::istringstream\b': '<sstream>',
    r'\bstd::ostringstream\b': '<sstream>',
    
    # C standard library
    r'\batoi\b': '<cstdlib>',
    r'\batol\b': '<cstdlib>',
    r'\batof\b': '<cstdlib>',
    r'\bstrtol\b': '<cstdlib>',
    r'\bstrtod\b': '<cstdlib>',
    r'\bexit\b': '<cstdlib>',
    r'\babs\b': '<cstdlib>',
    r'\brand\b': '<cstdlib>',
    r'\bsrand\b': '<cstdlib>',
    r'\bsystem\b': '<cstdlib>',
    r'\bgetenv\b': '<cstdlib>',
    
    # Math
    r'\bsqrt\b': '<cmath>',
    r'\bpow\b': '<cmath>',
    r'\bsin\b': '<cmath>',
    r'\bcos\b': '<cmath>',
    r'\btan\b': '<cmath>',
    r'\blog\b': '<cmath>',
    r'\bexp\b': '<cmath>',
    r'\bfloor\b': '<cmath>',
    r'\bceil\b': '<cmath>',
    r'\bfabs\b': '<cmath>',
    
    # Assertions
    r'\bassert\b': '<cassert>',
    
    # Limits
    r'\bINT_MAX\b': '<climits>',
    r'\bINT_MIN\b': '<climits>',
    r'\bUINT_MAX\b': '<climits>',
    r'\bLONG_MAX\b': '<climits>',
    r'\bstd::numeric_limits\b': '<limits>',
    
    # Database libraries
    r'\bsqlite3\b': '<sqlite3.h>',
    r'\bsqlite3_': '<sqlite3.h>',
    r'\bSQLITE_': '<sqlite3.h>',
    r'\bmysql_': '<mysql/mysql.h>',
    r'\bMYSQL\b': '<mysql/mysql.h>',
    r'\bpqxx::': '<pqxx/pqxx>',
    r'\bpqxx\b': '<pqxx/pqxx>',
    
    # Random
    r'\bstd::random_device\b': '<random>',
    r'\bstd::mt19937\b': '<random>',
    r'\bstd::uniform_': '<random>',
    r'\bstd::normal_distribution\b': '<random>',
    
    # Bitset
    r'\bstd::bitset\b': '<bitset>',
    
    # Complex
    r'\bstd::complex\b': '<complex>',
    
    # Initializer list
    r'\bstd::initializer_list\b': '<initializer_list>',
    
    # Type traits
    r'\bstd::is_same\b': '<type_traits>',
    r'\bstd::enable_if\b': '<type_traits>',
    r'\bstd::decay\b': '<type_traits>',
    
    # Atomic
    r'\bstd::atomic\b': '<atomic>',
}


def detect_needed_includes(code):
    """Analyze code and return set of needed includes."""
    needed = set()
    
    for pattern, include in INCLUDE_MAPPINGS.items():
        if re.search(pattern, code):
            needed.add(include)
    
    return sorted(needed)

def already_has_includes(code):
    """Check if code already has #include statements."""
    return bool(re.search(r'^\s*#include\s*[<"]', code, re.MULTILINE))

def add_includes_to_code(code):
    """Add necessary #include statements to code if not present."""
    # Skip if already has includes
    if already_has_includes(code):
        return code, False
    
    # Detect needed includes
    includes = detect_needed_includes(code)
    
    if not includes:
        # Add at least iostream as a default for cout/cerr usage
        includes = ['<iostream>']
    
    # Build include block
    include_lines = [f"#include {inc}" for inc in includes]
    include_block = "\n".join(include_lines) + "\n\n"
    
    # Prepend to code
    updated_code = include_block + code
    
    return updated_code, True

def process_dataset(input_path, output_path=None, dry_run=False):
    """Process the dataset and add includes to all code samples."""
    
    if output_path is None:
        output_path = input_path
    
    print(f"Loading dataset from: {input_path}")
    
    with open(input_path, 'r') as f:
        dataset = json.load(f)
    
    total = len(dataset)
    modified = 0
    already_had = 0
    
    print(f"Processing {total} samples...")
    
    for i, entry in enumerate(dataset):
        code = entry.get("code", "")
        
        if already_has_includes(code):
            already_had += 1
            continue
        
        updated_code, was_modified = add_includes_to_code(code)
        
        if was_modified:
            if not dry_run:
                entry["code"] = updated_code
            modified += 1
            
            if modified <= 5:  # Show first 5 examples
                includes = detect_needed_includes(code)
                print(f"\n  Sample {i+1}: Added {len(includes)} includes: {', '.join(includes)}")
    
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Total samples: {total}")
    print(f"  Already had includes: {already_had}")
    print(f"  Modified: {modified}")
    print(f"  Unchanged: {total - modified - already_had}")
    print(f"{'='*60}")
    
    if dry_run:
        print("\n[DRY RUN] No changes written to disk.")
    else:
        print(f"\nSaving to: {output_path}")
        with open(output_path, 'w') as f:
            json.dump(dataset, f, indent=2)
        print("Done!")

def main():
    parser = argparse.ArgumentParser(description="Add #include statements to C++ dataset")
    parser.add_argument("--input", "-i", default="dataset.json", help="Input dataset file")
    parser.add_argument("--output", "-o", default=None, help="Output file (default: overwrite input)")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Show what would be done without making changes")
    
    args = parser.parse_args()
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(script_dir, args.input)
    output_path = os.path.join(script_dir, args.output) if args.output else input_path
    
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        return
    
    process_dataset(input_path, output_path, args.dry_run)

if __name__ == "__main__":
    main()
