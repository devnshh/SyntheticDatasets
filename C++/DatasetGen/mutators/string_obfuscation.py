import random
import re

# Strings that should NOT be modified (security-critical patterns)
PRESERVED_STRINGS = [
    # SQL keywords
    "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR",
    "CREATE", "DROP", "TABLE", "VALUES", "INTO", "SET",
    # Shell/command patterns
    "/bin/", "/usr/", "/etc/", "/tmp/", "bash", "sh", "cmd",
    # Network protocols
    "http://", "https://", "ftp://", "tcp://", "udp://",
    # Format specifiers
    "%s", "%d", "%f", "%x", "%p", "%n", "%c", "%i", "%u", "%ld", "%lu",
    # File paths
    ".txt", ".log", ".conf", ".cfg", ".db", ".sqlite",
    # SQLite
    "sqlite3", "SQLITE",
    # C++ standard
    "std::", "nullptr", "NULL",
]

def should_preserve(s):
    """Check if a string should not be modified."""
    s_lower = s.lower()
    for preserved in PRESERVED_STRINGS:
        if preserved.lower() in s_lower:
            return True
    # Preserve very short strings
    if len(s) < 3:
        return True
    return False

def obfuscate_strings(code):
    """Slightly modify non-critical string literals by adding suffixes."""
    suffixes = ["_v2", "_new", "_tmp", "_mod", "_alt", "_rev"]
    
    def replace_string(match):
        content = match.group(1)
        
        # Don't modify preserved strings
        if should_preserve(content):
            return match.group(0)
        
        # 40% chance to modify
        if random.random() < 0.40:
            suffix = random.choice(suffixes)
            return f'"{content}{suffix}"'
        
        return match.group(0)
    
    # Match double-quoted strings (simple pattern, doesn't handle escaped quotes perfectly)
    # Pattern: "content" but not things like \"
    string_pattern = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
    
    new_code = string_pattern.sub(replace_string, code)
    
    return new_code
