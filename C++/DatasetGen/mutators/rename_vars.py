import re
import random
import string

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def rename_vars(code):
    """Rename common C++ variable names to random identifiers."""
    targets = [
        # Buffer/memory related
        "buffer", "buf", "ptr", "data", "temp", "tmp", "result",
        # Security sensitive
        "password", "passwd", "secret", "token", "apiKey", "credential",
        "user", "username", "input", "output", "payload",
        # Networking
        "socket", "sock", "fd", "conn", "connection", "host", "port",
        "addr", "address", "server", "client",
        # File operations
        "filename", "filepath", "file", "path", "stream", "fstream",
        # Database
        "query", "sql", "stmt", "statement", "cursor", "db", "database",
        # General
        "config", "settings", "options", "params", "args", "argv",
        "request", "response", "content", "body", "headers", "value",
        "reader", "writer", "handler", "manager", "controller",
        "str", "msg", "message", "text", "line", "cmd", "command"
    ]
    
    mapping = {}
    used_names = set(targets)
    
    for t in targets:
        # Only match whole words (not part of longer identifiers)
        pattern = r'\b' + re.escape(t) + r'\b'
        if re.search(pattern, code, re.IGNORECASE):
            new_name = random_string()
            while new_name in used_names:
                new_name = random_string()
            mapping[t] = new_name
            used_names.add(new_name)
    
    new_code = code
    # Sort by length descending to replace longer matches first
    for old, new in sorted(mapping.items(), key=lambda x: -len(x[0])):
        pattern = r'\b' + re.escape(old) + r'\b'
        new_code = re.sub(pattern, new, new_code, flags=re.IGNORECASE)
    
    return new_code
