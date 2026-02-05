import re
import random
import string

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def rename_vars(code):
    """
    Renames common Python variables using regex substitution.
    Prevents model from memorizing specific variable names.
    """
    
    targets = [
        "user", "password", "passwd", "query", "sql", "cmd", "command",
        "filename", "filepath", "file_path", "path", "url", "host",
        "conn", "cursor", "result", "response", "data", "payload",
        "input_data", "user_input", "request", "config", "secret",
        "token", "api_key", "username", "email", "name", "value",
        "content", "body", "headers", "params", "args", "kwargs"
    ]
    
    mapping = {}
    used_names = set(targets)
    
    for t in targets:
        pattern = r'\b' + re.escape(t) + r'\b'
        if re.search(pattern, code):
            new_name = random_string()
            while new_name in used_names:
                new_name = random_string()
            mapping[t] = new_name
            used_names.add(new_name)
    
    new_code = code
    for old, new in sorted(mapping.items(), key=lambda x: -len(x[0])):
        pattern = r'\b' + re.escape(old) + r'\b'
        new_code = re.sub(pattern, new, new_code)
    
    return new_code
