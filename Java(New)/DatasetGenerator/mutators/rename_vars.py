import re
import random
import string

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def rename_vars(code):
    targets = [
        "user", "password", "passwd", "query", "sql", "cmd", "command",
        "filename", "filePath", "file", "path", "url", "host", "port",
        "connection", "conn", "statement", "stmt", "resultSet", "rs",
        "result", "response", "data", "payload", "input", "output",
        "inputStream", "outputStream", "reader", "writer", "buffer",
        "request", "config", "secret", "token", "apiKey", "username",
        "email", "name", "value", "content", "body", "headers", "params",
        "stream", "socket", "channel", "session", "context", "entity"
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
