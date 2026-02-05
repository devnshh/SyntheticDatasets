import re
import random
import string

def random_func_name(length=10):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def rename_functions(code):
    """
    Renames user-defined function names to random strings.
    Preserves built-in and library function names.
    """
    
    builtin_funcs = {
        'print', 'len', 'range', 'str', 'int', 'float', 'list', 'dict',
        'open', 'read', 'write', 'close', 'join', 'split', 'strip',
        'get', 'post', 'put', 'delete', 'execute', 'commit', 'rollback',
        'load', 'loads', 'dump', 'dumps', 'render', 'render_template',
        'send_file', 'abort', 'redirect', 'url_for', 'request', 'jsonify',
        'run', 'call', 'Popen', 'system', 'popen', 'eval', 'exec',
        'format', 'encode', 'decode', 'replace', 'append', 'extend',
        '__init__', '__main__', '__name__', 'main', 'app'
    }
    
    func_pattern = r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
    matches = re.findall(func_pattern, code)
    
    mapping = {}
    used_names = set(builtin_funcs)
    
    for func_name in matches:
        if func_name not in builtin_funcs and func_name not in mapping:
            new_name = random_func_name()
            while new_name in used_names:
                new_name = random_func_name()
            mapping[func_name] = new_name
            used_names.add(new_name)
    
    new_code = code
    for old, new in sorted(mapping.items(), key=lambda x: -len(x[0])):
        pattern = r'\b' + re.escape(old) + r'\b'
        new_code = re.sub(pattern, new, new_code)
    
    return new_code
