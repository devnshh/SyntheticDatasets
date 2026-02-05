import re
import random
import string

def random_func_name(length=10):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def rename_functions(code):
    builtin_methods = {
        'main', 'toString', 'equals', 'hashCode', 'getClass', 'notify', 'notifyAll', 'wait',
        'clone', 'finalize', 'compareTo', 'compare', 'run', 'call', 'get', 'set', 'add',
        'remove', 'put', 'contains', 'size', 'isEmpty', 'clear', 'iterator', 'next', 'hasNext',
        'execute', 'executeQuery', 'executeUpdate', 'prepareStatement', 'createStatement',
        'getConnection', 'close', 'read', 'write', 'flush', 'print', 'println', 'format',
        'getParameter', 'getAttribute', 'setAttribute', 'getSession', 'getInputStream',
        'getOutputStream', 'getWriter', 'sendRedirect', 'forward', 'dispatch',
        'parse', 'valueOf', 'parseInt', 'parseDouble', 'substring', 'split', 'trim',
        'toLowerCase', 'toUpperCase', 'replace', 'matches', 'startsWith', 'endsWith',
        'getBytes', 'toCharArray', 'length', 'charAt', 'append', 'insert', 'delete',
        'readObject', 'writeObject', 'readLine', 'newInstance', 'forName', 'getMethod',
        'invoke', 'setAccessible', 'getDeclaredField', 'getField'
    }
    
    func_pattern = r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+([a-zA-Z_]\w*)\s*\('
    matches = re.findall(func_pattern, code)
    
    mapping = {}
    used_names = set(builtin_methods)
    
    for func_name in matches:
        if func_name not in builtin_methods and func_name not in mapping:
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
