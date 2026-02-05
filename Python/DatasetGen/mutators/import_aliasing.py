import re
import random
import string

def random_alias(length=4):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def alias_imports(code):
    """
    Adds random aliases to import statements.
    Prevents model from memorizing exact import names.
    """
    
    import_patterns = [
        (r'^import\s+(os)\s*$', 'os'),
        (r'^import\s+(sys)\s*$', 'sys'),
        (r'^import\s+(json)\s*$', 'json'),
        (r'^import\s+(pickle)\s*$', 'pickle'),
        (r'^import\s+(yaml)\s*$', 'yaml'),
        (r'^import\s+(subprocess)\s*$', 'subprocess'),
        (r'^import\s+(sqlite3)\s*$', 'sqlite3'),
        (r'^import\s+(requests)\s*$', 'requests'),
        (r'^import\s+(logging)\s*$', 'logging'),
    ]
    
    lines = code.split('\n')
    new_lines = []
    alias_mapping = {}
    
    for line in lines:
        stripped = line.strip()
        modified = False
        
        for pattern, module in import_patterns:
            if re.match(pattern, stripped) and random.random() < 0.3:
                alias = random_alias()
                new_line = f"import {module} as {alias}"
                new_lines.append(new_line)
                alias_mapping[module] = alias
                modified = True
                break
        
        if not modified:
            new_lines.append(line)
    
    result = '\n'.join(new_lines)
    
    for module, alias in alias_mapping.items():
        pattern = r'\b' + re.escape(module) + r'\.'
        result = re.sub(pattern, f"{alias}.", result)
    
    return result
