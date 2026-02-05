import re
import random
import string

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def obfuscate_strings(code):
    """
    Modifies string literals to prevent memorization of specific strings.
    Preserves SQL keywords and vulnerability-critical patterns.
    """
    
    preserve_patterns = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE',
        'DROP', 'UNION', 'OR', 'AND', '--', ';',
        'http://', 'https://', 'file://',
        '/bin/', '/etc/', '/tmp/', '../',
        'pickle', 'yaml', 'marshal', 'eval', 'exec',
        'password', 'secret', 'token', 'key', 'api',
        '.py', '.txt', '.json', '.yaml', '.xml',
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
        'Content-Type', 'Authorization', 'application/json'
    ]
    
    def should_preserve(s):
        for pattern in preserve_patterns:
            if pattern.lower() in s.lower():
                return True
        return False
    
    def mutate_string(match):
        original = match.group(0)
        inner = original[1:-1]
        quote = original[0]
        
        if should_preserve(inner):
            return original
        
        if len(inner) < 3:
            return original
        
        if random.random() < 0.4:
            suffix = random.choice(['_v2', '_new', '_temp', '_data', '_info'])
            new_inner = inner + suffix
            return f"{quote}{new_inner}{quote}"
        
        return original
    
    pattern = r'"[^"]*"|\'[^\']*\''
    new_code = re.sub(pattern, mutate_string, code)
    
    return new_code
