import re
import random
import string

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def obfuscate_strings(code):
    preserve_patterns = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE',
        'DROP', 'UNION', 'OR', 'AND', '--', ';',
        'http://', 'https://', 'file://',
        '/bin/', '/etc/', '/tmp/', '../',
        'ObjectInputStream', 'XMLDecoder', 'Runtime', 'ProcessBuilder',
        'password', 'secret', 'token', 'key', 'api',
        '.java', '.class', '.jar', '.xml', '.json', '.properties',
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
        'Content-Type', 'Authorization', 'application/json',
        'java.io', 'java.sql', 'java.net', 'javax.servlet',
        'executeQuery', 'executeUpdate', 'prepareStatement'
    ]
    
    def should_preserve(s):
        for pattern in preserve_patterns:
            if pattern.lower() in s.lower():
                return True
        return False
    
    def mutate_string(match):
        original = match.group(0)
        inner = original[1:-1]
        
        if should_preserve(inner):
            return original
        
        if len(inner) < 3:
            return original
        
        if random.random() < 0.4:
            suffix = random.choice(['_v2', '_new', '_temp', '_data', '_info'])
            new_inner = inner + suffix
            return f'"{new_inner}"'
        
        return original
    
    pattern = r'"[^"]*"'
    new_code = re.sub(pattern, mutate_string, code)
    
    return new_code
