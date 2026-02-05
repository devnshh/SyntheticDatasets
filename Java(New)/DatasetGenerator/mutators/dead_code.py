import random
import string
import re

def random_var_name(length=6):
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

def add_dead_code(code):
    lines = code.split('\n')
    new_lines = []
    
    noise_statements = [
        "int {var} = {val};",
        "String {var} = \"{str}\".toUpperCase();",
        "double {var} = Math.random();",
        "boolean {var} = true;",
        "long {var} = System.currentTimeMillis();",
        "int {var} = {val} + {val2};",
    ]
    
    for line in lines:
        new_lines.append(line)
        stripped = line.strip()
        
        if stripped and not stripped.startswith('//') and not stripped.startswith('import'):
            method_pattern = r'(public|private|protected)?\s*(static)?\s*\w+\s+\w+\s*\([^)]*\)\s*(throws\s+\w+)?\s*\{'
            if re.search(method_pattern, stripped):
                leading_spaces = len(line) - len(line.lstrip())
                
                if random.random() < 0.2:
                    var = random_var_name()
                    val = random.randint(1, 100)
                    val2 = random.randint(1, 50)
                    rand_str = ''.join(random.choices(string.ascii_letters, k=5))
                    
                    template = random.choice(noise_statements)
                    noise = template.format(var=var, val=val, val2=val2, str=rand_str)
                    indent = ' ' * (leading_spaces + 4)
                    new_lines.append(f"{indent}{noise}")
    
    return '\n'.join(new_lines)
