import random
import string

def random_var_name(length=6):
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

def add_dead_code(code):
    """
    Inserts dead code/noise into functions.
    Prevents model from learning based on code length or density.
    """
    lines = code.split('\n')
    new_lines = []
    
    noise_statements = [
        "_{var} = {val}",
        "_{var} = len('{str}')",
        "_{var} = {val} + {val2}",
        "_{var} = '{str}'.upper()",
        "_{var} = list(range({val}))",
    ]
    
    for line in lines:
        new_lines.append(line)
        stripped = line.strip()
        
        if stripped and not stripped.startswith('#') and not stripped.startswith('import'):
            if ':' in stripped and not stripped.startswith('if') and not stripped.startswith('for'):
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
