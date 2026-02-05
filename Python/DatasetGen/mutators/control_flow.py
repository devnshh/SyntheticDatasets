import random
import re

def add_benign_control_flow(code):
    """
    Wraps statements in benign control flow structures.
    Teaches model to focus on vulnerability patterns, not exact syntax.
    """
    lines = code.split('\n')
    new_lines = []
    
    inside_function = False
    current_indent = 0
    
    benign_conditions = [
        "if True:",
        "if 1:",
        "if not False:",
        "if len([1]) > 0:",
    ]
    
    for line in lines:
        stripped = line.strip()
        
        if stripped.startswith('def '):
            inside_function = True
            new_lines.append(line)
            continue
        
        if inside_function and stripped and not stripped.startswith('#'):
            leading_spaces = len(line) - len(line.lstrip())
            
            skip_patterns = [
                'return', 'import', 'from', 'class', 'def', 
                'if ', 'elif ', 'else:', 'try:', 'except', 'finally:',
                'for ', 'while ', 'with ', '@', 'pass', 'break', 'continue'
            ]
            
            should_skip = any(stripped.startswith(p) for p in skip_patterns)
            
            if not should_skip and random.random() < 0.15:
                condition = random.choice(benign_conditions)
                indent = ' ' * leading_spaces
                new_lines.append(f"{indent}{condition}")
                new_lines.append(' ' * 4 + line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    
    return '\n'.join(new_lines)
