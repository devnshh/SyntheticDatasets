import random
import re

def add_benign_control_flow(code):
    lines = code.split('\n')
    new_lines = []
    
    inside_method = False
    brace_depth = 0
    
    benign_conditions = [
        "if (true) {",
        "if (1 == 1) {",
        "if (!false) {",
        "if (Math.abs(1) > 0) {",
    ]
    
    for line in lines:
        stripped = line.strip()
        
        brace_depth += stripped.count('{') - stripped.count('}')
        
        method_pattern = r'(public|private|protected)?\s*(static)?\s*\w+\s+\w+\s*\([^)]*\)\s*(throws\s+\w+)?\s*\{'
        if re.search(method_pattern, stripped):
            inside_method = True
            new_lines.append(line)
            continue
        
        if inside_method and stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
            leading_spaces = len(line) - len(line.lstrip())
            
            skip_patterns = [
                'return', 'import', 'package', 'class', 'interface', 'enum',
                'if ', 'if(', 'else', 'try', 'catch', 'finally', 'throw',
                'for ', 'for(', 'while', 'switch', 'case', 'default:',
                '@', 'break', 'continue', 'public', 'private', 'protected',
                '{', '}', 'new ', 'super', 'this'
            ]
            
            should_skip = any(stripped.startswith(p) for p in skip_patterns) or stripped in ['{', '}']
            
            if not should_skip and random.random() < 0.15:
                condition = random.choice(benign_conditions)
                indent = ' ' * leading_spaces
                new_lines.append(f"{indent}{condition}")
                new_lines.append(' ' * 4 + line)
                new_lines.append(f"{indent}}}")
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    
    return '\n'.join(new_lines)
