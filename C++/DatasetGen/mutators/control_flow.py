import random
import re

def add_benign_control_flow(code):
    """Insert benign always-true conditionals around some statements."""
    lines = code.split('\n')
    new_lines = []
    
    inside_function = False
    brace_depth = 0
    
    # C++ benign conditions that are always true
    benign_conditions = [
        "if (true) {",
        "if (1) {",
        "if (1 == 1) {",
        "if (!0) {",
        "if (sizeof(int) > 0) {",
    ]
    
    for line in lines:
        stripped = line.strip()
        
        # Track brace depth
        brace_depth += stripped.count('{') - stripped.count('}')
        
        # Detect function definitions
        func_pattern = r'^\s*((?:void|int|char|bool|float|double|auto|static|inline)\s+)?\w+\s*\([^)]*\)\s*\{'
        if re.search(func_pattern, stripped):
            inside_function = True
            new_lines.append(line)
            continue
        
        # Only modify lines inside functions
        if inside_function and stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
            leading_spaces = len(line) - len(line.lstrip())
            
            # Skip patterns that shouldn't be wrapped
            skip_patterns = [
                'return', '#include', '#define', '#pragma', '#ifdef', '#endif', '#ifndef',
                'if ', 'if(', 'else', 'try', 'catch', 'finally', 'throw',
                'for ', 'for(', 'while', 'switch', 'case', 'default:',
                'class', 'struct', 'enum', 'namespace', 'template',
                'public:', 'private:', 'protected:',
                '@', 'break', 'continue', 'goto',
                '{', '}', 'using', 'typedef'
            ]
            
            should_skip = any(stripped.startswith(p) for p in skip_patterns) or stripped in ['{', '}']
            
            # 15% chance to wrap non-skipped lines
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
