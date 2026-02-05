import random
import re
import string

def random_var_name(length=6):
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

def add_dead_code(code):
    """Insert dead code (unused variables) after function definitions."""
    lines = code.split('\n')
    new_lines = []
    
    # C++ dead code patterns (unused variable assignments)
    dead_code_patterns = [
        lambda v: f"    int {v} = {random.randint(0, 1000)};",
        lambda v: f"    char {v}[] = \"{random_var_name(4)}\";",
        lambda v: f"    float {v} = {random.random():.4f}f;",
        lambda v: f"    double {v} = {random.random():.8f};",
        lambda v: f"    bool {v} = {'true' if random.random() > 0.5 else 'false'};",
        lambda v: f"    size_t {v} = sizeof(int);",
        lambda v: f"    void* {v} = nullptr;",
    ]
    
    # Detect function opening braces
    func_pattern = re.compile(
        r'^\s*((?:void|int|char|bool|float|double|auto|static|inline|unsigned|long|short|'
        r'std::\w+|\w+\*|\w+&)\s+)?\w+\s*\([^)]*\)\s*\{?\s*$'
    )
    
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        new_lines.append(line)
        
        # Check if this looks like a function definition
        if func_pattern.match(stripped):
            # If line ends with {, or next line is {, insert dead code after
            if stripped.endswith('{'):
                if random.random() < 0.20:  # 20% probability
                    var_name = random_var_name()
                    dead_code = random.choice(dead_code_patterns)(var_name)
                    new_lines.append(dead_code)
            elif i + 1 < len(lines) and lines[i + 1].strip() == '{':
                # Next line is the opening brace
                i += 1
                new_lines.append(lines[i])  # Add the {
                if random.random() < 0.20:  # 20% probability
                    var_name = random_var_name()
                    dead_code = random.choice(dead_code_patterns)(var_name)
                    new_lines.append(dead_code)
        
        i += 1
    
    return '\n'.join(new_lines)
