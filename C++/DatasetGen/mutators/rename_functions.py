import re
import random
import string

def random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

# C++ built-in functions and keywords that should NOT be renamed
PRESERVED_NAMES = {
    # Standard library functions
    "main", "printf", "scanf", "sprintf", "snprintf", "fprintf", "sscanf",
    "malloc", "calloc", "realloc", "free", "new", "delete",
    "memcpy", "memset", "memmove", "memcmp", "strlen", "strcpy", "strncpy",
    "strcat", "strncat", "strcmp", "strncmp", "strstr", "strchr", "strrchr",
    "fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fseek", "ftell",
    "open", "close", "read", "write", "lseek", "ioctl",
    "socket", "bind", "listen", "accept", "connect", "send", "recv",
    "system", "popen", "pclose", "exec", "execl", "execv", "fork", "wait",
    "getenv", "setenv", "exit", "abort", "atexit",
    "atoi", "atol", "atof", "strtol", "strtod", "strtoul",
    "abs", "labs", "fabs", "sqrt", "pow", "log", "exp", "sin", "cos",
    "rand", "srand", "time", "clock", "sleep", "usleep",
    # C++ specific
    "cout", "cin", "cerr", "endl", "getline", "push_back", "pop_back",
    "begin", "end", "size", "empty", "clear", "insert", "erase", "find",
    "substr", "c_str", "data", "at", "front", "back", "reserve", "resize",
    # SQLite
    "sqlite3_open", "sqlite3_close", "sqlite3_exec", "sqlite3_prepare",
    "sqlite3_bind_text", "sqlite3_bind_int", "sqlite3_step", "sqlite3_finalize",
    # Keywords
    "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
    "return", "class", "struct", "public", "private", "protected", "virtual",
    "static", "const", "volatile", "inline", "extern", "typedef", "using",
    "namespace", "template", "typename", "try", "catch", "throw", "noexcept"
}

def rename_functions(code):
    """Rename user-defined C++ functions to random identifiers."""
    # Match function definitions: return_type function_name(params) { or ;
    # Patterns: void foo(), int bar(int x), std::string baz()
    func_pattern = re.compile(
        r'\b(?:void|int|char|bool|float|double|auto|size_t|ssize_t|'
        r'std::\w+|unsigned\s+\w+|long\s+\w+|short\s+\w+|'
        r'\w+\*|\w+&)\s+(\w+)\s*\([^)]*\)\s*(?:\{|;|const)',
        re.MULTILINE
    )
    
    # Find all function names
    matches = func_pattern.findall(code)
    
    # Filter out preserved names
    user_funcs = [m for m in set(matches) if m not in PRESERVED_NAMES and not m.startswith('_')]
    
    if not user_funcs:
        return code
    
    mapping = {}
    used_names = set(PRESERVED_NAMES)
    
    for func in user_funcs:
        new_name = random_string()
        while new_name in used_names:
            new_name = random_string()
        mapping[func] = new_name
        used_names.add(new_name)
    
    new_code = code
    # Replace function names (whole words only)
    for old, new in sorted(mapping.items(), key=lambda x: -len(x[0])):
        pattern = r'\b' + re.escape(old) + r'\b'
        new_code = re.sub(pattern, new, new_code)
    
    return new_code
