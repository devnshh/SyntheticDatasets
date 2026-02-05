from .rename_vars import rename_vars
from .rename_functions import rename_functions
from .control_flow import add_benign_control_flow
from .dead_code import add_dead_code
from .string_obfuscation import obfuscate_strings
from .import_aliasing import alias_imports

def apply_all_mutations(code, mutation_probability=0.7):
    """Apply all mutations to the code with given probability."""
    import random
    
    mutations = [
        rename_vars,
        rename_functions,
        add_benign_control_flow,
        add_dead_code,
        obfuscate_strings,
        alias_imports
    ]
    
    for mutation in mutations:
        if random.random() < mutation_probability:
            try:
                code = mutation(code)
            except Exception:
                pass
    
    return code
