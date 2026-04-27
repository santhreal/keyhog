import os
import re

def process_file(path, rel_path, is_mod):
    with open(path, 'r') as f:
        text = f.read()

    # Find ::inventory::submit! or inventory::submit!
    # Simple regex replacing
    regex = re.compile(r'(?ms)^\s*(?:::)?inventory::submit!\s*\{\s*(.*?)\s*\}')
    matches = regex.findall(text)
    if not matches:
        return False, []

    new_text = regex.sub('', text)
    
    # Generate the register function
    fn_name = "register_self" if is_mod else "register"
    fn_code = f"\n\npub(crate) fn {fn_name}(registry: &mut crate::dialect::registry::RegistryBuilder) {{\n"
    for content in matches:
        fn_code += f"    registry.add({content.strip()});\n"
    fn_code += "}\n"

    with open(path, 'w') as f:
        f.write(new_text + fn_code)

    return True, matches

def build_tree(root_dir='vyre-core/src/dialect'):
    # Walk the directory tree bottom-up
    # At each directory, collect all its .rs files and subdirectories
    # If they contain a register function (either directly or via children),
    # create/update mod.rs to call them.
    pass

build_tree()
