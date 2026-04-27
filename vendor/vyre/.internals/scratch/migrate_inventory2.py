import os
import re

def main():
    root_dir = 'vyre-core/src'
    
    # regex to match top-level inventory::submit!
    # It assumes the closing brace is at the start of a line to avoid nested brace issues.
    regex = re.compile(r'(?ms)^(\s*)::?inventory::submit!\s*\{\s*(.*?)\s*^\1\}')
    
    for root, dirs, files in os.walk(root_dir):
        for f in files:
            if not f.endswith('.rs'): continue
            path = os.path.join(root, f)
            with open(path, 'r') as file:
                text = file.read()
                
            matches = regex.findall(text)
            if not matches:
                continue
                
            # Erase all inventory::submit! blocks
            new_text = regex.sub('', text)
            
            # Generate the register function at the end
            fn_code = f"\n\npub fn explicit_register(registry: &mut crate::dialect::registry::DialectRegistryBuilder) {{\n"
            for indent, inner in matches:
                fn_code += f"    registry.add({inner.strip()});\n"
            fn_code += "}\n"
            
            with open(path, 'w') as file:
                file.write(new_text + fn_code)
                
    print("Done generating explicit_register")

if __name__ == '__main__':
    main()
