import os
import re

def main():
    root_dir = 'vyre-core/src'
    
    entries = []
    
    def process_file(path):
        with open(path, 'r') as f:
            text = f.read()
            
        out_text = text
        start_idx = 0
        
        while True:
            # Find both ::inventory::submit! and inventory::submit!
            idx1 = out_text.find("::inventory::submit!", start_idx)
            idx2 = out_text.find("inventory::submit!", start_idx)
            
            if idx1 == -1 and idx2 == -1:
                break
                
            if idx1 != -1 and idx2 != -1:
                idx = min(idx1, idx2)
            else:
                idx = max(idx1, idx2)
                
            brace_idx = out_text.find("{", idx)
            if brace_idx == -1:
                start_idx = idx + 1
                continue
                
            brace_count = 1
            close_idx = brace_idx + 1
            while close_idx < len(out_text) and brace_count > 0:
                if out_text[close_idx] == '{':
                    brace_count += 1
                elif out_text[close_idx] == '}':
                    brace_count -= 1
                close_idx += 1
                
            if brace_count == 0:
                content = out_text[brace_idx+1:close_idx-1].strip()
                out_text = out_text[:idx] + out_text[close_idx:]
                entries.append((path, content))
            else:
                start_idx = idx + 1
                
        with open(path, 'w') as f:
            f.write(out_text)

    for root, dirs, files in os.walk(root_dir):
        for f in files:
            if not f.endswith('.rs'): continue
            process_file(os.path.join(root, f))
            
    # Remove inventory::collect!
    for root, dirs, files in os.walk(root_dir):
        for f in files:
            if not f.endswith('.rs'): continue
            path = os.path.join(root, f)
            with open(path, 'r') as file:
                t = file.read()
            # simple regex replace
            if "inventory::" in t:
                t = re.sub(r'inventory::collect!\(.*?\);', '', t)
                with open(path, 'w') as file:
                    file.write(t)

    # We cannot compile the entries directly into a single init because they reference local private variables/functions.
    # To fix this without breaking scope: we must APPEND an explicit register function to EACH file, and then call them.
    print(f"Removed {len(entries)} inventory usages. Since they reference private symbols, we need scope resolution.")
    
if __name__ == '__main__':
    main()
