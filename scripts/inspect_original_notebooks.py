import json
import sys

def inspect_notebook(path):
    print(f"\n=======================================================")
    print(f"FILE: {path}")
    print(f"=======================================================")
    with open(path, 'r', encoding='utf-8') as f:
        nb = json.load(f)
    cells = nb.get('cells', [])
    print(f"Total cells: {len(cells)}")
    for idx, cell in enumerate(cells):
        ctype = cell.get('cell_type')
        source = "".join(cell.get('source', [])).strip()
        lines = [l for l in source.splitlines() if l.strip()]
        first_line = lines[0] if lines else "<empty>"
        outputs = cell.get('outputs', [])
        errs = [o for o in outputs if o.get('output_type') == 'error']
        texts = []
        for o in outputs:
            if 'text' in o:
                t = "".join(o['text']).strip()
                if t:
                    texts.append(t)
        
        status = "OK"
        if errs:
            status = f"ERROR: {errs[0].get('ename')}: {errs[0].get('evalue', '')[:60]}"
        print(f"Cell {idx:02d} [{ctype}] (exec_count: {cell.get('execution_count')}) [{status}]: {first_line[:80]}")
        for t in texts:
            for l in t.splitlines()[:5]:
                print(f"     | {l[:100]}")
            if len(t.splitlines()) > 5:
                print(f"     | ... ({len(t.splitlines()) - 5} more lines)")

if __name__ == '__main__':
    inspect_notebook('Random_Forest.ipynb')
    inspect_notebook('XG_Boost.ipynb')

