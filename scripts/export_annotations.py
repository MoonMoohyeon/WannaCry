import idc
import idautils
import idaapi
import os
import json
from datetime import datetime
import git_sync

# Directories
SCRIPT_DIR = os.path.dirname(__file__)
ANNOT_DIR = os.path.join(SCRIPT_DIR, 'annotations')
CHANGE_DIR = os.path.join(SCRIPT_DIR, 'changes')

# Ensure directories exist
for d in (ANNOT_DIR, CHANGE_DIR):
    if not os.path.exists(d):
        os.makedirs(d)


def gather_annotations():
    """
    Collect all current function names and comments in the database.
    Returns a list of dicts: {type, ea, value}.
    """
    items = []
    # Function names
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea)
        items.append({
            'type': 'func_name',
            'ea': func_ea,
            'value': name
        })
    # Comments (regular and repeatable)
    for ea in idautils.Heads():
        c = idc.get_cmt(ea, False)
        rc = idc.get_cmt(ea, True)
        if c:
            items.append({ 'type': 'comment', 'ea': ea, 'value': c })
        if rc:
            items.append({ 'type': 'repeatable_comment', 'ea': ea, 'value': rc })
    return items


def load_previous():
    """
    Load the most recent annotation JSON (if any).
    """
    files = sorted([f for f in os.listdir(ANNOT_DIR)
                    if f.startswith('annotation_') and f.endswith('.json')])
    if not files:
        return []
    latest = files[-1]
    with open(os.path.join(ANNOT_DIR, latest), 'r') as fp:
        return json.load(fp)


def diff_items(old, new):
    """
    Return entries in new that are not identical in old.
    Comparison by matching type, ea, and value.
    """
    old_set = {(it['type'], it['ea'], it['value']) for it in old}
    diffs = [it for it in new if (it['type'], it['ea'], it['value']) not in old_set]
    return diffs


def save_annotations():
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    all_items = gather_annotations()
    # Write full JSON
    json_path = os.path.join(ANNOT_DIR, f'annotation_{ts}.json')
    with open(json_path, 'w') as jf:
        json.dump(all_items, jf, indent=2)
    print(f"[+] Full annotations saved to: {json_path}")

    # Compute diffs vs previous
    prev = load_previous()
    changes = diff_items(prev, all_items)
    if changes:
        txt_path = os.path.join(CHANGE_DIR, f'changes_{ts}.txt')
        with open(txt_path, 'w') as tf:
            for it in changes:
                ea_str = hex(it['ea'])
                tf.write(f"{it['type']} @ {ea_str}: {it['value']}\n")
        print(f"[+] Changes saved to: {txt_path}")
    else:
        print("[-] No changes since last run.")


if __name__ == '__main__':
    save_annotations()

# Git Pull -> Commit -> Push
git_sync.git_pull()
git_sync.git_push()