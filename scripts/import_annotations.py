import idc
import idaapi
import ida_kernwin
import os
import json
import git_sync

SCRIPT_DIR = os.path.dirname(__file__)
ANNOT_DIR = os.path.join(SCRIPT_DIR, 'annotations')


def choose_file():
    """
    Prompt the user to select one JSON file from the annotations folder.
    """
    files = [f for f in os.listdir(ANNOT_DIR)
             if f.startswith('annotation_') and f.endswith('.json')]
    if not files:
        print("[!] No annotation files found in 'annotations' folder.")
        return None
    files.sort()
    # Use ida_kernwin.ask_str instead of deprecated idc.AskStr
    prompt = "Select annotation file to import (use exact name):"
    choice = ida_kernwin.ask_str(files[-1], 0, prompt)
    if not choice or choice not in files:
        print(f"[!] Invalid selection: {choice}")
        return None
    return os.path.join(ANNOT_DIR, choice)


def apply_annotations(path):
    with open(path, 'r') as fp:
        items = json.load(fp)

    for it in items:
        ea = it['ea']
        val = it['value']
        if it['type'] == 'func_name':
            idc.set_name(ea, val, idc.SN_CHECK)
        elif it['type'] == 'comment':
            idc.set_cmt(ea, val, False)
        elif it['type'] == 'repeatable_comment':
            idc.set_cmt(ea, val, True)
    print(f"[+] Imported annotations from: {path}")


if __name__ == '__main__':
    f = choose_file()
    if f:
        apply_annotations(f)


git_sync.git_pull()

if __name__ == '__main__':
    f = choose_file()
    if f:
        apply_annotations(f)