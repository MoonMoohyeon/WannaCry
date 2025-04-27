# resolve_conflicts.py
import os
import re
import ida_kernwin
import idc

CONFLICT_LOG_PATH = os.path.join("annotations", "conflict_log.txt")

def parse_conflict_log(path):
    conflicts = []
    if not os.path.exists(path):
        print(f"[-] Conflict log not found at {path}")
        return conflicts

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Parse line
            match = re.match(r"(Function|Code) Comment Conflict at 0x([0-9A-Fa-f]+): existing='(.*?)' new='(.*?)'", line)
            if match:
                ctype, addr_hex, existing, new = match.groups()
                ea = int(addr_hex, 16)
                conflicts.append({
                    "type": ctype,
                    "ea": ea,
                    "existing": existing,
                    "new": new
                })
    return conflicts

def resolve_conflicts(conflicts):
    for idx, conflict in enumerate(conflicts):
        ea = conflict['ea']
        existing = conflict['existing']
        new = conflict['new']
        ctype = conflict['type']

        idc.jumpto(ea)

        # 사용자에게 선택지 제공
        title = f"[{idx+1}/{len(conflicts)}] {ctype} at 0x{ea:X}"
        msg = (f"Existing Comment:\n{existing}\n\nNew Comment:\n{new}\n\n"
               "Apply new comment?\n(Yes = Apply new / No = Keep existing / Cancel = Stop resolving)")
        choice = ida_kernwin.ask_yn(0, msg)  # 0 = No default

        if choice == 1:  # Yes
            if ctype == "Function":
                idc.set_func_cmt(ea, new, 0)
            else:  # Code
                idc.set_cmt(ea, new, 0)
            print(f"[+] Updated comment at 0x{ea:X}")
        elif choice == -1:  # Cancel
            print("[-] Conflict resolution cancelled.")
            break
        else:  # No
            print(f"[=] Kept existing comment at 0x{ea:X}")

def main():
    conflicts = parse_conflict_log(CONFLICT_LOG_PATH)
    if not conflicts:
        ida_kernwin.warning("No conflicts found to resolve.")
        return

    resolve_conflicts(conflicts)

main()
