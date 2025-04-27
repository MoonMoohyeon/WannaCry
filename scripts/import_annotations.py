# import_annotations_v3.py
import json
import os
import glob
import shutil
import idaapi
import idc
import ida_kernwin

import git_sync

def backup_idb():
    # 현재 IDB 파일 백업
    input_file = idaapi.get_input_file_path()
    if input_file:
        backup_file = input_file + ".bak"
        shutil.copyfile(input_file, backup_file)
        print(f"[+] Backup created: {backup_file}")

def select_latest_annotation_file(folder="annotations"):
    files = glob.glob(os.path.join(folder, "annotations_*.json"))
    if not files:
        print("[-] No annotation files found.")
        return None

    # 가장 최근 파일 선택
    latest_file = max(files, key=os.path.getctime)
    return latest_file

def choose_annotation_file(folder="annotations"):
    files = glob.glob(os.path.join(folder, "annotations_*.json"))
    if not files:
        print("[-] No annotation files found.")
        return None

    options = "\n".join(f"[{idx}] {os.path.basename(f)}" for idx, f in enumerate(files))
    choice = ida_kernwin.ask_long(0, f"Select annotation file:\n{options}\n\nInput number:")
    if choice is None or choice < 0 or choice >= len(files):
        print("[-] Invalid choice.")
        return None

    return files[choice]

def ask_overwrite():
    # 덮어쓰기 여부 묻기
    result = ida_kernwin.ask_yn(1, "Overwrite existing comments if conflict?\n(Yes=Overwrite / No=Keep existing)")  # 1=Yes default
    return result == 1  # Yes이면 True 반환

def import_annotations(auto=True, folder="annotations"):
    backup_idb()

    input_file = select_latest_annotation_file(folder) if auto else choose_annotation_file(folder)
    if not input_file:
        return

    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 덮어쓰기 여부 확인
    overwrite_comments = ask_overwrite()

    # conflict log 저장용
    conflict_log = []

    # 함수 이름 및 주석 복원
    for func in data.get('functions', []):
        ea = func['ea']
        name = func['name']
        comment = func['comment']

        if idc.get_func_name(ea) != name:
            idc.set_name(ea, name, idc.SN_AUTO)

        if comment:
            old_comment = idc.get_func_cmt(ea, 0)
            if old_comment and not overwrite_comments:
                conflict_log.append(f"Function Comment Conflict at 0x{ea:X}: existing='{old_comment}' new='{comment}'")
            if overwrite_comments or not old_comment:
                idc.set_func_cmt(ea, comment, 0)

    # 코드 주석 복원
    for cmt in data.get('comments', []):
        ea = cmt['ea']
        comment = cmt['comment']

        old_comment = idc.get_cmt(ea, 0)
        if old_comment and not overwrite_comments:
            conflict_log.append(f"Code Comment Conflict at 0x{ea:X}: existing='{old_comment}' new='{comment}'")
        if overwrite_comments or not old_comment:
            idc.set_cmt(ea, comment, 0)

    print(f"[+] Annotations imported from {input_file}")

    # conflict log 저장
    if conflict_log:
        log_file = os.path.join(folder, "conflict_log.txt")
        with open(log_file, "w", encoding="utf-8") as f:
            for line in conflict_log:
                f.write(line + "\n")
        print(f"[!] Conflicts detected. Log saved to {log_file}")
    else:
        print("[+] No conflicts detected.")


# Git Pull 먼저
git_sync.git_pull()

# 실행 (자동 최신 파일 선택, 수동 선택은 auto=False)
import_annotations(auto=True)

# Git Push
git_sync.git_push()
