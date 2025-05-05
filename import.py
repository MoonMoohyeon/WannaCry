# import_cfile_to_ida.py

import idc
import ida_loader
import ida_funcs
import ida_name
import re
import os
import subprocess

# --- 설정 ---
REPO_PATH = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
EXPORT_DIR = os.path.join(REPO_PATH, "ida_exports")

# --- git pull ---
def git_pull():
    print("[*] Git pull 실행")
    subprocess.run("git pull", cwd=REPO_PATH, shell=True)

# --- Metadata 파싱 ---
def parse_metadata(file_path):
    metadata = {}
    with open(file_path, "r", encoding="utf-8") as f:
        for _ in range(10):  # 상단 10줄만 검사
            line = f.readline()
            if line.startswith("// Function Name:"):
                metadata["func_name"] = line.strip().split(":")[1].strip()
            elif line.startswith("// Address:"):
                addr_hex = line.strip().split(":")[1].strip()
                metadata["address"] = int(addr_hex, 16)
            elif line.startswith("// Signature:"):
                metadata["signature"] = line.strip().split(":")[1].strip()
            elif line.strip() == "// ---------------":
                break
    if not metadata:
        raise ValueError("Metadata를 찾을 수 없습니다.")
    return metadata

# --- 함수 이름 변경 또는 새로 생성 ---
def apply_metadata(metadata):
    ea = metadata["address"]
    func_name = metadata["func_name"]

    # 함수가 없으면 새로 생성
    if not ida_funcs.get_func(ea):
        print(f"[*] 함수가 없어서 새로 생성: {func_name} at {hex(ea)}")
        ida_funcs.add_func(ea)

    # 함수 이름 설정
    old_name = idc.get_func_name(ea)
    if old_name != func_name:
        print(f"[*] 함수 이름 변경: {old_name} -> {func_name}")
        ida_name.set_name(ea, func_name, idc.SN_CHECK)

# --- 메인 ---
def import_cfile():
    git_pull()

    # 사용자에게 파일 선택받기
    from PyQt5.QtWidgets import QFileDialog

    file_dialog = QFileDialog()
    file_dialog.setDirectory(EXPORT_DIR)
    file_dialog.setNameFilter("C Files (*.c)")
    if file_dialog.exec_():
        selected_files = file_dialog.selectedFiles()
        if selected_files:
            c_file = selected_files[0]
            print(f"[+] 선택한 파일: {c_file}")

            # Metadata 읽고 적용
            metadata = parse_metadata(c_file)
            apply_metadata(metadata)

            print(f"[+] Import 완료: {metadata['func_name']} ({hex(metadata['address'])})")

if __name__ == "__main__":
    import_cfile()
