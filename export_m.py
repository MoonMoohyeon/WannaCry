# export_current_cfile_with_metadata_and_log.py

import idc
import ida_loader
import ida_funcs
import ida_hexrays
import os
import subprocess
import time

# --- 기본 설정 ---
timestamp = time.strftime("%Y%m%d_%H%M%S")
date_today = time.strftime("%Y-%m-%d")

REPO_PATH = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
EXPORT_DIR = os.path.join(REPO_PATH, "ida_exports_m")
LOG_DIR = os.path.join(EXPORT_DIR, "logs")
os.makedirs(EXPORT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, f"{date_today}.md")

# --- git 명령어 실행 ---
def run(cmd):
    res = subprocess.run(cmd, cwd=REPO_PATH, shell=True, text=True, capture_output=True)
    if res.returncode != 0:
        print(f"[-] `{cmd}` 실패: {res.stderr.strip()}")
    else:
        print(f"[+] `{cmd}` 성공: {res.stdout.strip()}")
    return res.returncode == 0

# --- 함수 시그니처 가져오기 ---
def get_function_signature(cfunc):
    try:
        type_str = str(cfunc.type())
        return type_str
    except Exception as e:
        print(f"[-] 시그니처 가져오기 실패: {e}")
        return "unknown_signature"

# --- 현재 함수 export ---
def export_current_function():
    ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        raise RuntimeError("커서가 함수 내부에 없습니다.")

    start = func.start_ea

    # 디컴파일
    try:
        cfunc = ida_hexrays.decompile(start)
        decompiled_text = str(cfunc)
    except Exception as e:
        print(f"[-] 디컴파일 실패: {e}")
        return None, None

    func_name = idc.get_func_name(start)
    safe_name = func_name.replace('<', '_').replace('>', '_')  # 파일명 안전하게
    file_name = f"{safe_name}_{timestamp}.c"
    file_path = os.path.join(EXPORT_DIR, file_name)

    # 함수 시그니처 가져오기
    func_signature = get_function_signature(cfunc)

    # --- Metadata 작성 ---
    metadata = [
        "// --- Metadata ---",
        f"// Function Name: {func_name}",
        f"// Address: 0x{start:X}",
        f"// Exported At: {timestamp}",
        f"// Signature: {func_signature}",
        "// ---------------",
        "",
    ]
    metadata_text = "\n".join(metadata)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(metadata_text)
        f.write(decompiled_text)

    print(f"[+] 함수 '{func_name}' 을(를) {file_path}로 내보냈습니다.")

    # --- 로그 파일 작성 ---
    with open(LOG_FILE, "a", encoding="utf-8") as logf:
        logf.write(f"\n## {time.strftime('%H:%M:%S')}\n")
        logf.write(f"- Exported `{func_name}` at address `0x{start:X}` with signature `{func_signature}`\n")

    return file_path, func_name

# --- Git + PR 생성 ---
def git_push(file_path, func_name):
    rel_path = os.path.relpath(file_path, REPO_PATH)
    rel_log_path = os.path.relpath(LOG_FILE, REPO_PATH)
    branch = f"ida-c-export/{timestamp}"

    run("git checkout main")
    run("git pull")
    run(f"git checkout -b {branch}")

    run(f"git add {rel_path}")
    run(f"git add {rel_log_path}")
    run(f'git commit -m "Export function {func_name} with metadata and logs at {timestamp}"')
    run(f"git push origin {branch}")

    # PR 생성 (gh cli 필요)
    run(f'gh pr create --base main --head {branch} '
        f'--title "Export {func_name} with metadata" '
        f'--body "Exported `{func_name}` with address `0x{idc.get_screen_ea():X}` at {timestamp}."')

# --- 메인 실행 ---
if __name__ == "__main__":
    path, name = export_current_function()
    if path:
        git_push(path, name)
