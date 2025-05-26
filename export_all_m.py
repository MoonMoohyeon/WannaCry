# export_all_functions_with_metadata_and_log.py

import idc
import ida_loader
import idautils
import ida_hexrays
import os
import subprocess
import time

# --- 기본 설정 ---
timestamp = time.strftime("%Y%m%d_%H%M%S")
date_today = time.strftime("%Y-%m-%d")

REPO_PATH = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
EXPORT_DIR = os.path.join(REPO_PATH, "ida_exports_u")
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
        return str(cfunc.type())
    except Exception as e:
        print(f"[-] 시그니처 가져오기 실패: {e}")
        return "unknown_signature"

# --- 모든 함수 export ---
def export_all_functions():
    file_name = f"export_all_{timestamp}.c"
    file_path = os.path.join(EXPORT_DIR, file_name)

    with open(file_path, "w", encoding="utf-8") as out:
        out.write(f"// Combined export of all functions at {timestamp}\n\n")
        for start in idautils.Functions():
            try:
                cfunc = ida_hexrays.decompile(start)
                code = str(cfunc)
            except Exception as e:
                print(f"[-] 디컴파일 실패: {hex(start)}: {e}")
                continue

            func_name = idc.get_func_name(start)
            signature = get_function_signature(cfunc)
            metadata = [
                "// --- Metadata ---",
                f"// Function Name: {func_name}",
                f"// Address: 0x{start:X}",
                f"// Signature: {signature}",
                "// ---------------",
                "",
            ]
            out.write("\n".join(metadata))
            out.write(code)
            out.write("\n\n")

    print(f"[+] 모든 함수가 {file_path}로 내보내졌습니다.")

    # --- 로그 파일 작성 ---
    with open(LOG_FILE, "a", encoding="utf-8") as logf:
        logf.write(f"\n## {time.strftime('%H:%M:%S')}\n")
        logf.write(f"- Exported all functions to `{file_name}`\n")

    return file_path

# --- Git + PR 생성 ---
def git_push(file_path):
    rel_path = os.path.relpath(file_path, REPO_PATH)
    rel_log = os.path.relpath(LOG_FILE, REPO_PATH)
    branch = f"ida-c-export-all/{timestamp}"

    run("git checkout main")
    run("git pull")
    run(f"git checkout -b {branch}")

    run(f"git add {rel_path}")
    run(f"git add {rel_log}")
    run(f'git commit -m "Export all functions at {timestamp}"')
    run(f"git push origin {branch}")

    run(f'gh pr create --base main --head {branch} '
        f'--title "Export All Functions {timestamp}" '
        f'--body "Combined export of all functions at {timestamp}."')

# --- 메인 실행 ---
if __name__ == "__main__":
    path = export_all_functions()
    if path:
        git_push(path)