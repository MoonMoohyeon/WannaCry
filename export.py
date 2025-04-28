# export_current_cfile.py

import idc
import ida_loader
import ida_funcs
import ida_hexrays
import os
import subprocess
import time

timestamp = time.strftime("%Y%m%d_%H%M%S")

REPO_PATH = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
EXPORT_DIR = os.path.join(REPO_PATH, "ida_exports")
os.makedirs(EXPORT_DIR, exist_ok=True)

def run(cmd):
    res = subprocess.run(cmd, cwd=REPO_PATH, shell=True, text=True, capture_output=True)
    if res.returncode != 0:
        print(f"[-] `{cmd}` 실패: {res.stderr.strip()}")
    else:
        print(f"[+] `{cmd}` 성공: {res.stdout.strip()}")
    return res.returncode == 0

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
        return

    func_name = idc.get_func_name(start)
    safe_name = func_name.replace('<', '_').replace('>', '_')  # 파일명 안전하게
    file_name = f"{safe_name}_{timestamp}.c"
    file_path = os.path.join(EXPORT_DIR, file_name)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(decompiled_text)

    print(f"[+] 함수 '{func_name}' 을(를) {file_path}로 내보냈습니다.")

    return file_path, func_name

def git_push(file_path, func_name):
    rel_path = os.path.relpath(file_path, REPO_PATH)
    branch = f"ida-c-export/{timestamp}"

    run("git checkout main")
    run("git pull")
    run(f"git checkout -b {branch}")

    run(f"git add {rel_path}")
    run(f'git commit -m "Export function {func_name} at {timestamp}"')
    run(f"git push origin {branch}")

    run(f'gh pr create --base main --head {branch} '
        f'--title "Export {func_name}" '
        f'--body "Exported decompiled function {func_name} at {timestamp}."')

if __name__ == "__main__":
    path, name = export_current_function()
    if path:
        git_push(path, name)
