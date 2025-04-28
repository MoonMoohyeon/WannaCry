import idc
import ida_loader
import ida_funcs
import ida_hexrays
import ida_kernwin
import os
import subprocess
import time
import re

# Git & paths
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


def git_sync():
    """
    Git pull from main branch before importing
    """
    run("git checkout main")
    run("git pull")


def choose_file():
    """
    Ask user to pick one of the exported .c files
    """
    return ida_kernwin.ask_file(False, EXPORT_DIR + os.sep + "*.c", "Import C file:")


def import_cfile():
    # 1) Git pull
    git_sync()

    # 2) Choose .c file to import
    file_path = choose_file()
    if not file_path:
        print("[-] 가져올 파일을 선택하지 않았습니다.")
        return

    # 3) Read file content
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 4) Extract function signature (prototype)
    #    Capture everything up to the opening brace '{'
    sig_match = re.search(r"^([^{]+)\{", content, re.MULTILINE)
    if not sig_match:
        print("[-] 함수 시그니처를 찾을 수 없습니다.")
        return
    prototype = sig_match.group(1).strip()  # e.g. "int foo(int a, char* b)
    # Ensure semicolon terminated signature
    if not prototype.endswith(';'):
        prototype = prototype + ';'
    print(f"[+] 파싱된 함수 시그니처: {prototype}")

    # 5) Find current function under cursor
    ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        print("[-] 커서가 함수 내부에 없습니다.")
        return

    # 6) Apply prototype (sets function & argument names)
    if not idc.SetType(func.start_ea, prototype):
        print(f"[-] 프로토타입 설정 실패: {prototype}")
    else:
        print(f"[+] 함수 프로토타입을 설정했습니다: {prototype}")

    # 7) Attach full pseudocode & comments as repeatable comment
    idc.set_cmt(func.start_ea, content, True)
    print(f"[+] 원본 C 파일 내용을 함수 주석으로 추가했습니다.")

if __name__ == '__main__':
    import_cfile()
