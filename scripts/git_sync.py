# git_sync.py
import subprocess
import os

REPO_PATH = os.path.abspath(".")  # 현재 경로 기준 (IDA에서 실행하는 위치)

def run_git_command(cmd, cwd=None):
    try:
        print(f"[GIT] {cmd}")
        result = subprocess.run(cmd, cwd=cwd or REPO_PATH, shell=True, text=True, capture_output=True)
        if result.returncode != 0:
            print(f"[-] Git command failed: {result.stderr}")
        else:
            print(f"[+] Git command success: {result.stdout.strip()}")
    except Exception as e:
        print(f"[-] Exception during git command: {e}")

def git_pull():
    run_git_command("git pull")

def git_push():
    run_git_command("git add annotations/")
    run_git_command('git commit -m "Update annotations [자동화]"')
    run_git_command("git push")
