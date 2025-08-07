import os
import subprocess
import time
import sys

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../app.py"))

DEBUG = True

def log(msg):
    if DEBUG:
        print(msg)

def start_dev():
    env = os.environ.copy()
    env["PRODUCTION"] = "false"
    return subprocess.Popen(
        ["python3", APP_PATH],
        env=env,
        preexec_fn=os.setsid,
        stdout=sys.stdout,
        stderr=sys.stderr
    )

def main():
    log("[*] Starting PacCrypt in DEVELOPMENT mode...")
    start_dev()

if __name__ == "__main__":
    main()
