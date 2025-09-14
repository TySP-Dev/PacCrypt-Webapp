import os
import subprocess
import time
import sys
import platform

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../app.py"))

def start_prod():
    env = os.environ.copy()
    env["PRODUCTION"] = "true"
    
    if platform.system() == "Windows":
        return subprocess.Popen(
            ["python", APP_PATH],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    else:
        return subprocess.Popen(
            ["python3", APP_PATH],
            env=env,
            preexec_fn=os.setsid,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

def main():
    print("[*] Starting PacCrypt in PRODUCTION mode with Waitress...")
    start_prod()

if __name__ == "__main__":
    main()
