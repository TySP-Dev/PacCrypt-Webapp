import os
import subprocess
import signal
import time
import sys
import psutil

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

def stop_by_port(port=5000):
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for conn in proc.connections(kind="inet"):
                if conn.laddr.port == port:
                    log(f"[*] Killing process {proc.pid} using port {port}")
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    return
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    log(f"[!] No process found using port {port}")

def main():
    log("[*] Restarting PacCrypt in DEVELOPMENT mode...")
    stop_by_port()
    time.sleep(1)
    start_dev()

if __name__ == "__main__":
    main()
