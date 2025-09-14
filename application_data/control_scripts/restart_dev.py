import os
import subprocess
import signal
import time
import sys
import psutil
import platform

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../app.py"))

DEBUG = True

def log(msg):
    if DEBUG:
        print(msg)

def start_dev():
    env = os.environ.copy()
    env["PRODUCTION"] = "false"
    
    if platform.system() == "Windows":
        return subprocess.Popen(
            ["python", APP_PATH],
            env=env,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
    else:
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
            for conn in proc.net_connections(kind="inet"):
                if conn.laddr.port == port:
                    log(f"[*] Killing process {proc.pid} using port {port}")
                    if platform.system() == "Windows":
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except psutil.TimeoutExpired:
                            proc.kill()
                    else:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    return
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    log(f"[!] No process found using port {port}")

def main():
    log("[*] Restarting PacCrypt in DEVELOPMENT mode...")
    stop_by_port()
    time.sleep(2)
    proc = start_dev()
    if proc:
        log(f"[*] Started development server with PID {proc.pid}")
        try:
            proc.wait()
        except KeyboardInterrupt:
            log("[*] Interrupted, stopping server...")
            stop_by_port()
    else:
        log("[!] Failed to start development server")

if __name__ == "__main__":
    main()
