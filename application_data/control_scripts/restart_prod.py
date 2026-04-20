import os
import subprocess
import signal
import time
import sys
import psutil
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

def stop_by_port(port=5000):
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for conn in proc.net_connections(kind="inet"):
                if conn.laddr.port == port:
                    print(f"[*] Killing process {proc.pid} using port {port}")
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
    print(f"[!] No process found using port {port}")

def main():
    print("[*] Restarting PacCrypt in PRODUCTION mode with Waitress...")
    stop_by_port()
    time.sleep(2)
    proc = start_prod()
    if proc:
        print(f"[*] Started production server with PID {proc.pid}")
        try:
            proc.wait()
        except KeyboardInterrupt:
            print("[*] Interrupted, stopping server...")
            stop_by_port()
    else:
        print("[!] Failed to start production server")

if __name__ == "__main__":
    main()
