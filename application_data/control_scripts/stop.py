import psutil
import os
import signal
import platform

DEBUG = True

def log(msg):
    if DEBUG:
        print(msg)

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
    stop_by_port()

if __name__ == "__main__":
    main()
