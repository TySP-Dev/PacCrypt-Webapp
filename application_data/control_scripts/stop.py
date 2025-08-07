import psutil
import os
import signal

DEBUG = True

def log(msg):
    if DEBUG:
        print(msg)

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
    stop_by_port()

if __name__ == "__main__":
    main()
