import subprocess
import ipaddress
import sys
from pythonping import ping
from tqdm import tqdm
from termcolor import colored
import os
import json
import socket
from concurrent.futures import ThreadPoolExecutor
import paramiko  # SSH接続に使用

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror):
        return None

def get_local_ip_range():
    ip_cmd = subprocess.check_output("ip a | grep 'inet ' | grep -v '127.0.0.1'", shell=True).decode()
    for line in ip_cmd.splitlines():
        ip_info = line.split()
        ip_addr = ip_info[1]
        if '/' in ip_addr:
            return ip_addr
    return None

def load_previous_results(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return set(json.load(file))
    return set()

def save_current_results(filename, alive_hosts):
    with open(filename, 'w') as file:
        json.dump(list(alive_hosts), file)

# 1つのIPにPingを送信してその結果を返す
def ping_ip(ip):
    response = ping(str(ip), count=1, timeout=0.7)
    return ip if response.success() else None

# 1つのIPにSSH接続が可能かどうかを確認
def check_ssh(ip, username="your_username", password="your_password"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=username, password=password, timeout=5)
        ssh.close()
        return True
    except (paramiko.ssh_exception.NoValidConnectionsError, paramiko.ssh_exception.AuthenticationException):
        return False
    except Exception as e:
        print(f"Error connecting to {ip}: {e}")
        return False

# スキャンのメイン処理
def scan_network(ip_range, local_ip, results_file):
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        alive_hosts = set()
        previous_hosts = load_previous_results(results_file)

        # プログレスバーの設定
        pbar = tqdm(total=network.num_addresses - 2, desc="Scanning", unit="host")

        # マルチスレッドでPingとSSHチェックを実行
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_ip, ip): ip for ip in network.hosts()}

            for future in tqdm(futures, total=len(futures), desc="Pinging"):
                ip = futures[future]
                try:
                    result = future.result()
                    if result:
                        alive_hosts.add(str(ip))
                except Exception as e:
                    print(f"Error pinging {ip}: {e}")
                pbar.update(1)

        pbar.close()

        # SSH接続が可能かどうかを確認
        ssh_enabled_hosts = []
        print("\nChecking SSH access:")
        for ip in alive_hosts:
            if check_ssh(ip):
                ssh_enabled_hosts.append(ip)
                print(colored(f"SSH available on {ip}", "green"))
            else:
                print(f"No SSH on {ip}")

        # 新しいホストや消失したホストの検出
        new_hosts = alive_hosts - previous_hosts
        gone_hosts = previous_hosts - alive_hosts

        print("\nFound hosts:")
        all_hosts = previous_hosts.union(alive_hosts)
        for host in all_hosts:
            hostname = get_hostname(host)
            display_text = f"{host} ({hostname})" if hostname else host
            color = None
            if host == local_ip:
                color = 'blue'
            elif host in new_hosts:
                color = 'green'
            elif host in gone_hosts:
                color = 'red'
            elif host in alive_hosts:
                color = None
            print(colored(display_text, color) if color else display_text)

        # 結果の保存
        save_current_results(results_file, alive_hosts)
    except ValueError as e:
        print(f"Error: {e}")

# メイン処理
if __name__ == "__main__":
    results_dir = os.path.expanduser('~/pingsweep/scanresults')
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    local_ip = get_local_ip_range()
    local_ip = local_ip.split('/')[0] if local_ip else None

    if len(sys.argv) > 1:
        ip_range = sys.argv[1]
    else:
        ip_range = get_local_ip_range()

    results_file = os.path.join(results_dir, f"scan_results_{ip_range.replace('/', '-')}.json")

    if ip_range:
        scan_network(ip_range, local_ip, results_file)
    else:
        print("No valid IP range provided or detected.")
