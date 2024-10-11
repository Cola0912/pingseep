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

# 修正: 空ファイルや不正なファイルに対するエラーハンドリングを追加
def load_previous_results(filename):
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as file:
                return set(json.load(file))
        except (json.JSONDecodeError, ValueError):
            # ファイルが空か不正な場合
            print(f"Warning: Could not load previous results from {filename}. Starting with empty set.")
            return set()
    return set()

# 修正: alive_hostsを文字列に変換して保存するように変更
def save_current_results(filename, alive_hosts):
    with open(filename, 'w') as file:
        # alive_hosts の各要素を文字列に変換して保存
        json.dump([str(host) for host in alive_hosts], file)

# 1つのIPにPingを送信してその結果を返す
def ping_ip(ip):
    response = ping(str(ip), count=1, timeout=1.2)
    return ip if response.success() else None

# 1つのIPにSSH接続が可能かどうかを確認
def check_ssh(ip, username="your_username", password="your_password"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 修正: 誤字の修正
    try:
        ssh.connect(ip, username=username, password=password, timeout=5)
        ssh.close()
        return True
    except (paramiko.ssh_exception.NoValidConnectionsError, paramiko.ssh_exception.AuthenticationException):
        return False
    except Exception as e:
        return False

# IPアドレスにPingとSSHチェックを行う関数
def ping_and_check_ssh(ip, username, password):
    result = ping_ip(ip)
    if result:
        ssh_available = check_ssh(ip, username, password)
        return ip, ssh_available
    return None, None

# スキャンの結果をtxtファイルに保存
def save_results_to_file(filename, alive_hosts, ssh_enabled_hosts):
    with open(filename, 'w') as f:
        f.write("Alive Hosts:\n")
        for host in alive_hosts:
            f.write(f"{host}\n")
        f.write("\nSSH Enabled Hosts:\n")
        for host in ssh_enabled_hosts:
            f.write(f"{host}\n")

# スキャンのメイン処理
def scan_network(ip_range, local_ip, results_file, username, password):
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        alive_hosts = set()
        previous_hosts = load_previous_results(results_file)

        ssh_enabled_hosts = []

        # プログレスバーの設定（全IP数）
        total_hosts = network.num_addresses - 2  # ネットワークアドレスとブロードキャストを除く
        with tqdm(total=total_hosts, desc="Scanning", unit="host") as pbar:
            # マルチスレッドでPingとSSHチェックを実行
            with ThreadPoolExecutor(max_workers=200) as executor:  # スレッド数を200に増加
                futures = {executor.submit(ping_and_check_ssh, ip, username, password): ip for ip in network.hosts()}

                for future in futures:
                    try:
                        ip, ssh_available = future.result()
                        if ip:
                            alive_hosts.add(ip)
                            if ssh_available:
                                ssh_enabled_hosts.append(ip)
                    except KeyboardInterrupt:
                        print("Process interrupted.")
                        executor.shutdown(wait=False)
                        raise
                    pbar.update(1)

        # 結果の表示（最後にまとめて）
        print("\nScan Complete.")
        print("\nAlive Hosts:")
        for host in alive_hosts:
            print(f"- {host}")
        
        print("\nSSH Enabled Hosts:")
        for host in ssh_enabled_hosts:
            print(f"- {host}")

        # 結果の保存
        save_current_results(results_file, alive_hosts)
        save_results_to_file("results.txt", alive_hosts, ssh_enabled_hosts)  # テキストファイルに保存
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

    username = "your_username"  # SSH接続用のユーザー名
    password = "your_password"  # SSH接続用のパスワード

    results_file = os.path.join(results_dir, f"scan_results_{ip_range.replace('/', '-')}.json")

    if ip_range:
        try:
            scan_network(ip_range, local_ip, results_file, username, password)
        except KeyboardInterrupt:
            print("Scanning process interrupted.")
    else:
        print("No valid IP range provided or detected.")
