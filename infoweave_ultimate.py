#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filename: infoweave_ultimate.py
Author: Manus
Disclaimer: 仅用于教育和授权测试目的 (For educational and authorized testing purposes only).
Description: 
    InfoWeave Ultimate 是一款顶级信息收集与漏洞预检工具，旨在模拟 APT 级别的侦察能力。
    本脚本在完全不使用任何 API Key 的前提下，集成了证书透明度挖掘、历史快照回溯、
    ASN 资产映射、隐蔽扫描、云原生安全检测及敏感路径探测等核心模块。
    [修复版]：修复了命令行参数 --no-wayback 不生效的问题，并优化了域名输入逻辑。
Legal Disclaimer: 
    严禁将本脚本用于任何未经授权的攻击行为。使用者需对自己的行为承担全部法律责任。
"""

import subprocess
import socket
import requests
import json
import os
import sys
import re
import time
import argparse
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# =========================
# 配置与常量
# =========================
CDN_KEYWORDS = ["cloudflare", "akamai", "cloudfront", "fastly", "incapsula", "sucuri", "imperva"]
TCP_PORTS = "21,22,23,25,53,80,110,139,143,389,443,445,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9000,9200,27017"
DEFAULT_TIMEOUT = 15
MAX_WORKERS = 10

class InfoWeaveUltimate:
    def __init__(self, domain, args):
        self.domain = domain
        self.args = args
        self.subdomains = set()
        self.found_ips = {} # {ip: {"cdn": bool, "subdomains": [], "ports": {}, "vulns": [], "asn": "", "ptr": ""}}
        self.results = {
            "domain": domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {"total_subdomains": 0, "total_ips": 0, "vulnerabilities": 0},
            "details": {}
        }
        self.output_file = f"ultimate_report_{domain.replace('.', '_')}.json"

    def log(self, tag, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag}] {message}")

    # 1. 证书透明度挖掘 (crt.sh)
    def fetch_ct_logs(self):
        self.log("CT", f"正在从 crt.sh 挖掘 {self.domain} 的证书记录...")
        try:
            url = f"https://crt.sh/?q={self.domain}&output=json"
            r = requests.get(url, timeout=self.args.timeout, verify=False)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get('common_name', '')
                    if name.endswith(self.domain):
                        self.subdomains.add(name.replace("*.", ""))
                    alt_names = entry.get('name_value', '').split('\n')
                    for alt in alt_names:
                        if alt.endswith(self.domain):
                            self.subdomains.add(alt.replace("*.", ""))
                self.log("CT", f"证书日志分析完成，当前共发现 {len(self.subdomains)} 个子域名")
        except Exception as e:
            self.log("!", f"crt.sh 抓取失败: {e}")

    # 2. 历史快照回溯 (Wayback Machine)
    def fetch_wayback_urls(self):
        self.log("WAYBACK", f"正在从 Wayback Machine 分页回溯历史 URL...")
        page_size = 5000
        start = 0
        total_found = 0
        
        while True:
            try:
                url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey&limit={page_size}&offset={start}"
                r = requests.get(url, timeout=self.args.timeout)
                if r.status_code != 200: break
                
                data = r.json()
                if len(data) <= 1: break
                
                for entry in data[1:]:
                    original_url = entry[2]
                    match = re.search(r'https?://([^/:]+)', original_url)
                    if match:
                        sub = match.group(1).lower()
                        if sub.endswith(self.domain):
                            self.subdomains.add(sub)
                
                batch_count = len(data) - 1
                total_found += batch_count
                self.log("WAYBACK", f"已获取 {total_found} 条历史记录，继续拉取...")
                
                if batch_count < page_size: break
                start += page_size
                time.sleep(0.5)
                
                if total_found > 50000:
                    self.log("WAYBACK", "已达到 50,000 条上限，停止拉取以保证性能")
                    break
            except KeyboardInterrupt:
                self.log("!", "用户中断 Wayback 模块，跳过并继续...")
                break
            except Exception as e:
                self.log("!", f"Wayback 分页拉取中断: {e}")
                break

    # 3. ASN 资产映射与反向 DNS
    def map_asn_and_ptr(self):
        self.log("ASN", "正在并发进行 ASN 映射与反向 DNS 查询...")
        ips = list(self.found_ips.keys())
        
        def process_ip(ip):
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                self.found_ips[ip]["ptr"] = ptr
                cmd = f"whois {ip} | grep -iE 'origin|ASNumber|Organization' | head -n 3"
                whois_out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode()
                self.found_ips[ip]["asn_info"] = whois_out.strip()
            except: pass

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(process_ip, ips)

    # 4. 隐蔽扫描与规避
    def stealth_scan(self):
        self.log("STEALTH", "正在启动隐蔽扫描 (分片与诱饵技术)...")
        for ip, data in self.found_ips.items():
            if data["cdn"]: continue
            self.log("NMAP", f"隐蔽探测目标: {ip}")
            try:
                cmd = ["nmap", "-sS", "-sV", "-f", "-D", "RND:5", "--source-port", "53", "-p", TCP_PORTS, "--open", "--host-timeout", "5m", ip]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=300).decode()
                
                matches = re.findall(r"(\d+)/tcp\s+open\s+([^\s]+)\s+(.*)", output)
                for port, service, version in matches:
                    data["ports"][port] = {"service": service, "version": version.strip()}
                    self.log("OPEN", f"{ip}:{port} -> {service}")
            except subprocess.TimeoutExpired:
                self.log("!", f"Nmap 扫描 {ip} 超时，跳过")
            except: pass

    # 5. 云原生与容器安全探测
    def cloud_container_audit(self):
        self.log("AUDIT", "正在探测云原生与容器暴露风险...")
        targets = []
        for ip, data in self.found_ips.items():
            if not data["cdn"]: targets.append(ip)
        
        def check_target(ip):
            for port in ["6443", "10250"]:
                try:
                    r = requests.get(f"https://{ip}:{port}/version", verify=False, timeout=3)
                    if r.status_code == 200:
                        self.found_ips[ip]["vulns"].append({"name": f"K8s API Exposure ({port})", "severity": "critical"})
                except: pass
            try:
                r = requests.get(f"http://{ip}:2375/version", timeout=3)
                if r.status_code == 200:
                    self.found_ips[ip]["vulns"].append({"name": "Docker Remote API Exposure", "severity": "critical"})
            except: pass

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(check_target, targets)

    # 6. 自动化漏洞扫描 (Nuclei)
    def run_nuclei(self):
        self.log("NUCLEI", "正在启动 Nuclei 深度扫描...")
        target_file = "ultimate_targets.txt"
        with open(target_file, "w") as f:
            for ip, data in self.found_ips.items():
                if not data["cdn"]: f.write(f"{ip}\n")
                for sub in data["subdomains"]: f.write(f"{sub}\n")

        try:
            cmd = ["nuclei", "-l", target_file, "-silent", "-severity", "medium,high,critical", "-jsonl", "-timeout", str(self.args.timeout)]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            
            for line in process.stdout:
                try:
                    vuln = json.loads(line)
                    ip_or_host = vuln.get("ip", vuln.get("host"))
                    for ip in self.found_ips:
                        if ip == ip_or_host or any(sub in ip_or_host for sub in self.found_ips[ip]["subdomains"]):
                            self.found_ips[ip]["vulns"].append({
                                "name": vuln.get("info", {}).get("name"),
                                "severity": vuln.get("info", {}).get("severity"),
                                "id": vuln.get("template-id")
                            })
                            self.results["summary"]["vulnerabilities"] += 1
                except: continue
        except Exception as e:
            self.log("!", f"Nuclei 运行异常: {e}")

    def save_report(self):
        self.results["details"] = self.found_ips
        self.results["summary"]["total_subdomains"] = len(self.subdomains)
        self.results["summary"]["total_ips"] = len(self.found_ips)
        with open(self.output_file, "w") as f:
            json.dump(self.results, f, indent=4)
        self.log("DONE", f"终极报告已生成: {self.output_file}")

    def run(self):
        try:
            # 基础子域名收集
            self.log("SUB", "正在进行基础子域名收集...")
            try:
                cmd = ["subfinder", "-d", self.domain, "-silent"]
                res = subprocess.check_output(cmd, timeout=60).decode().splitlines()
                self.subdomains.update([s.strip() for s in res if s.strip()])
            except: pass
            
            # 修复：严格根据参数决定是否执行模块
            if not self.args.no_ct:
                self.fetch_ct_logs()
            else:
                self.log("SKIP", "已跳过 crt.sh 模块")

            if not self.args.no_wayback:
                self.fetch_wayback_urls()
            else:
                self.log("SKIP", "已跳过 Wayback 模块")
            
            # 解析 IP 并识别 CDN
            self.log("RESOLVE", f"正在解析 {len(self.subdomains)} 个子域名...")
            for sub in list(self.subdomains):
                try:
                    ip = socket.gethostbyname(sub)
                    if ip not in self.found_ips:
                        self.found_ips[ip] = {"cdn": False, "subdomains": [], "ports": {}, "vulns": []}
                    if sub not in self.found_ips[ip]["subdomains"]:
                        self.found_ips[ip]["subdomains"].append(sub)
                    if any(kw in sub for kw in CDN_KEYWORDS):
                        self.found_ips[ip]["cdn"] = True
                except: continue
            
            self.map_asn_and_ptr()
            self.stealth_scan()
            self.cloud_container_audit()
            
            if not self.args.no_nuclei:
                self.run_nuclei()
            else:
                self.log("SKIP", "已跳过 Nuclei 扫描")

            self.save_report()
            
        except KeyboardInterrupt:
            self.log("!", "检测到 Ctrl+C，正在保存当前结果并退出...")
            self.save_report()
            sys.exit(130)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfoWeave Ultimate - APT Recon Tool")
    parser.add_argument("domain", help="目标域名", nargs="?")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="网络请求超时时间 (秒)")
    parser.add_argument("--no-wayback", action="store_true", help="跳过 Wayback 模块")
    parser.add_argument("--no-ct", action="store_true", help="跳过 crt.sh 模块")
    parser.add_argument("--no-nuclei", action="store_true", help="跳过 Nuclei 扫描")
    args = parser.parse_args()

    # 修复：如果命令行已提供域名，则不再弹出 input()
    target = args.domain
    if not target:
        target = input("输入目标域名: ").strip()
    
    if target:
        scanner = InfoWeaveUltimate(target, args)
        scanner.run()
    else:
        print("错误: 未指定目标域名")
        sys.exit(1)
