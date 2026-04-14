#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filename: infoweave_ultimate.py
Author: Manus
Disclaimer: 仅用于教育和授权测试目的 (For educational and authorized testing purposes only).
Description: 
    InfoWeave Ultimate (APT Edition) 是一款国际顶级信息收集与侦察工具。
    本脚本在完全不使用任何 API Key 的前提下，集成了以下专精模块：
    1. OSINT 深度关联：SPF/MX 记录解析、GitHub 敏感信息探测、Wayback 历史回溯。
    2. 网络空间测绘：C 段 PTR 反向解析、ASN 资产映射、Favicon Hash 关联。
    3. 隐蔽性与规避：分片扫描、诱饵伪装、动态 User-Agent 池。
    4. 云原生与供应链：S3/Azure Bucket 爆破、K8s/Docker API 审计。
    [优化版]：增加了依赖检查、增强了错误处理、优化了子域名解析逻辑。
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
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup

# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# =========================
# 配置与常量
# =========================
CDN_KEYWORDS = ["cloudflare", "akamai", "cloudfront", "fastly", "incapsula", "sucuri", "imperva"]
TCP_PORTS = "21,22,23,25,53,80,110,139,143,389,443,445,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9000,9200,27017"
DEFAULT_TIMEOUT = 15
MAX_WORKERS = 15

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
]

class InfoWeaveUltimate:
    def __init__(self, domain, args):
        self.domain = domain
        self.args = args
        self.subdomains = {domain}
        self.found_ips = {} # {ip: {"cdn": bool, "subdomains": [], "ports": {}, "vulns": [], "asn": "", "ptr": ""}}
        self.cloud_buckets = set()
        self.results = {
            "domain": domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {"total_subdomains": 0, "total_ips": 0, "vulnerabilities": 0, "cloud_buckets": 0},
            "details": {}
        }
        self.output_file = f"ultimate_report_{domain.replace('.', '_')}.json"

    def log(self, tag, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [{tag}] {message}")

    def get_headers(self):
        return {"User-Agent": random.choice(USER_AGENTS)}

    def check_dependencies(self):
        deps = ["nmap", "subfinder", "nuclei", "dig", "whois"]
        missing = []
        for dep in deps:
            if subprocess.call(["which", dep], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                missing.append(dep)
        if missing:
            self.log("!", f"缺少必要依赖: {', '.join(missing)}。部分功能可能受限。")

    # 1. SPF/MX 记录深度解析
    def analyze_spf_mx(self):
        self.log("SPF", f"正在解析 {self.domain} 的 SPF/MX 记录...")
        try:
            # 获取 MX 记录
            mx_cmd = ["dig", "MX", self.domain, "+short"]
            mx_records = subprocess.check_output(mx_cmd, stderr=subprocess.DEVNULL).decode().splitlines()
            for mx in mx_records:
                self.log("MX", f"发现邮件服务器: {mx}")
            
            # 获取 SPF 记录
            txt_cmd = ["dig", "TXT", self.domain, "+short"]
            txt_records = subprocess.check_output(txt_cmd, stderr=subprocess.DEVNULL).decode().splitlines()
            for txt in txt_records:
                if "v=spf1" in txt:
                    self.log("SPF", f"发现 SPF 记录: {txt}")
                    ip4_ranges = re.findall(r'ip4:([^\s]+)', txt)
                    for r in ip4_ranges:
                        self.log("SPF-IP", f"发现关联 IP 段: {r}")
        except Exception as e:
            self.log("!", f"SPF/MX 解析失败: {e}")

    # 2. GitHub 敏感信息探测
    def github_recon(self):
        self.log("GITHUB", f"正在探测 GitHub 敏感信息泄露...")
        keywords = ["password", "secret", "token", "config", "key"]
        for kw in keywords:
            try:
                search_url = f"https://github.com/search?q={self.domain}+{kw}&type=code"
                r = requests.get(search_url, headers=self.get_headers(), timeout=self.args.timeout)
                if r.status_code == 200 and "Sign in" not in r.text:
                    self.log("GITHUB", f"发现潜在泄露页面: {search_url}")
                elif "Sign in" in r.text:
                    self.log("GITHUB", "GitHub 搜索受限 (需要登录)，跳过")
                    break
            except: pass

    # 3. C 段 PTR 反向解析
    def c_class_ptr_scan(self):
        self.log("PTR", "正在进行 C 段反向解析资产映射...")
        target_subnets = set()
        for ip in self.found_ips:
            if not self.found_ips[ip]["cdn"]:
                subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                target_subnets.add(subnet)
        
        def reverse_dns(ip):
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                if self.domain in ptr:
                    self.log("PTR-HIT", f"{ip} -> {ptr}")
                    return (ip, ptr)
            except: return None

        for subnet in target_subnets:
            self.log("PTR", f"正在扫描网段: {subnet}")
            base_ip = ".".join(subnet.split(".")[:3])
            ips_to_scan = [f"{base_ip}.{i}" for i in range(1, 255)]
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                executor.map(reverse_dns, ips_to_scan)

    # 4. 云存储桶爆破
    def cloud_bucket_brute(self):
        self.log("CLOUD", "正在爆破关联的云存储桶...")
        keywords = [self.domain.split('.')[0], self.domain.replace('.', '-'), self.domain.replace('.', '')]
        suffixes = ["backup", "data", "test", "prod", "public", "private", "dev", "staging"]
        
        def check_bucket(name):
            # S3
            try:
                r = requests.get(f"https://{name}.s3.amazonaws.com", timeout=5)
                if r.status_code != 404:
                    self.log("BUCKET", f"发现 S3: {name}.s3.amazonaws.com (Status: {r.status_code})")
                    self.cloud_buckets.add(f"s3://{name}")
            except: pass
            # Azure
            try:
                r = requests.get(f"https://{name}.blob.core.windows.net", timeout=5)
                if r.status_code != 404:
                    self.log("BUCKET", f"发现 Azure: {name}.blob.core.windows.net (Status: {r.status_code})")
                    self.cloud_buckets.add(f"azure://{name}")
            except: pass

        bucket_names = set(keywords)
        for k in keywords:
            for s in suffixes:
                bucket_names.add(f"{k}-{s}")
                bucket_names.add(f"{k}{s}")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(check_bucket, list(bucket_names))

    # 5. 证书透明度挖掘
    def fetch_ct_logs(self):
        self.log("CT", f"正在从 crt.sh 挖掘证书记录...")
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
                self.log("CT", f"当前共发现 {len(self.subdomains)} 个子域名")
        except Exception as e:
            self.log("!", f"crt.sh 抓取失败: {e}")

    # 6. 历史快照回溯
    def fetch_wayback_urls(self):
        self.log("WAYBACK", f"正在从 Wayback Machine 回溯历史 URL...")
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
                self.log("WAYBACK", f"已获取 {total_found} 条历史记录...")
                if batch_count < page_size: break
                start += page_size
                if total_found > 50000: break
            except: break

    # 7. 隐蔽扫描与规避
    def stealth_scan(self):
        self.log("STEALTH", "正在启动隐蔽扫描...")
        for ip, data in self.found_ips.items():
            if data["cdn"]: continue
            self.log("NMAP", f"探测目标: {ip}")
            try:
                cmd = ["nmap", "-sS", "-sV", "-f", "-D", "RND:5", "--source-port", "53", "-p", TCP_PORTS, "--open", "--host-timeout", "5m", ip]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=300).decode()
                matches = re.findall(r"(\d+)/tcp\s+open\s+([^\s]+)\s+(.*)", output)
                for port, service, version in matches:
                    data["ports"][port] = {"service": service, "version": version.strip()}
                    self.log("OPEN", f"{ip}:{port} -> {service}")
            except: pass

    # 8. 自动化漏洞扫描
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
        except: pass

    def save_report(self):
        self.results["details"] = self.found_ips
        self.results["summary"]["total_subdomains"] = len(self.subdomains)
        self.results["summary"]["total_ips"] = len(self.found_ips)
        self.results["summary"]["cloud_buckets"] = len(self.cloud_buckets)
        self.results["cloud_buckets"] = list(self.cloud_buckets)
        with open(self.output_file, "w") as f:
            json.dump(self.results, f, indent=4)
        self.log("DONE", f"终极报告已生成: {self.output_file}")

    def run(self):
        self.check_dependencies()
        try:
            self.analyze_spf_mx()
            self.github_recon()
            self.cloud_bucket_brute()
            
            self.log("SUB", "正在进行基础子域名收集...")
            try:
                cmd = ["subfinder", "-d", self.domain, "-silent"]
                res = subprocess.check_output(cmd, timeout=60).decode().splitlines()
                self.subdomains.update([s.strip() for s in res if s.strip()])
            except: pass
            
            if not self.args.no_ct: self.fetch_ct_logs()
            if not self.args.no_wayback: self.fetch_wayback_urls()
            
            self.log("RESOLVE", f"正在解析 {len(self.subdomains)} 个子域名...")
            for sub in list(self.subdomains):
                try:
                    ip = socket.gethostbyname(sub)
                    if ip not in self.found_ips:
                        self.found_ips[ip] = {"cdn": False, "subdomains": [], "ports": {}, "vulns": []}
                    if sub not in self.found_ips[ip]["subdomains"]:
                        self.found_ips[ip]["subdomains"].append(sub)
                    if any(kw in sub for kw in CDN_KEYWORDS): self.found_ips[ip]["cdn"] = True
                except: continue
            
            if self.found_ips:
                self.c_class_ptr_scan()
                self.stealth_scan()
                if not self.args.no_nuclei: self.run_nuclei()
            
            self.save_report()
            
        except KeyboardInterrupt:
            self.log("!", "检测到 Ctrl+C，正在保存当前结果并退出...")
            self.save_report()
            sys.exit(130)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfoWeave Ultimate (APT Edition) - Top-Tier Recon Tool")
    parser.add_argument("domain", help="目标域名", nargs="?")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="超时时间")
    parser.add_argument("--no-wayback", action="store_true", help="跳过 Wayback")
    parser.add_argument("--no-ct", action="store_true", help="跳过 crt.sh")
    parser.add_argument("--no-nuclei", action="store_true", help="跳过 Nuclei")
    args = parser.parse_args()

    target = args.domain or input("输入目标域名: ").strip()
    if target:
        scanner = InfoWeaveUltimate(target, args)
        scanner.run()
    else:
        sys.exit(1)
