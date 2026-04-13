# InfoWeave - 顶级信息收集与漏洞预检仓库

InfoWeave 是一款专为渗透测试和红队评估设计的高效工具。它不仅集成了基础的资产发现功能，还通过 **InfoWeave Ultimate** 实现了 APT 级别的侦察能力，且**完全不需要任何 API Key**。

## 核心功能

### 1. 基础版 (infoweave.py)
- **子域名收集**：集成 `subfinder` 引擎。
- **CDN 识别**：自动检测并过滤 CDN 节点。

### 2. 专业版 (infoweave_pro.py)
- **深度服务识别**：利用 `nmap` NSE 脚本识别中间件版本。
- **自动化漏洞扫描**：集成 `nuclei` 引擎。

### 3. 终极版 (infoweave_ultimate.py) - **NEW!**
- **证书透明度挖掘**：通过 `crt.sh` 爬虫发现隐藏子域名及内部系统。
- **历史快照回溯**：利用 `Wayback Machine` 抓取历史 URL、API 文档及备份文件。
- **ASN 资产映射**：自动获取目标 AS 号并进行全网段 PTR 反向解析。
- **隐蔽扫描引擎**：集成 Nmap 的分片（-f）、诱饵（-D）及源端口伪装技术。
- **云原生与容器审计**：自动化探测 K8s API、Docker Remote API 及云元数据暴露。
- **零 API Key 依赖**：所有高级功能均通过公开数据源爬取和本地扫描实现。

## 安装要求

工具依赖以下外部组件，请确保已安装：

- Python 3.x
- `nmap` (完整版)
- `subfinder`
- `nuclei`
- `requests`, `beautifulsoup4` (Python 库)

## 使用方法

1. 克隆仓库：
   ```bash
   git clone https://github.com/ADA-XiaoYao/Infoweave.git
   cd Infoweave
   ```

2. 运行终极版：
   ```bash
   python3 infoweave_ultimate.py
   ```

3. 输入目标域名（如 `example.com`），等待扫描完成。结果将保存为 `ultimate_report_domain.json`。

## 法律声明

本工具仅用于授权的渗透测试和安全研究。使用者需遵守当地法律法规，严禁用于非法攻击。
