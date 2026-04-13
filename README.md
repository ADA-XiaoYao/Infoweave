# InfoWeave - 顶级信息收集仓库

InfoWeave 是一款专为渗透测试和红队评估设计的高效信息收集工具。它集成了子域名枚举、CDN 识别、端口扫描、服务版本识别以及 Web 目录爆破功能，且**完全不需要任何 API Key**。

## 核心功能

- **子域名收集**：集成 `subfinder` 引擎，快速发现目标关联子域名。
- **CDN 识别**：自动检测目标 IP 是否属于常见 CDN 服务商（Cloudflare, Akamai 等）。
- **端口扫描与服务识别**：利用 `nmap` 进行深度扫描，识别开放端口及其运行的服务版本。
- **Web 目录爆破**：使用 `gobuster` 或内置轻量级字典探测敏感路径（如 `.git`, `.env`, `admin` 等）。
- **自动化报告**：扫描结果自动保存为结构化的 JSON 报告，便于后续分析。

## 安装要求

工具依赖以下外部组件，请确保已安装：

- Python 3.x
- `nmap`
- `subfinder`
- `gobuster`
- `requests` (Python 库)

## 使用方法

1. 克隆仓库：
   ```bash
   git clone https://github.com/ADA-XiaoYao/Infoweave.git
   cd Infoweave
   ```

2. 运行脚本：
   ```bash
   python3 infoweave.py
   ```

3. 输入目标域名（如 `example.com`），等待扫描完成。

## 法律声明

本工具仅用于授权的渗透测试和安全研究。使用者需遵守当地法律法规，严禁用于非法攻击。
