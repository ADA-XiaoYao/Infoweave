# InfoWeave - 顶级信息收集与侦察建模仓库

InfoWeave 是一款专为红队评估和国家级侦察设计的高效工具。它通过 **InfoWeave Ultimate (National-Level APT Edition)** 实现了全维度、高精度、隐蔽化的情报建模，且**完全不需要任何 API Key**。

## 核心功能

### 1. 基础版 (infoweave.py)
- **资产发现**：子域名收集与 CDN 识别。

### 2. 专业版 (infoweave_pro.py)
- **漏洞预检**：服务识别与自动化漏洞扫描。

### 3. 终极版 (infoweave_ultimate.py) - **[National-Level APT Edition]**
- **全协议主动探测引擎**：
    - **全端口扫描**：覆盖 1-65535 常用及高危端口（TCP/UDP）。
    - **服务指纹对齐**：深度识别中间件版本、框架及 HTTP 标题。
- **Web 攻击面建模引擎**：
    - **JS 敏感信息提取**：自动分析 JS 文件，提取 API 端点、硬编码密钥及注释。
    - **API 发现**：基于流量和代码分析，自动构建目标的 API 资产清单。
- **基础设施指纹引擎**：
    - **SSL/TLS 证书审计**：深度解析证书 SANs，挖掘隐藏的关联域名。
    - **Favicon/JARM 关联**：通过指纹对齐在全网定位目标的同构服务器。
- **云与供应链侦察引擎**：
    - **云存储桶权限校验**：自动化探测 S3/Azure Blob 的公开列取与写入权限。
    - **供应链审计**：分析第三方 JS 库版本并关联已知 CVE。

## 安装要求

工具依赖以下外部组件，请确保已安装：

- Python 3.x
- `nmap` (完整版，需支持 NSE 脚本)
- `subfinder`
- `nuclei`
- `requests`, `beautifulsoup4` (Python 库)

## 使用方法

1. 克隆仓库：
   ```bash
   git clone https://github.com/ADA-XiaoYao/Infoweave.git
   cd Infoweave
   ```

2. 运行国家级侦察版：
   ```bash
   # 基础运行
   python3 infoweave_ultimate.py example.com
   
   # 高级参数
   python3 infoweave_ultimate.py example.com --timeout 30 --no-nuclei
   ```

## 法律声明

本工具仅用于授权的渗透测试和安全研究。使用者需遵守当地法律法规，严禁用于非法攻击。
