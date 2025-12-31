🛡️ BaguetteAV

基于 ClamAV 引擎的 Windows 杀毒软件

#-快速开始 • #-功能特性 • #-自行编译 • #-致谢

</div>

✨ 功能特性

• ⚡ 全盘扫描 - 扫描系统，全面检测威胁

• 📁 自定义扫描 - 选择指定目录进行扫描

• 🔍 Rootkit 检测 - 检测隐藏进程、可疑服务、启动项、Hosts劫持、可疑驱动

• 🛡️ ClamAV 引擎 - 采用开源杀毒引擎，病毒库持续更新

• 🎨 现代界面 - 简洁专业的用户界面

• 🙏 赛博佛祖 - 启动画面自带佛祖保佑，永无BUG

🚀 快速开始

下载使用（推荐）

1. 前往 https://github.com/baguette168/BaguetteAV/releases 页面
2. 下载最新版本的 BaguetteAV-v1.0.0-Full.zip
3. 解压到任意目录
4. 双击运行 BaguetteAV.exe

⚠️ 注意: 完整包已包含病毒库，解压即可使用！

文件说明

BaguetteAV/
├── BaguetteAV.exe       # 主程序
├── libclamav.dll        # ClamAV 动态库
├── database/            # 病毒库目录
│   ├── main.cvd         # 主病毒库
│   ├── daily.cvd        # 每日更新库
│   └── bytecode.cvd     # 字节码库
└── certs/               # 证书目录

🖥️ 使用说明

主界面

按钮 功能说明

全盘扫描 扫描 C:\Users 目录下的所有文件

自定义扫描 选择指定文件夹进行扫描

Rootkit检测 检测系统中的 Rootkit 威胁

停止 停止当前扫描任务

Rootkit 检测项目

• 隐藏进程检测 - 比较不同 API 获取的进程列表

• 可疑服务检测 - 检查服务路径是否异常

• 启动项检测 - 检查注册表启动项

• Hosts 文件检测 - 检查是否被劫持

• 可疑驱动检测 - 检查驱动名称是否可疑

🔧 自行编译

环境要求

• Windows 10/11

• Visual Studio 2022（含 MFC 组件）

编译步骤

1. 克隆仓库
   git clone https://github.com/baguette168/BaguetteAV.git
   cd BaguetteAV

2. 下载病毒库

从 https://github.com/baguette168/BaguetteAV/releases 下载 database.zip，解压到 BaguetteAV/database/ 目录

3. 打开项目

使用 Visual Studio 2022 打开 BaguetteAV.slnx

4. 配置平台

选择 Debug 或 Release，平台选择 x64

5. 编译运行

按 F5 或点击"本地 Windows 调试器"

💡 生成后事件会自动复制 DLL、证书到输出目录

📁 项目结构

BaguetteAV/
├── .gitignore
├── README.md
├── LICENSE
├── BaguetteAV.slnx          # VS 解决方案
└── BaguetteAV/
    ├── 3rdparty/clamav/
    │   ├── include/         # ClamAV 头文件
    │   ├── lib/             # ClamAV 静态库
    │   └── dll/             # ClamAV 动态库
    ├── certs/               # 证书文件
    ├── database/            # 病毒库（需下载）
    ├── res/                 # 资源文件
    ├── BaguetteAV.cpp       # 程序入口
    ├── BaguetteAVDlg.*      # 主界面
    ├── SplashDlg.*          # 启动画面
    ├── ClamAVWrapper.*      # ClamAV 封装
    ├── ScanManager.*        # 扫描管理
    └── RootkitDetector.*    # Rootkit 检测

📸 截图

启动画面

                  o8888888o
                  88" .   "88
                  (| -_- |)
                  O\  =  /O
               ____/`---'\____
             .'  \\|     |//  `.
            /  \\|||  :  |||//  \
           /  _||||| -:- |||||_  \
           |   | \\\  -  /// |   |
           | \_|  ''\---/''  |_/ |
           \  .-\__  `-`  __/-.    /
         ___`. .'  /--. --\  `. .'___
      ."" '<  `.___\_<|>_/___.'  >' "".
     | | :   `- \`.;`\ _ /`;.`/ -` : | |
     \  \ `-.   \_ __\ /__ _/   .-` /  /

=====`-. ____`-.___\_____/___.-`____.-'=====
                  `=---='

                BaguetteAV

🙏 致谢

本项目的实现离不开以下开源项目的支持：

ClamAV

<img src="https://www.clamav.net/assets/clamav-trademark.png" width="200">

https://www.clamav.net/ 是一个开源的跨平台杀毒引擎，由 Cisco Talos 团队维护。

• 🌐 官网：https://www.clamav.net/

• 📦 GitHub：https://github.com/Cisco-Talos/clamav

• 📄 许可证：GPL v2

ClamAV 提供了强大的病毒检测能力，包括：
• 命令行扫描工具

• 可嵌入的 libclamav 库

• 自动更新的病毒库

• 支持多种文件格式

特别感谢 ClamAV 团队为开源安全社区做出的贡献！

其他致谢

• Microsoft - Visual Studio 和 MFC 框架

• 赛博佛祖 - 保佑程序永无BUG 🙏

📄 开源协议

本项目采用 LICENSE 开源协议。

⭐ 支持项目

如果这个项目对你有帮助，请给一个 Star ⭐ 支持一下！

<div align="center">

Made with ❤️ by baguette168

</div>