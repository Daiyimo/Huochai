# 火柴 (Huochai)

火柴（原火萤酱）是我用了很久的一款软件。作者停更后，部分功能年久失修，因此开源此项目，继承火柴的极简精神，并更新 Everything SDK 内核，使其继续可用。

核心用途：**双击 Ctrl 键弹窗，用 Everything 可视化搜索本地文件**，快捷且完全本地化，无数据安全顾虑。

## 与同类工具对比

| 工具   | 特点                     |
|--------|--------------------------|
| 火柴   | 极简、纯本地、无多余功能 |
| uTools | 功能多但臃肿，内置浏览器 |
| SOFAST | 较卡顿，同样功能过剩     |

## 截图

### 升级后的 Everything 界面

<img width="780" height="657" alt="升级后的界面" src="https://github.com/user-attachments/assets/d4cd22eb-f9ce-420b-9424-357e16c2278f" />

### 原版界面

<img width="780" height="657" alt="原版界面" src="https://github.com/user-attachments/assets/32f0d9c0-704e-4b0f-8092-9e8b1f48d3c4" />

### Ctrl 双击搜索框

<img width="900" height="622" alt="搜索框" src="https://github.com/user-attachments/assets/0af2efdc-f956-4fa3-b617-271376ee9825" />

### 设置（全关，仅当 Everything 可视化使用）

<img width="1260" height="800" alt="设置" src="https://github.com/user-attachments/assets/f6675b83-50a2-4b7f-8b2c-05289775fc6a" />

## 手动升级 Everything SDK

1. 从 [voidtools](https://www.voidtools.com/) 下载 Everything 最新版 SDK
2. SDK 解压后，在 `dll` 文件夹中找到 `Everything32.dll`
3. 下载与 SDK 同版本的 Everything x86 安装版，安装后获得 `.exe` 启动文件
4. 打开火柴安装目录，将第 2 步的 `Everything32.dll` 复制进去替换原文件
5. 将第 3 步的 `.exe` 复制到安装目录，重命名为 `hc_engine.exe` 替换原文件

> 本项目附件中已包含所需的替换文件，直接覆盖即可。

## 许可证

完全本地化，无服务器依赖，无数据隐私顾虑。
