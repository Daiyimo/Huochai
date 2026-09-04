# 火柴逆向工程案例分析

以 Windows 桌面程序为背景，记录 PE 补丁、API hook、URL 与资源清洗、IPC 适配的实现和验证。项目以技术解析与实验源码为主体，可执行文件仅作为本地验证 demo 的构建产物。

## 技术内容

| 主题 | 解析重点 | 源码入口 |
| --- | --- | --- |
| PE 补丁 | 校验输入、定位导入表、保持字节布局和重定位正确 | [build.py](reverse/build.py)、[data_layout.py](reverse/data_layout.py) |
| API hook | 导入表重定向、导出转发、x86 调用约定 | [guard.c](reverse/guard.c)、[sdk_bridge.c](reverse/sdk_bridge.c) |
| URL 清洗 | ASCII、UTF-16、Base64、业务域名样本及误报边界 | [policy.py](reverse/policy.py)、[test_policy.py](reverse/test_policy.py) |
| 验证方法 | 执行真实调用路径，检查缓存、实例隔离与退出行为 | [test_ui_query.c](reverse/test_ui_query.c)、[backend_checks.py](reverse/backend_checks.py) |

`BARE_DENYLIST` 保留为静态分析与回归样例。域名命中本身不代表恶意行为；版权、许可和署名文本单独保留，不参与清洗。详见 [技术解析](docs/case-study.md)。

## 自行构建 demo

```powershell
python reverse/demo.py
```

该 demo 从仓库中的自编 C 样例生成 PE，验证导入表重定向、API hook 和定长 URL 清洗，无需火柴或 Everything 二进制。工具依赖和步骤见 [构建说明](docs/build.md)。

需要比较多个模型时，使用 [Benchmark 协议](benchmark/README.md) 生成不含答案的 T1/T2/T3 starter，并以固定硬门槛、100 分量表和独立运行指标评测。

产物只写入被 Git 忽略的 `.local/demo/`，仅供技术验证。本仓库不提供安装包、修改版 EXE 或加密下载；GitHub Releases 也不作为二进制分发渠道。

## 第三方组件

Everything 和 SDK 具有独立许可，允许再分发的同时要求保留版权和许可声明；这些条款不构成对火柴主体或其他组件的授权。来源、条款和保留方式见 [第三方许可说明](third_party/README.md)。

旧集成实验需要自行准备具有相应使用、分析权限且哈希匹配的输入，并非完整原软件源码构建。研究用途、加密或提取码不会自动取得修改与分发权限。
