# 第三方组件与许可

核对日期：2026-09-03。此说明区分各组件的许可范围，不对整个原软件作统一授权判断。

| 组件 | 已核对的条款与处理 |
| --- | --- |
| Everything 引擎 | 官方下载页指向的许可允许使用、修改和再分发，但要求在副本或重要部分中保留版权与许可声明。该文本还包含 PCRE 的再分发条件、免责声明和不得借贡献者名义背书的要求。 |
| Everything SDK | 官方 SDK 的 `include/Everything.h` 与 `src/Everything.c` 含独立许可段落，允许修改和再分发，并要求保留相应声明。SDK 是 IPC 接口，不是引擎源码。 |
| DuiLib | 保留历史样本附带的完整许可及署名，按其独立条款处理。 |
| 火柴主体、Microsoft 运行库等 | 不由 Everything 的许可覆盖；须分别依据对应版本的授权和条款。本项目不提供这些二进制。 |

官方依据：[Everything 下载页](https://www.voidtools.com/downloads/)、[Everything 许可](https://www.voidtools.com/License.txt)、[SDK 说明与下载](https://www.voidtools.com/support/everything/sdk/)。Everything 1.5 仍是 beta；公开允许再分发不等于整合后的应用已取得全部权利。

## 保留的声明

- [Everything 许可](licenses/Everything-LICENSE.txt)：官方许可页的文本副本。
- [SDK 许可](licenses/Everything-SDK-LICENSE.txt)：从官方 SDK 两个文件提取的许可段落，去除 C 注释标记，保留版权和完整条款。
- [历史 Everything 许可](licenses/Everything-legacy-LICENSE.txt) 与 [DuiLib 许可](licenses/DuiLib-LICENSE.txt)：历史样本附带的声明，用于复核旧集成实验。

本地集成构建逐字节复制并校验这些文本，不清洗其中的链接、署名或条件。引擎文件保持官方字节和签名；SDK 的路由改动由项目适配层完成，其许可继续独立有效。

独立教学 demo 不使用上述第三方应用二进制。若后续更换依赖版本或进行任何分发，应以实际取得版本所附条款重新核对；“技术验证”、加密或提取码本身不会赋予修改与分发权限。
