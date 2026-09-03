# 固定的上游构建输入

这些文件用于离线、可复现构建，由 `reverse/backend_build.py` 校验 SHA-256。不要在此目录保存运行时配置或数据库。

| 文件 | 来源 | SHA-256 |
| --- | --- | --- |
| Everything-1.5.0.1423b.x64.exe | [官方便携 ZIP](https://www.voidtools.com/Everything-1.5.0.1423b.x64.zip) 内的 Everything.exe | `81b4d05e84e61891ac043dd76e97de616af17adf53b2ee2fe984d8b0bbbfcc21` |
| Everything32.upstream.dll | [官方 SDK](https://www.voidtools.com/Everything-SDK.zip) 内的 dll/Everything32.dll，2026-09-03 获取 | `1ffe69d856a8a071a7531d54d7b05ae04a87814b812e649521a67a606c7f93e0` |

引擎按原样分发，Windows 验证签名为 voidtools PTY LTD。SDK 在构建时改接本地拒绝层及实例路由桥接；引擎不会应用二进制补丁。最终包继续携带 `everything license.txt`，上游许可及署名保持有效。
