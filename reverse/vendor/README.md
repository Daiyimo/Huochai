# 独立取得的上游输入

此目录只保存来源说明，不存放 EXE 或 DLL。历史集成实验从私有目录 `.local/inputs/vendor/` 读取以下文件，并校验固定哈希。

| 本地文件 | 官方来源 | SHA-256 |
| --- | --- | --- |
| `Everything-1.5.0.1423b.x64.exe` | [官方便携 ZIP](https://www.voidtools.com/Everything-1.5.0.1423b.x64.zip) 内的 Everything.exe | `81b4d05e84e61891ac043dd76e97de616af17adf53b2ee2fe984d8b0bbbfcc21` |
| `Everything32.upstream.dll` | [官方 SDK](https://www.voidtools.com/Everything-SDK.zip) 内的 dll/Everything32.dll | `1ffe69d856a8a071a7531d54d7b05ae04a87814b812e649521a67a606c7f93e0` |

引擎保留原始字节与签名；SDK 在本地集成实验中适配实例路由。下载包若与固定哈希不同，不应关闭校验或假定兼容。

许可来源与条款见 [第三方许可说明](../../third_party/README.md)。独立教学 demo 不需要这些输入。
