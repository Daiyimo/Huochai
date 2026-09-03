# 本地构建与验证

## 独立教学 demo

需要 Windows 10/11、Python 3、Visual Studio C++ Build Tools 与 Windows SDK。Python 依赖为 `pefile`、`Pillow`、`pycryptodome`、`psutil`。

```powershell
python -m pip install pefile Pillow pycryptodome psutil
python reverse/demo.py
python -m unittest discover -s reverse -p "test_*.py" -v
```

`demo.py` 编译自编的 `demo_fixture.c` 和 `demo_hook.c`，生成原始 PE，再执行定长 URL 清洗和导入表重定向。它实际运行补丁前后的样例，并验证目标 API 已被接管。

输出位于 `.local/demo/`：原始样例、补丁样例、hook DLL 和 `verification.json`。没有原软件输入也能完成这条流程；无需安装 Everything 服务或索引磁盘。可用 `--output-dir` 指定仓库外的本地目录。

## 历史集成实验

`build.py` 保留对固定历史样本的集成验证流程，需要 7-Zip、NSIS、微软雅黑字体，以及自行准备的以下输入。它不从 Git 历史或网络提取程序，也不能从任意一份官方安装器直接生成所需历史基线。

| `.local/inputs/` 下的文件 | SHA-256 |
| --- | --- |
| `base/火柴单文件版.exe` | `452541a3327935ac452504ff0355bbea801090837f626f1a82c5245e3f89ef1a` |
| `base/火柴绿色版.exe` | `0b32b5f393806f0c154b2b7f2ff2c93459848e85832c4584d7b3099d25e80e8b` |
| `vendor/Everything-1.5.0.1423b.x64.exe` | `81b4d05e84e61891ac043dd76e97de616af17adf53b2ee2fe984d8b0bbbfcc21` |
| `vendor/Everything32.upstream.dll` | `1ffe69d856a8a071a7531d54d7b05ae04a87814b812e649521a67a606c7f93e0` |

前两项是特定历史实验输入，本项目不再提供其下载。没有合适输入时，请使用上面的独立 demo。Everything 输入的官方来源见 [依赖说明](../reverse/vendor/README.md)。输入哈希只用于识别版本，不证明具有授权。

```powershell
# 使用默认私有输入目录，全部验证通过后保存本地 demo
python reverse/build.py

# 自备输入目录，保留中间验证材料
python reverse/build.py --inputs-dir <私有输入目录> --keep-workdir

# 静态检查已解包的本地样本，不启动它
python reverse/build.py --verify <样本目录>
```

集成产物写入 `.local/integration-demo/`，不会替换项目根目录程序或上传 Releases。缺失或哈希不匹配的输入会被拒绝。原生回归包含 SDK、实际查询代码、缓存、退出和打包修复；完整桌面交互需要另行验证。

第三方许可文件按完整文本复制、校验，不经过 URL 清洗。原始验证报告可能包含本机路径，只能保存在仓库外或 `.local/` 中；对外分享时仅提取脱敏结论。
