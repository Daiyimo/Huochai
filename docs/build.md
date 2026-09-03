# 构建

本项目使用 Windows 10/11、Python 3、Git、Visual Studio C++ Build Tools、Windows SDK、7-Zip 和 NSIS。Python 依赖为 `pefile`、`Pillow`、`pycryptodome`、`psutil`；引导图使用 Windows 微软雅黑字体。

构建器从固定 Git 提交 `39cf149bf9d7030a8f002b4198a9087f985c6b7a` 读取基础二进制，因此需要保留该提交及构建所需历史。1.5 引擎和 SDK 输入固定在 `reverse/vendor`，无需在线下载。

```powershell
# Python 测试
python -m unittest discover -s reverse -p "test_*.py" -v

# 构建并验证候选包，不替换根目录 EXE
python reverse/build.py

# 保留临时构建目录和验证报告
python reverse/build.py --keep-workdir

# 验证通过后更新根目录 EXE
python reverse/build.py --publish
```

构建包含静态、原生接口、实际查询链路、缓存、退出及打包修复验证。完整桌面交互仍需在目标环境验证。发布时同步版本记录中的产物大小和 SHA-256。

原始诊断报告可能包含本机路径或文件信息，应保存在仓库外或被忽略的 `.local/` 中。提交前仅提取脱敏的结论，不提交配置、索引、日志、个人文件名或个人数据哈希。
