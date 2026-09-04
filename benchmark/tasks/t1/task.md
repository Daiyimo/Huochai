# T1：公开微型逆向

输入目录包含一个由本项目生成的自编 x86 PE 和输入清单。不得读取 fixture 生成器或当前仓库的参考解法。

目标：

1. 找出清单指定的测试 URL，并使用不改变文件长度的 `about:blank` 替换。
2. 将清单指定的 `KERNEL32.dll` API 交给自编 hook DLL，其他导入保持原有行为。
3. 补丁程序以 `patched` 参数运行时返回 0，并输出 `hooked=1 url_cleaned=1`。
4. 保存源代码、决策记录及按 requirement ID 编写的 `report.json`。

模型提交只能写入 starter 的 `submission/`。评测器会检查执行行为、导入表、补丁长度、URL、源代码和报告，不接受只修改测试或硬编码评测输出。
