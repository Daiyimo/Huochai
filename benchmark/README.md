# 火柴模型能力 Benchmark

本目录把逆向案例拆成可重复执行的三层赛题。源码仓库只保存任务、生成器、评测协议和公开冒烟测试；原始程序、依赖、模型产物及隐藏测试保存在仓库外或 `.local/`。

## 赛题

| 轨道 | 起点 | 主要能力 | 当前状态 |
| --- | --- | --- | --- |
| T1 `micro` | 随机生成的自编 PE | PE 分析、定长清洗、导入重定向、API hook | 可公开执行 |
| T2 `integration` | 四个固定哈希私有输入 | 资源清理、IPC、缓存、生命周期、单文件打包 | 可用现有私有输入执行 |
| T3 `e2e` | 原始安装包及固定第三方依赖 | 解包、盘点、方案设计、逆向、重组和验证 | 已建立规范化入口，解法仍待参赛模型完成 |

T3 是目标赛题。T2 仍从已加工的单文件版和绿色版起步，因此不能代替 T3。

## 快速开始

所有命令都应将输出写入 `.local/` 或仓库外目录。

```powershell
# 生成公开微型赛题；starter 不包含 fixture 源码或参考解法
python benchmark/tools/prepare_starter.py --track t1 --seed 101 `
  --output .local/benchmark/t1-101

# 生成固定合成检索语料
python benchmark/tools/generate_corpus.py `
  --output .local/benchmark/corpus-101 --seed 101 --file-count 1000

# 归一化原始安装包，只解包并生成逐文件清单，不执行程序
python benchmark/tools/normalize_input.py `
  --input <原始安装包> --expected-sha256 <SHA-256> `
  --output .local/benchmark/normalized-original

# 检查提交契约
python benchmark/tools/validate_submission.py `
  --task benchmark/tasks/t1/task.json `
  --submission .local/benchmark/t1-101/submission

# 模型运行前后都校验 starter，检测输入篡改和答案材料泄漏
python benchmark/tools/validate_starter.py `
  --starter .local/benchmark/t1-101

# 按硬门槛和量表汇总审核结果
python benchmark/tools/score_run.py `
  --assessment <assessment.json> --output <score.json>

# 汇总同一模型的三次独立得分或比较多个模型
python benchmark/tools/compare_runs.py <score-1.json> <score-2.json> <score-3.json> `
  --output <comparison.json>
```

T2/T3 starter 需要 `--inputs-dir`。输入目录的相对路径和哈希见各任务的 `input-manifest.json`。生成器验证全部输入后才创建 starter，并在副本中写入 `.input-lock.json`。

## 公平性约束

- Starter 不包含 `.git`、当前 `reverse/` 解法或隐藏评测器。
- 所有模型使用同一系统快照、工具版本、网络策略、时间和推理设置。
- 隐藏测试位于模型无法修改的位置，模型结束后再注入。
- 输入和提交在评测前后都重新计算哈希，模型自己的“通过”声明不作为证据。
- 每个模型至少独立运行三次，同时报告质量分、`pass@1`、`pass@3`、时间、token、费用、工具调用和人工介入。

## 评测材料

- [参考环境](environment.lock.json)
- [100 分量表与硬门槛](rubric.json)
- [任务格式](task.schema.json)
- [提交报告格式](submission.schema.json)
- [审核结果格式](assessment.schema.json)
- [本机参考验证结果](reference-results.json)
- [T1](tasks/t1/task.md) · [T2](tasks/t2/task.md) · [T3](tasks/t3/task.md)

`environment.lock.json` 记录当前已验证的参考环境，并不等同于完整虚拟机镜像。正式对比应保存 VM 快照或镜像摘要。
