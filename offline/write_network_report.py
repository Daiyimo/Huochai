"""Write the runtime report from completed local capture evidence."""
import collections
import datetime as dt
import hashlib
import json
from pathlib import Path

from summarize_network_capture import events

ROOT=Path(__file__).resolve().parent.parent
CAPTURE=ROOT/'reverse'/'network_capture_target_20260831'


def read(name):
    return json.loads((CAPTURE/name).read_text(encoding='utf-8-sig'))


def local(value):
    return dt.datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(dt.timezone(dt.timedelta(hours=8))).strftime('%H:%M:%S')


def main():
    idle=read('idle-run.json');summary=read('network-summary.json');export=read('event-export-summary.json')
    probes=read('guard-probes.json');control=read('positive-control.json')
    files=read('tested-files.json');package=Path(files[0]['file'])
    assert idle['valid'] and idle['application_idle_seconds']>=600
    assert hashlib.sha256(package.read_bytes()).hexdigest()==files[0]['sha256']
    assert summary['positive_control_packets']>0
    groups=sum(line.startswith('PASS ') for line in probes['output'].splitlines())
    probe_counts=collections.Counter()
    for item in events(CAPTURE/'probe-events.xml'):
        if not item['provider'].endswith(('Kernel-Network','DNS-Client')):
            continue
        owner=item.get('owner_pid',item['header_pid'])
        if owner==probes['pid']:
            probe_counts[item['provider']]+=1
    result={'tested_package':str(package),'sha256':files[0]['sha256'],
            'application_idle_seconds':idle['application_idle_seconds'],
            'target_network_events':summary['target_kernel_network_events'],
            'target_dns_query_events':summary['target_dns_query_events'],
            'target_connect_events':summary['target_connect_events'],
            'target_send_events':summary['target_send_events'],
            'deny_probe_groups_passed':groups if probes['returncode']==0 else 0,
            'deny_probe_kernel_dns_events':dict(probe_counts),
            'positive_control_packets':summary['positive_control_packets'],
            'gui_scenarios':'not_verified: Windows input denied with GetCursorPos 0x80070005',
            'all_scenarios_complete':False,'firewall_changed_by_test':False,
            'full_network_isolation_proven':False,'capture_directory':str(CAPTURE)}
    (CAPTURE/'results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    clean=not(summary['target_kernel_network_events'] or summary['target_dns_query_events'])
    conclusion='在已完成的场景中，未发现可归属到火柴及其相关进程的 TCP/UDP 网络事件或 DNS 查询。' if clean else '发现了可归属网络事件，需根据 network-summary.json 继续定位。'
    report=f'''# 指定单文件版运行抓包验证（2026-08-31）

{conclusion} **搜索、设置等实际界面场景尚未完成，因此不能写成“全部场景通过”或“绝对不会联网”。**

## 测试对象与范围

- 仅测试用户指定的 `{package}`，大小 `{files[0]['bytes']:,}` 字节。
- SHA-256：`{files[0]['sha256']}`。测试前后相同，未重新编译或替换 EXE。
- 从该包释放的 `HuoChat.exe`、`hc_engine.exe`、启动器、`hcn.dll`、`hcg.dll` 均记录了哈希；两个搜索引擎进程（包括 Everything 服务）和应用启动的辅助进程都纳入归属分析。
- 前一轮目录重定向失败的测试已作废。用户清理目录后，本轮按“D 盘目录仅有指定 EXE”的状态重新开始，未将失败时段计入 10 分钟。

## 场景结果

| 场景 | 实际执行 | 结果 |
|---|---|---|
| 新目录解包及首次初始化 | 从 {local(idle['start_utc'])} 启动指定 EXE，确认主程序与引擎运行 | 在已完成的整个采集中，目标 TCP/UDP 事件 {summary['target_kernel_network_events']}，DNS 查询事件 {summary['target_dns_query_events']} |
| 成功启动后持续运行 10 分钟 | {local(idle['application_started_utc'])}—{local(idle['end_utc'])}，连续 {idle['application_idle_seconds']:.3f} 秒，不操作程序界面 | 主程序持续运行；连接快照为空；原始网络事件结果同上 |
| 完全退出后重新启动 | 14:32:10 退出本次进程及对应服务，14:32:14 重启同一 EXE，观察至至少 14:35:28 | 主程序、启动器、两个引擎均重新运行；纳入同一网络事件分析 |
| 网络拒绝接口扩展测试 | 独立测试进程加载 D 盘实际 `hcn.dll` / `hcg.dll` | {groups} 组通过，测试进程退出码 {probes['returncode']}；不是实际 UI 操作 |
| 抓包正向对照 | 独立进程执行 IPv4/IPv6 回环 TCP/UDP、合成 `.invalid` DNS 查询及一次外部 TCP 握手 | 正向进程的事件被捕获，网卡抓包中匹配外部测试连接的数据包 {summary['positive_control_packets']} 个 |
| 双 Ctrl、搜索、输入网址、设置页面 | Windows 输入调用和刷新绑定后的重试均返回 `GetCursorPos: 0x80070005` | **未完成，不计为通过** |

拒绝接口测试覆盖：IPv4/IPv6 TCP/UDP 套接字、DNS、WinINet、WinHTTP、URL 下载、动态网络 DLL 路由、动态加载入口、外部与回环网址打开、mailto、`.url`、UNC/扩展 UNC、HTTP COM 入口和已移除的 Web 引擎。各调用使用有意义的测试目标并检查失败返回值；具体输出保存在 `guard-probes.json`。

## 数据与归属方法

- PktMon 保存每包前 **64 字节**并输出 PCAPNG；同时采集 Kernel-Network、DNS-Client、Winsock-AFD、Kernel-Process 事件。全部证据只保存在本机。
- 两段有效采集共包含其他软件在内的数据包 **{summary['captured_packets_all_processes']:,}** 个。不能把整机流量算成火柴流量。
- Kernel-Network 使用事件数据中的拥有者 PID；进程关系按 **启动序号、父进程启动序号和存活时间**关联，避免 PID 重用导致误报。此机器确实出现了进程编号复用。
- Winsock-AFD 的套接字创建记录使用显式 `ProcessId` 归属，目标套接字创建事件 **{export.get('TargetSocketCreateEvents','未统计')}** 条。异步完成通知可能执行在其他进程线程上，不能仅凭事件头的线程所属 PID 判断请求来源；最终不将这种通知当作火柴发起请求或拦截成功的证据，原始通知保留在 ETL 中。
- 有归属的目标连接事件：**{summary['target_connect_events']}**；发送事件：**{summary['target_send_events']}**；DNS 查询事件：**{summary['target_dns_query_events']}**。
- 两次停止抓包均报告无 ETW 事件丢失。PCAP 转换工具的网络丢包计数是网络栈观察结果，不等于采集丢事件，更不能当作软件的拦截次数。
- 2 秒一次的进程/端点快照只作补充，不用它排除短连接。Sysmon 在该时段没有任何网络事件（包括正向对照），因此未将 Sysmon 的“0”用作证明。

## 限制

1. 系统已有针对 `%LOCALAPPDATA%\\HuoChat\\HuoChat.exe` 的出站阻止规则，且此路径是指向 D 盘运行目录的联接。本次没有新增、关闭或修改防火墙规则，因此不能把实际无流量完全归功于软件补丁。
2. 当前应用确实加载了拒绝 DLL，也由系统组件带入了部分原网络 DLL；加载 DLL 本身不等于发送流量。独立探针证明列出的拒绝入口返回失败，但不证明所有间接调用路径都已覆盖。
3. 原应用的实际搜索、设置、热键和网址交互未完成；共享系统服务或已运行外部程序代为联网的所有间接关系也未被穷尽证明。采集仅覆盖本报告列出的时段和输入。
4. 原始 ETL/PCAPNG 可能包含本机其他应用的连接元数据，不应直接公开上传。

## 复查证据

证据目录：`{CAPTURE}`。

- `runtime1.etl` / `runtime1.pcapng`：首次启动和连续空闲阶段。
- `interaction1.etl` / `interaction1.pcapng`：后续观察及完全退出重启。
- `idle-run.json`、`endpoint-snapshots.jsonl`、`scenarios.jsonl`：时间、进程与场景记录。
- `target-process-lifetimes.json`、`target-events.xml`、`network-summary.json`、`results.json`：最终归属与统计。
- `tested-files.json`、`guard-probes.json`、`positive-control.json`、`probe-events.xml`：文件身份及正负对照。
- `firewall-existing.json`、`loaded-network-modules.json`：环境影响因素。

采集与解释参考：[Microsoft PktMon start](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-start)、[Microsoft Winsock tracing events](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-tracing-event-details)、[Microsoft TCP/IP ETW events](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip)。
'''
    destination=ROOT/'offline'/'NETWORK_RUNTIME_REPORT_20260831.md'
    destination.write_text(report,encoding='utf-8')
    verification=ROOT/'offline'/'verification.json'
    data=json.loads(verification.read_text(encoding='utf-8'))
    data['runtime_network_checks']=dict(result,report=str(destination))
    verification.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
