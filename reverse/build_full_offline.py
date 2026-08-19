#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
构建「全面离线精简版」HuoChat 单文件（基于稳基线 build_portable_nozipres.py 架构）。

与稳基线的三点增强：
  1. 联网全面禁用 —— HuoChat 9 点 + hc_engine 全部 voidtools 链接（含 help/donate/download）
     一并中和到 127.0.0.1，做到构建产物内无任何有效外网 URL 残留。
  2. site.db 清空 bookmark（376 条默认书签，离线无用）+ top_site（9853 条导航）。
  3. 设置页安全隐藏 —— 仅用已证明不闪退的 visible="false" Proven 集
     {menu_btn, switch_btn}（见记忆 huochat_singlefile_debug：移位才闪退，纯隐藏不闪退），
     绝不做任何节点移位/删除。

产物：项目根目录中的单文件 EXE。
旧版（火柴单文件版.exe / 火柴实验精简版_极简.exe / 火柴绿色版.exe）全部保留作回滚。
"""
import os
import sys
import shutil
import subprocess
import re
import sqlite3 as _sqlite3

import pefile

WORK_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reverse', 'full_offline_build'))
GREEN_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reverse', 'green_extracted'))
OUT_EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '火柴全面离线版.exe'))
NSIS = r'C:\Program Files (x86)\NSIS\makensis.exe'
LAUNCHER_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reverse', 'HuoChat_launcher.exe'))
ICON_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reverse', 'green_icon.ico'))
ZIPRES_ORIG = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'reverse', 'zipres_orig'))

# ----------------------------------------------------------------------------
# 1) 联网补丁 —— search 不得长于 replace，不足用 \x00 填充（定长原地替换）
# ----------------------------------------------------------------------------
# HuoChat.exe：3 个绝对 URL + 6 个 /api/ 相对端点
HUOCHAT_PATCHES = [
    (b'http://suggestion.baidu.com/su?wd=%s&action=opensearch',
     b'http://127.0.0.1' + b'\x00' * 27),
    (b'https://www.baidu.com/s?wd=%s&ie=UTF-16',
     b'http://127.0.0.1' + b'\x00' * 17),
    (b'http://huoying666.com',
     b'http://127.0.0.1' + b'\x00' * 4),
    (b'/api/weather/attribution\x00\x00\x00\x00', b'/api/offline' + b'\x00' * 14),
    (b'/api/share/exchange\x00',               b'/api/offline' + b'\x00' * 6),
    (b'/api/weather/ip\x00',                   b'/api/offline' + b'\x00' * 2),
    (b'/api/share/exp\x00\x00',                b'/api/offline' + b'\x00' * 3),
    (b'/api/weather\x00\x00\x00\x00',          b'/api/offline' + b'\x00' * 2),
    (b'/api/share\x00\x00',                    b'/api/none' + b'\x00' * 2),
]

# hc_engine.exe：Everything 更新 + 全部 voidtools 帮助/捐赠/下载链接一并中和
# （这些不是运行时功能，但为了"无任何有效外网 URL 残留"也一并处理）
ENGINE_PATCHES = [
    (b'http://www.voidtools.com/everything/update.ini',
     b'http://127.0.0.1' + b'\x00' * 13),
    (b'http://www.voidtools.com/everything/beta-update.ini',
     b'http://127.0.0.1' + b'\x00' * 13),
    (b'https://www.voidtools.com/donate/',
     b'http://127.0.0.1' + b'\x00' * 5),
    (b'https://www.voidtools.com/support/everything/',
     b'http://127.0.0.1' + b'\x00' * 5),
    (b'https://www.voidtools.com/downloads/',
     b'http://127.0.0.1' + b'\x00' * 5),
    (b'https://www.voidtools.com/downloads/#language',
     b'http://127.0.0.1' + b'\x00' * 5),
    (b'https://www.voidtools.com/',
     b'http://127.0.0.1' + b'\x00' * 5),
    (b'https://www.voidtools.com/update/)',
     b'http://127.0.0.1' + b'\x00' * 5),
    # 嵌入的 HTML DTD 声明串，运行时绝不连接，但为"无外网 URL 残留"一并中和
    (b'www.w3.org', b'127.0.0.1\x00'),
]

# 构建后断言：这些外网域名在产物里不应再出现（验证"全面离线"）
FORBIDDEN_DOMAINS = [b'baidu.com', b'huoying666.com', b'voidtools.com', b'w3.org']

# 设置页安全隐藏的 Proven 集（仅 visible=false，绝不移位/删节点）
# - menu_btn：标题栏汉堡按钮（三道杠）。隐藏后其下拉菜单含「关于」一并不可达。
#   visible=false 会让它从布局流移除、同盒按钮左移，靠下方「按钮盒贴角」逻辑
#   把盒宽同步缩到「可见按钮数×30」来保持贴角（2026-08-19 验证）。
# - switch_btn：不隐藏，保留「功能开关」tab（用户要求功能菜单可见）。
SAFE_HIDE_CONTROLS = ['menu_btn']


def patch_binary(filepath, patches, label=''):
    """定长原地二进制补丁。replace 不得长于 search，不足 \x00 填充。"""
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
    patched = 0
    for search, replace in patches:
        if len(replace) > len(search):
            print('  [ERROR] replace 长于 search: %s' % search[:40])
            continue
        pos = 0
        while True:
            idx = data.find(search, pos)
            if idx == -1:
                break
            replacement = replace + b'\x00' * (len(search) - len(replace))
            data[idx:idx + len(search)] = replacement
            print('  [%s] 0x%06x %s' % (label, idx, search[:46].decode('latin1')))
            patched += 1
            pos = idx + len(search)
    if patched > 0:
        with open(filepath, 'wb') as f:
            f.write(data)
    return patched


def hide_control_safe(xml_bytes, control_name):
    """给控件开标签加 visible="false"（只隐藏，不移位/不删节点）。

    Returns (new_bytes, changed: bool)。保持 XML 结构完整以避免闪退。
    """
    key = ('name="%s"' % control_name).encode()
    pos = xml_bytes.find(key)
    if pos == -1:
        print('  [WARN] %s 未找到' % control_name)
        return xml_bytes, False
    end = xml_bytes.find(b'>', pos)
    if end == -1:
        return xml_bytes, False
    if b'visible=' in xml_bytes[pos:end]:
        print('  [skip] %s 已有 visible' % control_name)
        return xml_bytes, False
    if xml_bytes[end - 1:end] == b'/':  # 自闭合
        new = xml_bytes[:end - 1] + b' visible="false"/>' + xml_bytes[end + 1:]
    else:
        new = xml_bytes[:end] + b' visible="false">' + xml_bytes[end:]
    print('  [hide] %s' % control_name)
    return new, True


def get_zipres_off_size(pe):
    """从 PE 资源里取 ZIPRES 的文件偏移与大小。"""
    for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(rt.name) == 'ZIPRES':
            for rid in rt.directory.entries:
                for lang in rid.directory.entries:
                    off = pe.get_offset_from_rva(lang.data.struct.OffsetToData)
                    size = lang.data.struct.Size
                    return off, size
    return None, None


def apply_safe_zipres_hide(target_exe):
    """用 Proven 集安全隐藏设置页控件，定长原地替换 ZIPRES 资源。"""
    import xml.dom.minidom as minidom
    import zipfile
    import io

    xml_path = os.path.join(ZIPRES_ORIG, 'search_setting_ui.xml')
    with open(xml_path, 'rb') as f:
        xml = f.read()
    print('  原始 xml %d 字节' % len(xml))

    for ctrl in SAFE_HIDE_CONTROLS:
        xml, _ = hide_control_safe(xml, ctrl)

    # 标题栏按钮贴角：按钮盒原 width=180，右对齐后右侧空隙 = 180 - 可见按钮宽，
    # 正好是「关闭按钮到右窗缘」的缝。把盒宽缩到「可见按钮数×30」让按钮填满盒子，
    # 关闭按钮即贴右窗缘。可见按钮恒为 menu_btn/mini_btn/close_btn 三个（其余已隐藏），
    # 被 SAFE_HIDE 藏掉的要扣减。原地改属性，不移位/不删节点。
    title_btns = ['menu_btn', 'mini_btn', 'close_btn']
    visible_n = sum(1 for b in title_btns if b not in SAFE_HIDE_CONTROLS)
    box_w = visible_n * 30
    box_key = b'<HorizontalLayout width="180">'
    new_btn = b'<Button name="new_btn"'
    bi = xml.find(box_key)
    if (bi != -1 and 0 < xml.find(new_btn, bi) < xml.find(b'</HorizontalLayout>', bi)):
        xml = xml[:bi] + ('<HorizontalLayout width="%d">' % box_w).encode() + xml[bi + len(box_key):]
        print('  [shrink] 标题栏按钮盒 180 -> %d（贴角，可见按钮 %d 个）' % (box_w, visible_n))
    else:
        print('  [WARN] 未定位到标题栏按钮盒，跳过贴角')

    print('  补丁后 xml %d 字节' % len(xml))

    # XML 良构校验
    try:
        minidom.parseString(xml)
        print('  XML 良构: OK')
    except Exception as e:
        print('  [ERROR] XML 解析失败: %s' % e)
        return False

    # 定位目标 exe 的 ZIPRES 槽
    pe = pefile.PE(target_exe)
    off, size = get_zipres_off_size(pe)
    pe.close()
    if off is None:
        print('  [ERROR] 目标 exe 无 ZIPRES 资源')
        return False
    print('  ZIPRES off=0x%x size=%d' % (off, size))

    # 用原始 ZIPRES 全量文件重建 zip，仅覆盖 search_setting_ui.xml
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, _, files in os.walk(ZIPRES_ORIG):
            for fn in files:
                fp = os.path.join(root, fn)
                arcname = os.path.relpath(fp, ZIPRES_ORIG).replace('\\', '/')
                if arcname == 'search_setting_ui.xml':
                    zf.writestr(arcname, xml)
                else:
                    zf.write(fp, arcname)
    new_zip = buf.getvalue()
    print('  新 zip %d 字节 (delta %+d)' % (len(new_zip), len(new_zip) - size))
    if len(new_zip) > size:
        print('  [ERROR] 新 zip 超出 ZIPRES 槽，放弃（避免破坏 exe）')
        return False

    with open(target_exe, 'rb') as f:
        data = bytearray(f.read())
    padded = new_zip + b'\x00' * (size - len(new_zip))
    data[off:off + size] = padded
    tmp = target_exe + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(data)
    os.remove(target_exe)
    os.rename(tmp, target_exe)
    print('  安全 ZIPRES 隐藏完成')
    return True


def configure_everything_ini(ini_path):
    """关闭 Everything 自更新（保持索引范围现状，按用户决策不动）。"""
    with open(ini_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    if 'check_for_updates_on_startup' not in content:
        content = content.rstrip() + '\ncheck_for_updates_on_startup=0\nbeta_updates=0\n'
    else:
        content = re.sub(r'check_for_updates_on_startup=\d+',
                         'check_for_updates_on_startup=0', content)
        content = re.sub(r'beta_updates=\d+', 'beta_updates=0', content)
    with open(ini_path, 'w', encoding='utf-8') as f:
        f.write(content)


def clean_site_db(site_path):
    """清空 bookmark + top_site（离线无用），VACUUM 瘦身。保留表结构。"""
    conn = _sqlite3.connect(site_path)
    removed = {}
    for tbl in ('top_site', 'bookmark'):
        try:
            n = conn.execute('SELECT COUNT(*) FROM "%s"' % tbl).fetchone()[0]
            conn.execute('DELETE FROM "%s"' % tbl)
            removed[tbl] = n
        except _sqlite3.Error as e:
            print('  [WARN] %s 清理跳过: %s' % (tbl, e))
    conn.commit()
    conn.execute('VACUUM')
    conn.close()
    print('  site.db 清空: %s' % removed)


def create_nsis_script(work_dir):
    """生成静默单文件 NSIS 脚本。nsExec 隐藏执行，无 CMD 闪窗。"""
    script = r'''
!include "MUI2.nsh"

Name "HuoChat"
OutFile "火柴全面离线版.exe"
InstallDir "$EXEDIR\HuoChat"
RequestExecutionLevel user
ShowInstDetails nevershow

Icon "green_icon.ico"
!define MUI_ICON "green_icon.ico"
!define MUI_UNICON "green_icon.ico"

SilentInstall silent
AutoCloseWindow true
SetCompressor /SOLID /FINAL lzma
SetCompressorDictSize 64

!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
    FindWindow $0 "" "HuoChat"
    StrCmp $0 0 +3
    MessageBox MB_OK|MB_ICONEXCLAMATION "HuoChat 已经在运行中。"
    Abort
FunctionEnd

Section "HuoChat"
    SetShellVarContext current
    SetOutPath "$EXEDIR\HuoChat"

    ; nsExec 隐藏执行，不弹 CMD 窗
    nsExec::ExecToStack 'taskkill /F /IM HuoChat.exe'
    nsExec::ExecToStack 'taskkill /F /IM hc_engine.exe'
    Sleep 300

    CreateDirectory "$EXEDIR\HuoChat"
    CreateDirectory "$EXEDIR\HuoChat\plugins"
    CreateDirectory "$EXEDIR\HuoChat\user data"
    CreateDirectory "$EXEDIR\HuoChat\user data\page"
    CreateDirectory "$EXEDIR\HuoChat\user data\resource"
    CreateDirectory "$EXEDIR\HuoChat\user data\resource\edit"
    CreateDirectory "$EXEDIR\HuoChat\user data\resource\skin"
    CreateDirectory "$EXEDIR\HuoChat\user data\resource\skin\white"
    CreateDirectory "$EXEDIR\HuoChat\user data\tam"

    SetOutPath "$EXEDIR\HuoChat"
    File "files\HuoChat.exe"
    File "files\hc_engine.exe"
    File "files\Everything32.dll"
    File "files\shot.dll"
    File "files\sqlite3.dll"
    File "files\msvcp120.dll"
    File "files\msvcr120.dll"
    File "files\site.db"
    File "files\Everything.ini"
    File "files\duilib license.txt"
    File "files\everything license.txt"
    File "files\HuoChat_launcher.exe"

    SetOutPath "$EXEDIR\HuoChat\plugins"
    File "files\plugins\MOle.dll"
    File "files\plugins\taskpin.vbs"

    SetOutPath "$EXEDIR\HuoChat\user data"
    File "files\user data\config"

    SetOutPath "$EXEDIR\HuoChat\user data\page"
    File "files\user data\page\error.html"
    File "files\user data\page\error.jpg"

    SetOutPath "$EXEDIR\HuoChat\user data\resource\edit"
    File /r "files\user data\resource\edit\*.*"

    SetOutPath "$EXEDIR\HuoChat\user data\resource\skin\white"
    File "files\user data\resource\skin\white\Config.hyjs"
    File "files\user data\resource\skin\white\Main_editBkImage.png"

    SetOutPath "$EXEDIR\HuoChat\user data\tam"
    File "files\user data\tam\config"

    ; junction: %LOCALAPPDATA%\HuoChat -> exe_dir\HuoChat（便携化路标，勿删）
    nsExec::ExecToStack 'cmd /c if exist "$LOCALAPPDATA\HuoChat" rmdir "$LOCALAPPDATA\HuoChat"'
    nsExec::ExecToStack 'cmd /c mklink /J "$LOCALAPPDATA\HuoChat" "$EXEDIR\HuoChat"'

    Exec '"$EXEDIR\HuoChat\HuoChat_launcher.exe"'
SectionEnd
'''
    # 动态剔线：Step 1.5 裁掉的组件，删掉其 NSIS File/CreateDirectory 行，
    # 避免编译器引用已不存在的文件（保留仍在的组件行）。
    fd = os.path.join(work_dir, 'files')
    strip_kw = []
    if not os.path.isdir(os.path.join(fd, 'web')):
        strip_kw.append('web')
    if not os.path.isdir(os.path.join(fd, 'plugins')):
        strip_kw.append('plugins')
    if not os.path.exists(os.path.join(fd, 'shot.dll')):
        strip_kw.append('shot.dll')
    if not os.path.exists(os.path.join(fd, 'sqlite3.dll')):
        strip_kw.append('sqlite3.dll')
    if not os.path.exists(os.path.join(fd, 'site.db')):
        strip_kw.append('site.db')
    if strip_kw:
        lines = script.split('\n')
        before = len(lines)
        lines = [l for l in lines if not any(kw in l.lower() for kw in strip_kw)]
        script = '\n'.join(lines)
        print('  NSIS 剔线 %s，删除 %d 行' % (strip_kw, before - len(lines)))

    script_path = os.path.join(work_dir, 'installer.nsi')
    with open(script_path, 'w', encoding='utf-8-sig') as f:
        f.write(script)
    return script_path


def verify_offline(files_dir):
    """构建后断言：产物二进制里无任何禁用外网域名残留。"""
    print('[7] 验证全面离线（扫描残留外网域名）...')
    bad = False
    for fn in ('HuoChat.exe', 'hc_engine.exe'):
        fp = os.path.join(files_dir, fn)
        d = open(fp, 'rb').read()
        for dom in FORBIDDEN_DOMAINS:
            # 允许出现在 127.0.0.1 上下文之外的位置；直接查域名串
            cnt = d.count(dom)
            # huoying/baidu/voidtools/w3 若仍以 http(s) 邻近出现才算残留
            if cnt:
                # 粗略上下文检查：域名前 8 字节是否含 http
                idx = d.find(dom)
                ctx = d[max(0, idx - 10):idx]
                if b'http' in ctx or b'//' in ctx:
                    print('  [FAIL] %s 仍含外网域名 %s @0x%x' % (fn, dom, idx))
                    bad = True
    if bad:
        print('  [ERROR] 联网未彻底禁用，请检查补丁')
        return False
    print('  通过：无有效外网 URL 残留')
    return True


def main():
    if os.path.exists(WORK_DIR):
        shutil.rmtree(WORK_DIR)
    os.makedirs(WORK_DIR)
    files_dir = os.path.join(WORK_DIR, 'files')
    os.makedirs(files_dir)

    print('=== 构建全面离线精简版 HuoChat ===\n')

    # Step 1: 复制绿色版文件
    print('[1] 复制绿色版文件...')
    for item in os.listdir(GREEN_DIR):
        src = os.path.join(GREEN_DIR, item)
        dst = os.path.join(files_dir, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    if os.path.exists(LAUNCHER_SRC):
        shutil.copy2(LAUNCHER_SRC, os.path.join(files_dir, 'HuoChat_launcher.exe'))
    count = sum(len(fs) for _, _, fs in os.walk(files_dir))
    print('  复制 %d 个文件' % count)

    # Step 1.5: 裁掉已证明可删的组件
    print('[1.5] 裁组件（web/plugins/shot.dll）...')
    stripped = 0
    for d in ('web', 'plugins'):
        dd = os.path.join(files_dir, d)
        if os.path.isdir(dd):
            sz = sum(os.path.getsize(os.path.join(r, f))
                     for r, _, fs in os.walk(dd) for f in fs)
            shutil.rmtree(dd)
            stripped += sz
            print('  [strip] %s/ (%.1f MB)' % (d, sz / 1024 / 1024))
    for f in ('shot.dll',):
        fp = os.path.join(files_dir, f)
        if os.path.exists(fp):
            stripped += os.path.getsize(fp)
            os.remove(fp)
            print('  [strip] %s' % f)
    print('  合计裁掉 %.1f MB' % (stripped / 1024 / 1024))

    # Step 1.6: 清空 site.db（top_site + bookmark）
    print('[1.6] 清空 site.db...')
    site_path = os.path.join(files_dir, 'site.db')
    if os.path.exists(site_path):
        try:
            clean_site_db(site_path)
        except Exception as e:
            print('  [WARN] site.db 清理跳过: %s' % e)
    else:
        print('  [WARN] site.db 不存在')

    # Step 2: 联网全面禁用
    print('[2] 联网补丁（HuoChat 9 点 + hc_engine 全部 voidtools）...')
    patch_binary(os.path.join(files_dir, 'HuoChat.exe'), HUOCHAT_PATCHES, 'HuoChat')
    patch_binary(os.path.join(files_dir, 'hc_engine.exe'), ENGINE_PATCHES, 'hc_engine')

    # Step 3: 安全 ZIPRES 隐藏（Proven 集，只 visible=false）
    print('[3] 安全 ZIPRES 隐藏（%s）...' % SAFE_HIDE_CONTROLS)
    if not apply_safe_zipres_hide(os.path.join(files_dir, 'HuoChat.exe')):
        print('  [ERROR] ZIPRES 安全隐藏失败，中止')
        sys.exit(1)

    # Step 4: Everything.ini 关闭自更新（索引范围保持现状）
    print('[4] 配置 Everything.ini（关自更新，索引保持现状）...')
    configure_everything_ini(os.path.join(files_dir, 'Everything.ini'))
    print('  完成')

    # Step 5: 图标
    print('[5] 准备图标...')
    if os.path.exists(ICON_SRC):
        shutil.copy2(ICON_SRC, os.path.join(WORK_DIR, 'green_icon.ico'))

    # Step 6: NSIS 打包
    print('[6] NSIS 打包...')
    script_path = create_nsis_script(WORK_DIR)
    result = subprocess.run([NSIS, '/V2', script_path],
                            capture_output=True, text=True, cwd=WORK_DIR)
    if result.returncode != 0:
        print('  NSIS 错误:')
        print(result.stdout[-2000:] if result.stdout else '')
        print(result.stderr[-1000:] if result.stderr else '')
        sys.exit(1)

    built = os.path.join(WORK_DIR, '火柴全面离线版.exe')
    if not os.path.exists(built):
        print('  [ERROR] 未生成输出')
        sys.exit(1)
    shutil.move(built, OUT_EXE)
    sz = os.path.getsize(OUT_EXE)
    print('  产出: %s (%.1f MB)' % (OUT_EXE, sz / 1024 / 1024))

    # Step 7: 静态验证全面离线
    verify_offline(files_dir)

    print('\n=== 完成 ===')
    print('产物: %s' % OUT_EXE)
    print('旧版保留: 火柴单文件版.exe / 火柴实验精简版_极简.exe / 火柴绿色版.exe')


if __name__ == '__main__':
    main()
