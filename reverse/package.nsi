Unicode true
Name "火柴离线版"
OutFile "@OUTFILE@"
RequestExecutionLevel user
SilentInstall silent
AutoCloseWindow true
ShowInstDetails nevershow
SetCompressor /SOLID /FINAL lzma
SetCompressorDictSize 16
Icon "@ICON@"
VIProductVersion "2026.9.3.4"
VIAddVersionKey "ProductName" "火柴离线单文件版"
VIAddVersionKey "FileDescription" "火柴离线便携启动器"
VIAddVersionKey "FileVersion" "2026.09.03.4"
VIAddVersionKey "ProductVersion" "2.1.0.11 / Offline 2026.09.03.4"
VIAddVersionKey "LegalCopyright" "Original application and components retain their respective licenses."
!addplugindir /x86-unicode "@PLUGINS@"
!include "FileFunc.nsh"

Var Gate
Var Ready
Var Probe
Var HashFile
Var HashResult
Var Failure
Var LaunchArgs
Var QuietErrors

Function .onInit
 @ASSERT_SILENT@
 HideWindow
 StrCpy $LaunchArgs ""
 ${GetParameters} $0
 StrCpy $QuietErrors 0
 ClearErrors
 ${GetOptions} $0 "/S" $1
 IfErrors +2 0
 StrCpy $QuietErrors 1
 ClearErrors
 ${GetOptions} $0 "-s" $1
 IfErrors +2 0
 StrCpy $LaunchArgs " -s"
 ; The package gate spans extraction and the handoff to the launcher mutex.
 System::Call 'kernel32::CreateMutexW(p 0, i 0, w "Local\@IDENTITY@PackageV2") p .r0 ?e'
 Pop $1
 StrCpy $Gate $0
 StrCmp $0 0 init_failed
 StrCmp $1 183 already_running
 System::Call 'kernel32::OpenMutexW(i 0x100001, i 0, w "Local\@IDENTITY@LauncherV1") p .r0'
 StrCmp $0 0 init_ready
 StrCpy $2 $0
 ; A tray-exit notification distinguishes teardown from a genuine duplicate.
 System::Call 'kernel32::OpenEventW(i 0x100000, i 0, w "Local\@IDENTITY@LauncherStoppingV1") p .r0'
 StrCmp $0 0 launcher_still_running
 StrCpy $3 $0
 System::Call 'kernel32::WaitForSingleObject(p r3, i 300) i .r1'
 System::Call 'kernel32::CloseHandle(p r3)'
 StrCmp $1 0 wait_for_teardown launcher_still_running
 wait_for_teardown:
 System::Call 'kernel32::WaitForSingleObject(p r2, i 8000) i .r1'
 StrCmp $1 0 teardown_finished
 StrCmp $1 128 teardown_finished launcher_still_running
 teardown_finished:
 System::Call 'kernel32::ReleaseMutex(p r2)'
 System::Call 'kernel32::CloseHandle(p r2)'
 Goto init_ready
 launcher_still_running:
 System::Call 'kernel32::CloseHandle(p r2)'
 already_running:
 StrCmp $QuietErrors 1 +2
 MessageBox MB_OK|MB_ICONINFORMATION "火柴正在运行或启动中。请双击 Ctrl 唤起搜索。"
 SetErrorLevel 10
 Quit
 init_failed:
 StrCmp $QuietErrors 1 +2
 MessageBox MB_OK|MB_ICONSTOP "无法初始化火柴启动器。请退出其他火柴进程后重试。"
 SetErrorLevel 11
 Quit
 init_ready:
 System::Call 'kernel32::CreateEventW(p 0, i 1, i 0, w "Local\@IDENTITY@LauncherReadyV2") p .r0'
 StrCpy $Ready $0
 StrCmp $0 0 init_failed
 System::Call 'kernel32::ResetEvent(p r0)'
FunctionEnd

; Hash immutable files without executing a cached helper. System.dll is
; embedded before the payload, so a warm start never inflates that payload.
Function SHA256
 Push $0
 Push $1
 Push $2
 Push $3
 Push $4
 Push $5
 Push $6
 Push $7
 Push $8
 StrCpy $HashResult ""
 StrCpy $0 0
 StrCpy $1 0
 StrCpy $2 -1
 StrCpy $3 0
 StrCpy $4 0
 System::Call 'advapi32::CryptAcquireContextW(*p .r0, p 0, p 0, i 24, i 0xF0000000) i .r6'
 StrCmp $6 0 hash_done
 System::Call 'advapi32::CryptCreateHash(p r0, i 0x800c, p 0, i 0, *p .r1) i .r6'
 StrCmp $6 0 hash_done
 System::Call 'kernel32::CreateFileW(w "$HashFile", i 0x80000000, i 7, p 0, i 3, i 0x80, p 0) p .r2'
 StrCmp $2 -1 hash_done
 System::Alloc 65536
 Pop $3
 StrCmp $3 0 hash_done
 hash_read:
 System::Call 'kernel32::ReadFile(p r2, p r3, i 65536, *i .r5, p 0) i .r6'
 StrCmp $6 0 hash_done
 StrCmp $5 0 hash_digest
 System::Call 'advapi32::CryptHashData(p r1, p r3, i r5, i 0) i .r6'
 StrCmp $6 0 hash_done hash_read
 hash_digest:
 System::Alloc 32
 Pop $4
 StrCmp $4 0 hash_done
 System::Call 'advapi32::CryptGetHashParam(p r1, i 2, p r4, *i 32, i 0) i .r6'
 StrCmp $6 0 hash_done
 StrCpy $7 0
 hash_hex:
 IntOp $5 $4 + $7
 System::Call '*$5(&i1 .r6)'
 IntFmt $8 "%02x" $6
 StrCpy $HashResult "$HashResult$8"
 IntOp $7 $7 + 1
 IntCmp $7 32 hash_done hash_hex hash_done
 hash_done:
 System::Free $4
 System::Free $3
 StrCmp $2 -1 +2
 System::Call 'kernel32::CloseHandle(p r2)'
 StrCmp $1 0 +2
 System::Call 'advapi32::CryptDestroyHash(p r1)'
 StrCmp $0 0 +2
 System::Call 'advapi32::CryptReleaseContext(p r0, i 0)'
 Pop $8
 Pop $7
 Pop $6
 Pop $5
 Pop $4
 Pop $3
 Pop $2
 Pop $1
 Pop $0
FunctionEnd

Section
 StrCpy $INSTDIR "$EXEDIR\HuoChatOffline-v1-@VARIANT@"
 StrCpy $Failure "无法写入程序目录。请把整个程序移到有写入权限的本地目录。"
 ClearErrors
 CreateDirectory "$INSTDIR"
 IfErrors failed
 GetTempFileName $Probe "$INSTDIR"
 IfErrors failed
 Delete "$Probe"
 ReadINIStr $0 "$INSTDIR\.package.ini" "Package" "id"
 StrCmp $0 "@PACKAGE_ID@" 0 repair
 @CACHE_CHECKS@
 Goto seed_check
 repair:
 StrCpy $Failure "程序文件无法更新或修复。请退出火柴，并检查文件占用和目录权限。"
 ClearErrors
 Delete "$INSTDIR\.package.ini"
 IfErrors failed
 SetOutPath "$INSTDIR"
 SetOverwrite try
 ClearErrors
 @IMMUTABLE_FILES@
 IfErrors failed
 @VERIFY_CHECKS@
 seed_check:
 ; Migrate old data before creating any new default files at its destination.
 StrCpy $Failure "数据整理未完成。请退出火柴及由它启动的 WeGame、CLI 等程序后重试；检查 Data\offline.log 中的文件占用、重名目录或目录联接。旧数据不会被默认文件覆盖。"
 ClearErrors
 ExecWait '"$INSTDIR\HuoChat_launcher.exe" --prepare' $0
 IfErrors failed
 StrCmp $0 0 +2 0
 Goto failed
 @SEED_CHECKS@
 Goto launch
 seeds:
 StrCpy $Failure "无法初始化配置或资源文件。请检查目录权限及剩余磁盘空间。"
 SetOverwrite off
 ClearErrors
 @SEED_FILES@
 IfErrors failed
 launch:
 ; Write the completion marker only after extraction, validation and seeding.
 ClearErrors
 ReadINIStr $0 "$INSTDIR\.package.ini" "Package" "id"
 StrCmp $0 "@PACKAGE_ID@" marker_ready
 ClearErrors
 WriteINIStr "$INSTDIR\.package.ini" "Package" "id" "@PACKAGE_ID@"
 IfErrors failed
 marker_ready:
 ReadINIStr $0 "$INSTDIR\.package.ini" "Package" "entry"
 StrCmp $0 "$EXEPATH" entry_ready
 ClearErrors
 WriteINIStr "$INSTDIR\.package.ini" "Package" "entry" "$EXEPATH"
 IfErrors failed
 entry_ready:
 StrCpy $Failure "无法启动火柴。请检查程序文件是否被占用或被安全软件隔离。"
 ClearErrors
 Exec '"$INSTDIR\HuoChat_launcher.exe"$LaunchArgs'
 IfErrors failed
 System::Call 'kernel32::WaitForSingleObject(p $Ready, i 10000) i .r0'
 StrCmp $0 0 done
 StrCpy $Failure "火柴启动未响应。请查看 Data\offline.log，或退出其他火柴进程后重试。"
 failed:
 FileOpen $0 "$INSTDIR\package-error.log" w
 IfErrors no_log
 FileWriteWord $0 0xFEFF
 FileWriteUTF16LE $0 "$Failure$\r$\n"
 FileClose $0
 no_log:
 StrCmp $QuietErrors 1 +2
 MessageBox MB_OK|MB_ICONSTOP "$Failure"
 SetErrorLevel 20
 Quit
 done:
 Delete "$INSTDIR\package-error.log"
 SetErrorLevel 0
SectionEnd
