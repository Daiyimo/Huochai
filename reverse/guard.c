/* Local-only API guards. Never contacts a network. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <shlwapi.h>
#include "startup.h"

static HMODULE self_module;
#include "engine_entry.h"

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) self_module = module;
    return TRUE;
}

static WCHAR lower(WCHAR c) { return c >= L'A' && c <= L'Z' ? c + 32 : c; }
static BOOL contains(LPCWSTR s, LPCWSTR part) {
    LPCWSTR a, b;
    if (!s) return FALSE;
    for (; *s; ++s) {
        for (a = s, b = part; *a && *b && lower(*a) == lower(*b); ++a, ++b) {}
        if (!*b) return TRUE;
    }
    return FALSE;
}
static BOOL wide(LPCSTR text, WCHAR *out, int count) {
    if (!text) { out[0] = 0; return TRUE; }
    return MultiByteToWideChar(CP_ACP, 0, text, -1, out, count) != 0;
}
static BOOL remote(LPCWSTR text) {
    if (!text) return FALSE;
    return contains(text, L"://") || contains(text, L"mailto:") ||
        contains(text, L"about:") || contains(text, L"javascript:") || contains(text, L"data:") ||
        contains(text, L"microsoft-edge:") || contains(text, L"www.") ||
        contains(text, L"\\\\?\\UNC\\") || contains(text, L"\\\\?\\GLOBALROOT\\Device\\Mup") ||
        contains(text, L"\\Device\\Mup") || contains(text, L"\\Device\\LanmanRedirector");
}
static BOOL local_path(LPCWSTR path) {
    WCHAR drive[4];
    if (!path) return TRUE;
    if (remote(path)) return FALSE;
    /* Local device/volume/pipe namespaces are required by Everything. */
    if ((path[0] == L'\\' && path[1] == L'\\') ||
        (path[0] == L'/' && path[1] == L'/')) {
        if (!((path[2] == L'?' || path[2] == L'.') && path[3] == L'\\')) return FALSE;
        path += 4;
    }
    if (path[0] && path[1] == L':') {
        drive[0] = path[0]; drive[1] = L':'; drive[2] = L'\\'; drive[3] = 0;
        if (GetDriveTypeW(drive) == DRIVE_REMOTE) return FALSE;
    }
    return TRUE;
}
static BOOL local_a(LPCSTR path) {
    WCHAR buf[1024];
    return wide(path, buf, 1024) && local_path(buf);
}
/* Kept in step with policy.NETWORK_DLLS; build.py asserts the two agree. */
static BOOL network_module(LPCWSTR name) {
    LPCWSTR base = name, p;
    if (!name) return FALSE;
    for (p = name; *p; ++p) if (*p == L'\\' || *p == L'/') base = p + 1;
    return contains(base, L"wininet") || contains(base, L"winhttp") ||
        contains(base, L"ws2_32") || contains(base, L"wsock32") ||
        contains(base, L"urlmon") || contains(base, L"dnsapi") ||
        contains(base, L"netapi32") || contains(base, L"iphlpapi") ||
        contains(base, L"httpapi") || contains(base, L"webio") ||
        contains(base, L"msxml") || contains(base, L"mshtml") ||
        contains(base, L"ieframe") || contains(base, L"wldap32") ||
        contains(base, L"rasapi32") || contains(base, L"api-ms-win-net-") ||
        contains(base, L"node.dll") || contains(base, L"winrnr") ||
        contains(base, L"mpr.dll") || contains(base, L"schannel.dll") ||
        contains(base, L"secur32.dll") || contains(base, L"ncrypt.dll") ||
        contains(base, L"davclnt.dll") || contains(base, L"nlaapi.dll") ||
        contains(base, L"netiohlp.dll") || contains(base, L"wsnmp32.dll");
}
static HMODULE net_stub(void) {
    WCHAR path[1024]; DWORD n, i;
    const WCHAR name[] = L"hcn.dll";
    n = GetModuleFileNameW(self_module, path, 1024);
    if (!n || n >= 1015) return NULL;
    while (n && path[n-1] != L'\\' && path[n-1] != L'/') --n;
    for (i = 0; i < sizeof(name)/sizeof(WCHAR); ++i) path[n+i] = name[i];
    return LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
}

/* The application resolves known AppData folders to Data. External programs
   inherit Data\\Apps through the launcher's process environment. */
static BOOL portable_dir_w(WCHAR *out, DWORD count) {
    DWORD n;
    if (!out || count < 4) return FALSE;
    n = GetModuleFileNameW(self_module, out, count);
    if (!n || n >= count) return FALSE;
    while (n && out[n-1] != L'\\' && out[n-1] != L'/') --n;
    if (!n) return FALSE;
    out[n] = 0;
    return SUCCEEDED(StringCchCatW(out,count,L"Data"));
}
static BOOL portable_dir_a(CHAR *out, DWORD count) {
    WCHAR path[MAX_PATH];
    return portable_dir_w(path, MAX_PATH) &&
        WideCharToMultiByte(CP_ACP, 0, path, -1, out, count, NULL, NULL) != 0;
}
static BOOL portable_csidl(int csidl) {
    int folder = csidl & 0xff;
    return folder == CSIDL_LOCAL_APPDATA || folder == CSIDL_APPDATA;
}
static BOOL same_guid(REFKNOWNFOLDERID a, const GUID *b) {
    unsigned i;
    if (!a || a->Data1 != b->Data1 || a->Data2 != b->Data2 || a->Data3 != b->Data3)
        return FALSE;
    for (i=0; i<8; ++i) if (a->Data4[i] != b->Data4[i]) return FALSE;
    return TRUE;
}
static BOOL portable_known_folder(REFKNOWNFOLDERID id) {
    static const GUID local = {0xf1b32785,0x6fba,0x4fcf,{0x9d,0x55,0x7b,0x8e,0x7f,0x15,0x70,0x91}};
    static const GUID roaming = {0x3eb685db,0x65f9,0x4cf6,{0xa0,0x3a,0xe3,0xef,0x65,0x72,0x9f,0x3d}};
    return same_guid(id,&local) || same_guid(id,&roaming);
}

HRESULT WINAPI Guard_SHGetFolderPathW(HWND hwnd,int csidl,HANDLE token,DWORD flags,LPWSTR path) {
    if (portable_csidl(csidl))
        return portable_dir_w(path,MAX_PATH) ? S_OK : E_FAIL;
    return SHGetFolderPathW(hwnd,csidl,token,flags,path);
}
HRESULT WINAPI Guard_SHGetFolderPathA(HWND hwnd,int csidl,HANDLE token,DWORD flags,LPSTR path) {
    if (portable_csidl(csidl))
        return portable_dir_a(path,MAX_PATH) ? S_OK : E_FAIL;
    return SHGetFolderPathA(hwnd,csidl,token,flags,path);
}
BOOL WINAPI Guard_SHGetSpecialFolderPathW(HWND hwnd,LPWSTR path,int csidl,BOOL create) {
    if (portable_csidl(csidl)) {
        BOOL ok=portable_dir_w(path,MAX_PATH);
        if (ok && create) CreateDirectoryW(path,NULL);
        return ok;
    }
    return SHGetSpecialFolderPathW(hwnd,path,csidl,create);
}
BOOL WINAPI Guard_SHGetSpecialFolderPathA(HWND hwnd,LPSTR path,int csidl,BOOL create) {
    if (portable_csidl(csidl)) {
        BOOL ok=portable_dir_a(path,MAX_PATH);
        if (ok && create) CreateDirectoryA(path,NULL);
        return ok;
    }
    return SHGetSpecialFolderPathA(hwnd,path,csidl,create);
}
HRESULT WINAPI Guard_SHGetKnownFolderPath(REFKNOWNFOLDERID id,DWORD flags,HANDLE token,PWSTR *path) {
    WCHAR local[MAX_PATH]; SIZE_T bytes; PWSTR copy;
    (void)flags; (void)token;
    if (!portable_known_folder(id)) return SHGetKnownFolderPath(id,flags,token,path);
    if (!path || !portable_dir_w(local,MAX_PATH)) return E_FAIL;
    bytes=((SIZE_T)lstrlenW(local)+1)*sizeof(WCHAR);
    copy=(PWSTR)CoTaskMemAlloc(bytes);
    if (!copy) { *path=NULL; return E_OUTOFMEMORY; }
    CopyMemory(copy,local,bytes); *path=copy;
    return S_OK;
}

HMODULE WINAPI Guard_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) {
    if (!local_path(name)) { SetLastError(ERROR_ACCESS_DENIED); return NULL; }
    /* Missing optional web components must remain missing; a fake handle would
       let legacy code call absent wke/COM exports through a null pointer. */
    if (contains(name,L"node.dll") || contains(name,L"mshtml") || contains(name,L"msxml") || contains(name,L"ieframe")) {
        SetLastError(ERROR_ACCESS_DENIED); return NULL;
    }
    if (network_module(name)) return net_stub();
    return LoadLibraryExW(name, file, flags);
}
HMODULE WINAPI Guard_LoadLibraryW(LPCWSTR name) { return Guard_LoadLibraryExW(name, NULL, 0); }
HMODULE WINAPI Guard_LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags) {
    WCHAR buf[1024];
    if (!wide(name, buf, 1024)) { SetLastError(ERROR_ACCESS_DENIED); return NULL; }
    return Guard_LoadLibraryExW(buf, file, flags);
}
HMODULE WINAPI Guard_LoadLibraryA(LPCSTR name) { return Guard_LoadLibraryExA(name, NULL, 0); }

FARPROC WINAPI Guard_GetProcAddress(HMODULE module, LPCSTR name) {
    WCHAR path[1024]; HMODULE guard, net; FARPROC proc;
    if (GetModuleFileNameW(module, path, 1024) && network_module(path)) {
        if ((ULONG_PTR)name <= 0xffff) { SetLastError(ERROR_PROC_NOT_FOUND); return NULL; }
        net = net_stub();
        return net ? GetProcAddress(net, name) : NULL;
    }
    /* Dynamic resolution must not bypass guarded kernel/shell/COM exports. */
    if ((ULONG_PTR)name > 0xffff) {
        guard = self_module;
        if (lstrcmpA(name, "LoadLibraryA") == 0 || lstrcmpA(name, "LoadLibraryW") == 0 ||
            lstrcmpA(name, "LoadLibraryExA") == 0 || lstrcmpA(name, "LoadLibraryExW") == 0 ||
            lstrcmpA(name, "GetProcAddress") == 0 || lstrcmpA(name, "ShellExecuteA") == 0 ||
            lstrcmpA(name, "ShellExecuteW") == 0 || lstrcmpA(name, "ShellExecuteExW") == 0 ||
            lstrcmpA(name, "ShellExecuteExA") == 0 || lstrcmpA(name, "CoCreateInstance") == 0 ||
            lstrcmpA(name, "CoGetClassObject") == 0 || lstrcmpA(name, "CLSIDFromProgID") == 0 ||
             lstrcmpA(name, "CreateFileA") == 0 || lstrcmpA(name, "CreateFileW") == 0 ||
             lstrcmpA(name, "GetFileAttributesA") == 0 || lstrcmpA(name, "GetFileAttributesW") == 0 ||
             lstrcmpA(name, "FindFirstFileA") == 0 || lstrcmpA(name, "FindFirstFileW") == 0 ||
             lstrcmpA(name, "FindFirstFileExA") == 0 || lstrcmpA(name, "FindFirstFileExW") == 0 ||
             lstrcmpA(name, "SHGetFolderPathA") == 0 || lstrcmpA(name, "SHGetFolderPathW") == 0 ||
             lstrcmpA(name, "SHGetSpecialFolderPathA") == 0 || lstrcmpA(name, "SHGetSpecialFolderPathW") == 0 ||
             lstrcmpA(name, "SHGetKnownFolderPath") == 0 ||
             lstrcmpA(name, "RegSetValueExW") == 0 || lstrcmpA(name, "RegSetValueExA") == 0 ||
             lstrcmpA(name, "SHSetValueW") == 0 || lstrcmpA(name, "SHSetValueA") == 0 ||
             lstrcmpA(name, "GetCommandLineW") == 0 || lstrcmpA(name, "GetCommandLineA") == 0 ||
             lstrcmpA(name, "Shell_NotifyIconW") == 0 || lstrcmpA(name, "Shell_NotifyIconA") == 0) {
            proc = GetProcAddress(guard, name);
            if (!proc) SetLastError(ERROR_PROC_NOT_FOUND);
            return proc;
        }
    }
    return GetProcAddress(module, name);
}

static BOOL shell_name(LPCWSTR file) {
    LPCWSTR first, end, leaf, p;
    if (!file || !*file) return FALSE;
    first = file;
    end = file + lstrlenW(file);
    if (end - first >= 2 && *first == L'"' && end[-1] == L'"') {
        ++first; --end;
    }
    if (first == end) return FALSE;
    leaf = first;
    for (p = first; p < end; ++p)
        if (*p == L'\\' || *p == L'/' || *p == L':') leaf = p + 1;
    /* Explicit directory/drive targets remain valid (e.g. C:\\ or C:\\docs\\).
       Removed component constants contain spaces, not an empty string: the
       legacy startup code appends all 23 characters to its current directory.
       Do not pass that blank filename to ShellExecuteEx: Windows shows its
       own "file not found" dialog even though the component was disabled. */
    if (leaf == end) return TRUE;
    for (p = leaf; p < end; ++p) if (*p > L' ') return TRUE;
    return FALSE;
}

static BOOL shell_target(LPCWSTR file, LPCWSTR args, LPCWSTR dir) {
    LPCWSTR p;
    if (!shell_name(file) || !local_path(file) || !local_path(dir) || remote(args)) return FALSE;
    for(p=file;*p;++p) if(*p==L':' && p!=file+1 && !(p==file+5 && file[0]==L'\\' && file[1]==L'\\')) return FALSE;
    if ((contains(file,L".com") || contains(file,L".cn") || contains(file,L".net") || contains(file,L".org")) && GetFileAttributesW(file)==INVALID_FILE_ATTRIBUTES) return FALSE;
    /* Browser shortcuts can hide a URL outside the command line. */
    if (contains(file, L".url") || contains(file, L".website") || contains(file, L".hta")) return FALSE;
    return TRUE;
}
HINSTANCE WINAPI Guard_ShellExecuteW(HWND hwnd, LPCWSTR op, LPCWSTR file, LPCWSTR args, LPCWSTR dir, INT show) {
    if (!shell_target(file, args, dir)) { SetLastError(ERROR_ACCESS_DENIED); return (HINSTANCE)SE_ERR_ACCESSDENIED; }
    return ShellExecuteW(hwnd, op, file, args, dir, show);
}
HINSTANCE WINAPI Guard_ShellExecuteA(HWND hwnd, LPCSTR op, LPCSTR file, LPCSTR args, LPCSTR dir, INT show) {
    WCHAR f[1024], a[1024], d[1024];
    if (!wide(file,f,1024) || !wide(args,a,1024) || !wide(dir,d,1024) || !shell_target(f,a,d)) {
        SetLastError(ERROR_ACCESS_DENIED); return (HINSTANCE)SE_ERR_ACCESSDENIED;
    }
    return ShellExecuteA(hwnd, op, file, args, dir, show);
}
BOOL WINAPI Guard_ShellExecuteExW(SHELLEXECUTEINFOW *info) {
    WCHAR pidl_path[MAX_PATH]; LPCWSTR file=info ? info->lpFile : NULL;
    if(info && (info->fMask & SEE_MASK_IDLIST)) {
        if(!info->lpIDList || !SHGetPathFromIDListW((LPCITEMIDLIST)info->lpIDList,pidl_path)) file=NULL;
        else file=pidl_path;
    }
    if (!info || !shell_target(file, info->lpParameters, info->lpDirectory)) {
        if (info) { info->hInstApp=(HINSTANCE)SE_ERR_ACCESSDENIED; info->hProcess=NULL; }
        SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    return ShellExecuteExW(info);
}
BOOL WINAPI Guard_ShellExecuteExA(SHELLEXECUTEINFOA *info) {
    WCHAR f[1024], a[1024], d[1024];
    BOOL file_ok=FALSE;
    if(info) {
        if(info->fMask & SEE_MASK_IDLIST) file_ok=info->lpIDList && SHGetPathFromIDListW((LPCITEMIDLIST)info->lpIDList,f);
        else file_ok=wide(info->lpFile,f,1024);
    }
    if (!info || !file_ok ||
        !wide(info->lpParameters,a,1024) || !wide(info->lpDirectory,d,1024) || !shell_target(f,a,d)) {
        if (info) { info->hInstApp=(HINSTANCE)SE_ERR_ACCESSDENIED; info->hProcess=NULL; }
        SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    return ShellExecuteExA(info);
}

/* A spawned child gets its own import table, so the guard cannot follow it.
   Local helpers (the search engine, updaters) must still start; only targets
   that can reach the network directly -- browsers and anything remote -- are
   refused. This is a policy boundary, not a sandbox. */
static BOOL spawn_target(LPCWSTR app, LPCWSTR cmd) {
    LPCWSTR subject = app && *app ? app : cmd;
    if (!subject || !*subject) return TRUE;
    if (remote(subject)) return FALSE;
    if (!local_path(subject)) return FALSE;
    if (contains(subject, L"iexplore") || contains(subject, L"msedge") ||
        contains(subject, L"chrome") || contains(subject, L"firefox") ||
        contains(subject, L"browser") || contains(subject, L"opera") ||
        contains(subject, L"webkit")) return FALSE;
    return TRUE;
}

BOOL WINAPI Guard_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    (void)pa; (void)ta; (void)inherit; (void)flags; (void)env; (void)dir; (void)si; (void)pi;
    if (!spawn_target(app, cmd)) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    return CreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}
BOOL WINAPI Guard_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir,
    LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi) {
    WCHAR a[1024], c[1024];
    (void)pa; (void)ta; (void)inherit; (void)flags; (void)env; (void)dir; (void)si; (void)pi;
    if (!wide(app,a,1024) || !wide(cmd,c,1024) || !spawn_target(a,c)) {
        SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    return CreateProcessA(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}
UINT WINAPI Guard_WinExec(LPCSTR cmd, UINT show) {
    WCHAR c[1024];
    if (!wide(cmd,c,1024) || !spawn_target(c,c)) { SetLastError(ERROR_ACCESS_DENIED); return 0; }
    return WinExec(cmd, show);
}

LSTATUS WINAPI Guard_RegSetValueExW(HKEY key,LPCWSTR name,DWORD reserved,DWORD type,const BYTE *data,DWORD bytes) {
    WCHAR dir[STARTUP_CAP],command[STARTUP_CAP],value[STARTUP_CAP]={0}; DWORD n;
    if(name && !lstrcmpiW(name,L"HuoChat") && type==REG_SZ && data && bytes>=2 && bytes%2==0 &&
       bytes<sizeof(value) && IsStartupKey(key)) {
        CopyMemory(value,data,bytes); /* The original SHSetValueW omits the NUL. */
        n=GetModuleFileNameW(self_module,dir,STARTUP_CAP);
        if(!n || n>=STARTUP_CAP) return ERROR_BUFFER_OVERFLOW;
        while(n && dir[n-1]!=L'\\') n--; dir[n]=0;
        if(IsOwnStartup(value,dir,NULL)) {
            if(!StartupCommand(dir,command)) return ERROR_BUFFER_OVERFLOW;
            return RegSetValueExW(key,name,reserved,REG_SZ,(const BYTE*)command,((DWORD)wcslen(command)+1)*2);
        }
    }
    return RegSetValueExW(key,name,reserved,type,data,bytes);
}
LSTATUS WINAPI Guard_RegSetValueExA(HKEY key,LPCSTR name,DWORD reserved,DWORD type,const BYTE *data,DWORD bytes) {
    WCHAR wide_name[STARTUP_CAP],value[STARTUP_CAP]={0};
    if(name && !lstrcmpiA(name,"HuoChat") && type==REG_SZ && data && bytes && bytes<STARTUP_CAP && IsStartupKey(key)) {
        if(!wide(name,wide_name,STARTUP_CAP) || !MultiByteToWideChar(CP_ACP,0,(LPCSTR)data,bytes,value,STARTUP_CAP-1)) return ERROR_NO_UNICODE_TRANSLATION;
        return Guard_RegSetValueExW(key,wide_name,reserved,type,(const BYTE*)value,((DWORD)wcslen(value)+1)*2);
    }
    return RegSetValueExA(key,name,reserved,type,data,bytes);
}

LSTATUS WINAPI Guard_SHSetValueW(HKEY key,LPCWSTR subkey,LPCWSTR name,DWORD type,const void *data,DWORD bytes) {
    HKEY target=key; LONG result;
    if(!name || lstrcmpiW(name,L"HuoChat") || type!=REG_SZ) return SHSetValueW(key,subkey,name,type,data,bytes);
    if(subkey && *subkey) {
        result=RegCreateKeyExW(key,subkey,0,NULL,0,KEY_SET_VALUE,NULL,&target,NULL);
        if(result!=ERROR_SUCCESS) return result;
    }
    result=Guard_RegSetValueExW(target,name,0,type,(const BYTE*)data,bytes);
    if(target!=key) RegCloseKey(target);
    return result;
}
LSTATUS WINAPI Guard_SHSetValueA(HKEY key,LPCSTR subkey,LPCSTR name,DWORD type,const void *data,DWORD bytes) {
    HKEY target=key; LONG result;
    if(!name || lstrcmpiA(name,"HuoChat") || type!=REG_SZ) return SHSetValueA(key,subkey,name,type,data,bytes);
    if(subkey && *subkey) {
        result=RegCreateKeyExA(key,subkey,0,NULL,0,KEY_SET_VALUE,NULL,&target,NULL);
        if(result!=ERROR_SUCCESS) return result;
    }
    result=Guard_RegSetValueExA(target,name,0,type,(const BYTE*)data,bytes);
    if(target!=key) RegCloseKey(target);
    return result;
}

HANDLE WINAPI Guard_CreateFileW(LPCWSTR p,DWORD a,DWORD s,LPSECURITY_ATTRIBUTES sa,DWORD c,DWORD f,HANDLE t) {
    if (!local_path(p)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
    return CreateFileW(p,a,s,sa,c,f,t);
}
HANDLE WINAPI Guard_CreateFileA(LPCSTR p,DWORD a,DWORD s,LPSECURITY_ATTRIBUTES sa,DWORD c,DWORD f,HANDLE t) {
    if (!local_a(p)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
    return CreateFileA(p,a,s,sa,c,f,t);
}
DWORD WINAPI Guard_GetFileAttributesW(LPCWSTR p) {
    if (!local_path(p)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_FILE_ATTRIBUTES; }
    return GetFileAttributesW(p);
}
DWORD WINAPI Guard_GetFileAttributesA(LPCSTR p) {
    if (!local_a(p)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_FILE_ATTRIBUTES; }
    return GetFileAttributesA(p);
}
HANDLE WINAPI Guard_FindFirstFileW(LPCWSTR p,LPWIN32_FIND_DATAW d) {
    if (!local_path(p)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
    return FindFirstFileW(p,d);
}
HANDLE WINAPI Guard_FindFirstFileA(LPCSTR p,LPWIN32_FIND_DATAA d) {
    if (!local_a(p)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
    return FindFirstFileA(p,d);
}
HANDLE WINAPI Guard_FindFirstFileExW(LPCWSTR p,FINDEX_INFO_LEVELS l,LPVOID d,FINDEX_SEARCH_OPS o,LPVOID f,DWORD flags) {
    if (!local_path(p)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
    return FindFirstFileExW(p,l,d,o,f,flags);
}
HANDLE WINAPI Guard_FindFirstFileExA(LPCSTR p,FINDEX_INFO_LEVELS l,LPVOID d,FINDEX_SEARCH_OPS o,LPVOID f,DWORD flags) {
    if (!local_a(p)) { SetLastError(ERROR_ACCESS_DENIED); return INVALID_HANDLE_VALUE; }
    return FindFirstFileExA(p,l,d,o,f,flags);
}

/* Deny in-process browser/HTTP COM activation. Local shell COM remains intact. */
static BOOL network_class(REFCLSID cls) {
    static const DWORD ids[] = {0x8856f961,0xeab22ac3,0x0002df01,0x0002df02,
        0xf5078f35,0xf5078f1e,0x88d969c5,0x88d969c6,0x88d969d5,0x88d969d6,
        0xafb40ffd,0x2087c2f4,0xfbf23b40};
    unsigned i;
    for(i=0;i<sizeof(ids)/sizeof(ids[0]);++i) if(cls->Data1==ids[i]) return TRUE;
    return FALSE;
}
HRESULT WINAPI Guard_CoCreateInstance(REFCLSID cls,LPUNKNOWN outer,DWORD context,REFIID iid,LPVOID *out) {
    if(network_class(cls)) { if(out)*out=NULL; return E_ACCESSDENIED; }
    return CoCreateInstance(cls,outer,context,iid,out);
}
HRESULT WINAPI Guard_CoGetClassObject(REFCLSID cls,DWORD context,LPVOID reserved,REFIID iid,LPVOID *out) {
    if(network_class(cls)) { if(out)*out=NULL; return E_ACCESSDENIED; }
    return CoGetClassObject(cls,context,reserved,iid,out);
}
HRESULT WINAPI Guard_CLSIDFromProgID(LPCOLESTR name,LPCLSID cls) {
    if(contains(name,L"xmlhttp") || contains(name,L"winhttp") || contains(name,L"internetexplorer") || contains(name,L"msxml")) return E_ACCESSDENIED;
    return CLSIDFromProgID(name,cls);
}
