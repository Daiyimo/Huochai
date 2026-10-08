/* Local-only API guards. Never contacts a network. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <objbase.h>
#include <shlwapi.h>
#include "startup.h"

static HMODULE self_module;
#include "engine_entry.h"
#include "backend.h"

SC_HANDLE WINAPI Guard_OpenServiceW(SC_HANDLE manager,LPCWSTR name,DWORD access) {
    BackendPaths paths;
    if(name && !lstrcmpiW(name,L"Everything") && BackendFromModule(&paths,self_module) && paths.modern)
        return OpenServiceW(manager,paths.service,access);
    return OpenServiceW(manager,name,access);
}

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
/* Last component of a path, using the shell's separators. Matching tokens
   against this instead of the whole string keeps a directory called
   "node.dll.bak" (or "MyNode.dll") from being treated as a module name. */
static LPCWSTR file_name_of(LPCWSTR p) {
    LPCWSTR last = p;
    if (!p) return p;
    for (; *p; ++p) if (*p == L'\\' || *p == L'/') last = p + 1;
    return last;
}
/* Whole-name match for a module token. A substring test would refuse
   "notanode.dll" (it ends in "node.dll") and "mshtmlful.dll"; both are
   ordinary modules that have nothing to do with the removed web engine. */
static BOOL module_named(LPCWSTR path, LPCWSTR token) {
    LPCWSTR p = file_name_of(path), q;
    if (!p || !token) return FALSE;
    for (q = token; *q && *p && lower(*p) == lower(*q); ++p, ++q) {}
    if (*q) return FALSE;               /* the name is shorter than the token */
    return *p == 0 || *p == L'.';       /* or longer: a different module */
}
/* Shell-namespace items (::{GUID}) are virtual objects: they can never be a
   file on disk, a UNC share or a URL. Everything still resolves them through
   the shell itself, so the drive-letter rules below must not reject them --
   doing so turns "open Recycle Bin" into the shell's "choose an app" dialog.
   Only a bare GUID is accepted: anything appended (a traversal segment, an
   extra colon) falls through to the ordinary rules and is rejected there. */
static BOOL shell_namespace(LPCWSTR p) {
    DWORD i;
    if (!p || p[0] != L':' || p[1] != L':' || p[2] != L'{') return FALSE;
    for (i = 3; p[i] && p[i] != L'}'; ++i) {}
    return p[i] == L'}' && p[i+1] == 0;
}
/* Reads a path the way the shell does. Surrounding quotes are removed before
   any rule runs: without this, "\"C:\\dir\\app.exe\"" would fail the
   drive-letter test, and "\"\\\\server\\share\\t.exe\"" would slip past the
   UNC rejection below. Unquoted input is used in place, so the length limit of
   the caller is unchanged. */
static BOOL unwrap_path(LPCWSTR file, WCHAR *buf, DWORD count, LPCWSTR *out) {
    DWORD n;
    if (!file) return FALSE;
    n = lstrlenW(file);
    if (n < 2 || file[0] != L'"' || file[n-1] != L'"') { *out = file; return TRUE; }
    n -= 2;
    if (n >= count) return FALSE;
    CopyMemory(buf, file + 1, n * sizeof(WCHAR));
    buf[n] = 0;
    *out = buf;
    return TRUE;
}
/* The leaf of a target must contain a visible character. Component names
   disabled by stub_component_names become spaces, and Windows answers that
   with its own "file not found" dialog even though the feature was removed. */
static BOOL visible_leaf(LPCWSTR s) {
    LPCWSTR leaf = s, p;
    if (!s) return FALSE;
    for (p = s; *p; ++p) if (*p == L'\\' || *p == L'/' || *p == L':') leaf = p + 1;
    for (p = leaf; *p; ++p) if (*p > L' ') return TRUE;
    return FALSE;
}
static BOOL remote(LPCWSTR text) {
    if (!text) return FALSE;
    return contains(text, L"://") || contains(text, L"mailto:") ||
        contains(text, L"about:") || contains(text, L"javascript:") || contains(text, L"data:") ||
        contains(text, L"microsoft-edge:") ||
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
    LPCWSTR base = file_name_of(name), p;
    if (!base) return FALSE;
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
    WCHAR path[PATH_CAP];
    if (!module_dir(self_module, path, PATH_CAP)) return NULL;
    if (FAILED(StringCchCatW(path, PATH_CAP, L"hcn.dll"))) return NULL;
    return LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
}

/* Only modules using this guard resolve their own AppData/temp to Data.
   External applications inherit the unchanged caller environment. */
static BOOL portable_dir_w(WCHAR *out, DWORD count) {
    if (!module_dir(self_module, out, count)) return FALSE;
    return SUCCEEDED(StringCchCatW(out,count,L"Data"));
}
static BOOL portable_dir_a(CHAR *out, DWORD count) {
    WCHAR path[MAX_PATH];
    return portable_dir_w(path, MAX_PATH) &&
        WideCharToMultiByte(CP_ACP, 0, path, -1, out, count, NULL, NULL) != 0;
}

DWORD WINAPI Guard_GetTempPathW(DWORD count,LPWSTR out) {
    WCHAR path[PATH_CAP];DWORD length;
    if(!portable_dir_w(path,PATH_CAP) || FAILED(StringCchCatW(path,PATH_CAP,L"\\Temp\\"))) {
        SetLastError(ERROR_DIRECTORY); return 0;
    }
    /* Callers write temp files here. Creating it up front turns a late
       create-file failure into a success; an existing directory just returns
       ERROR_ALREADY_EXISTS, which this deliberately ignores. */
    CreateDirectoryW(path,NULL);
    length=(DWORD)wcslen(path);
    if(count<=length)return length+1;
    if(!out){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
    CopyMemory(out,path,(length+1)*sizeof(WCHAR));return length;
}
DWORD WINAPI Guard_GetTempPathA(DWORD count,LPSTR out) {
    WCHAR path[PATH_CAP];CHAR value[PATH_CAP*4];int bytes;
    if(!Guard_GetTempPathW(PATH_CAP,path))return 0;
    bytes=WideCharToMultiByte(CP_ACP,0,path,-1,value,sizeof(value),NULL,NULL);if(!bytes)return 0;
    if(count<(DWORD)bytes)return (DWORD)bytes;
    if(!out){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
    CopyMemory(out,value,bytes);return (DWORD)bytes-1;
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
    /* The contract requires *path to be NULL on failure; a caller that only
       inspects *path would otherwise follow an uninitialised pointer. */
    if (!path || !portable_dir_w(local,MAX_PATH)) { if (path) *path=NULL; return E_FAIL; }
    bytes=((SIZE_T)lstrlenW(local)+1)*sizeof(WCHAR);
    copy=(PWSTR)CoTaskMemAlloc(bytes);
    if (!copy) { *path=NULL; return E_OUTOFMEMORY; }
    CopyMemory(copy,local,bytes); *path=copy;
    return S_OK;
}

HMODULE WINAPI Guard_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) {
    if (!local_path(name)) { SetLastError(ERROR_ACCESS_DENIED); return NULL; }
    /* Missing optional web components must remain missing; a fake handle would
       let legacy code call absent wke/COM exports through a null pointer.
       Match the module name on its own and as a whole: "node.dll" must not
       pick up "notanode.dll", and "mshtml" must not pick up "mshtmlful.dll". */
    if (module_named(name,L"node.dll") || module_named(name,L"mshtml") ||
        module_named(name,L"msxml") || module_named(name,L"ieframe")) {
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

/* Dynamic resolution must not bypass the guarded kernel/shell/COM exports.
   This table is the single source of truth for what hcg intercepts; build.py's
   check_policy_parity() asserts it matches the GUARDS table, so a name added
   there and missing here (or the reverse) fails the build instead of silently
   opening a hole. */
static const char *const GUARDED_EXPORTS[] = {
    "LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW",
    "GetProcAddress",
    "ShellExecuteA","ShellExecuteW","ShellExecuteExW","ShellExecuteExA",
    "CreateProcessA","CreateProcessW","WinExec",
    "OpenServiceW",
    "CoCreateInstance","CoGetClassObject","CLSIDFromProgID",
    "CreateFileA","CreateFileW",
    "GetFileAttributesA","GetFileAttributesW",
    "FindFirstFileA","FindFirstFileW","FindFirstFileExA","FindFirstFileExW",
    "SHGetFolderPathA","SHGetFolderPathW",
    "SHGetSpecialFolderPathA","SHGetSpecialFolderPathW","SHGetKnownFolderPath",
    "GetTempPathW","GetTempPathA",
    "RegSetValueExW","RegSetValueExA","SHSetValueW","SHSetValueA",
    "GetCommandLineW","GetCommandLineA",
    "Shell_NotifyIconW","Shell_NotifyIconA",
};
static BOOL guarded_export(LPCSTR name) {
    unsigned i;
    for (i = 0; i < sizeof(GUARDED_EXPORTS)/sizeof(GUARDED_EXPORTS[0]); ++i)
        if (lstrcmpA(name, GUARDED_EXPORTS[i]) == 0) return TRUE;
    return FALSE;
}

FARPROC WINAPI Guard_GetProcAddress(HMODULE module, LPCSTR name) {
    WCHAR path[1024]; DWORD n; HMODULE guard, net; FARPROC proc;
    /* A truncated module name would let network_module() read past the
       buffer, so treat truncation as "not a network module" and reject. */
    n = GetModuleFileNameW(module, path, 1024);
    if (n && n < 1024 && network_module(path)) {
        if ((ULONG_PTR)name <= 0xffff) { SetLastError(ERROR_PROC_NOT_FOUND); return NULL; }
        net = net_stub();
        return net ? GetProcAddress(net, name) : NULL;
    }
    /* Dynamic resolution must not bypass guarded kernel/shell/COM exports. */
    if ((ULONG_PTR)name > 0xffff && guarded_export(name)) {
        guard = self_module;
        proc = GetProcAddress(guard, name);
        if (!proc) SetLastError(ERROR_PROC_NOT_FOUND);
        return proc;
    }
    return GetProcAddress(module, name);
}

static BOOL shell_name(LPCWSTR file) {
    LPCWSTR first, end, leaf, p;
    if (!file || !*file) return FALSE;
    first = file;
    end = file + lstrlenW(file);
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

/* SIGDN_DESKTOPABSOLUTEPARSING, spelled out because it lives in shobjidl.h.
   This is the name the shell itself uses to locate an item. */
#define GUARD_SIGDN_PARSING 0x80028000u
/* Resolve a SEE_MASK_IDLIST request to a wide string the rules can judge.
   A shell-namespace item has no filesystem path at all -- SHGetPathFromIDListW
   fails for it by design -- so refusing the request on that basis turns
   "open Recycle Bin" into the shell's choose-an-app dialog. Take the parsing
   name instead: for a share it starts with \\ and local_path() still refuses
   it, and for a namespace item it starts with ::{ and is judged as one. */
static BOOL idlist_target(LPCVOID pidl, WCHAR *buf, DWORD count, LPCWSTR *out) {
    PWSTR owned = NULL;
    DWORD n;
    if (!pidl) return FALSE;
    if (SHGetPathFromIDListW((LPCITEMIDLIST)pidl, buf)) { *out = buf; return TRUE; }
    if (FAILED(SHGetNameFromIDList((LPCITEMIDLIST)pidl, GUARD_SIGDN_PARSING, &owned)) || !owned)
        return FALSE;
    n = (DWORD)lstrlenW(owned);
    if (n >= count) { CoTaskMemFree(owned); return FALSE; }
    CopyMemory(buf, owned, n * sizeof(WCHAR));
    buf[n] = 0;
    CoTaskMemFree(owned);
    *out = buf;
    return TRUE;
}

static BOOL shell_target(LPCWSTR file, LPCWSTR args, LPCWSTR dir) {
    WCHAR raw[1024]; LPCWSTR path, p;
    if (!unwrap_path(file, raw, 1024, &path)) return FALSE;
    if (!shell_name(path) || !local_path(path) || !local_path(dir) || remote(args)) return FALSE;
    if (shell_namespace(path)) {
        /* A namespace item carries no drive letter, so the rule below cannot
           be applied to it as written -- but it is what stops URLs. Test the
           remainder instead of the whole string. */
        for (p = path + 2; *p; ++p) if (*p == L':') return FALSE;
    } else {
        for (p = path; *p; ++p)
            if (*p == L':' && p != path + 1 &&
                !(p == path + 5 && path[0] == L'\\' && path[1] == L'\\')) return FALSE;
    }
    /* A domain-shaped name can be an ordinary local file or directory.
       Reject schemeless addresses only at the shell boundary when no such
       local target exists; never reject filesystem access merely for www. */
    if ((contains(path,L"www.") || contains(path,L".com") || contains(path,L".cn") ||
         contains(path,L".net") || contains(path,L".org")) &&
        GetFileAttributesW(path)==INVALID_FILE_ATTRIBUTES) return FALSE;
    /* Browser shortcuts can hide a URL outside the command line. */
    if (contains(path, L".url") || contains(path, L".website") || contains(path, L".hta")) return FALSE;
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
    WCHAR pidl_path[MAX_PATH]; LPCWSTR resolved, target=NULL;
    if(info) {
        if(info->fMask & SEE_MASK_IDLIST) {
            if(idlist_target(info->lpIDList, pidl_path, MAX_PATH, &resolved)) target=resolved;
        } else target=info->lpFile;
    }
    if (!info || !shell_target(target, info->lpParameters, info->lpDirectory)) {
        if (info) { info->hInstApp=(HINSTANCE)SE_ERR_ACCESSDENIED; info->hProcess=NULL; }
        SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    return ShellExecuteExW(info);
}
BOOL WINAPI Guard_ShellExecuteExA(SHELLEXECUTEINFOA *info) {
    WCHAR f[1024], a[1024], d[1024];
    BOOL file_ok=FALSE; LPCWSTR resolved, target=NULL;
    if(info) {
        if(info->fMask & SEE_MASK_IDLIST) {
            file_ok=idlist_target(info->lpIDList, f, 1024, &resolved);
            if(file_ok) target=resolved;
        } else {
            file_ok=wide(info->lpFile,f,1024);
            if(file_ok) target=f;
        }
    }
    if (!info || !file_ok ||
        !wide(info->lpParameters,a,1024) || !wide(info->lpDirectory,d,1024) ||
        !shell_target(target,a,d)) {
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
    WCHAR raw[1024]; LPCWSTR subject, chosen = app && *app ? app : cmd;
    if (!chosen || !*chosen) return TRUE;
    if (!unwrap_path(chosen, raw, 1024, &subject)) return FALSE;
    /* A component disabled by stub_component_names becomes spaces. The shell
       guards already refuse that leaf; letting it through here would reach
       Windows and raise its own "file not found" dialog. */
    if (!visible_leaf(subject)) return FALSE;
    if (remote(subject)) return FALSE;
    if (!local_path(subject)) return FALSE;
    if (contains(subject, L"iexplore") || contains(subject, L"msedge") ||
        contains(subject, L"chrome") || contains(subject, L"firefox") ||
        contains(subject, L"browser") || contains(subject, L"opera") ||
        contains(subject, L"webkit")) return FALSE;
    return TRUE;
}

/* The program index lists every package Get-AppxPackage reports, including
   packages that register only a shell extension -- share target, print dialog,
   context menu. Their manifest still declares an Application element, but
   marks it AppListEntry="none", so Windows never starts it as a program and no
   AppsFolder id resolves: the entry looks like a program, and activating it
   does nothing. Keep the enumeration to applications Windows would really
   start, rather than hiding the symptom at launch time. A package whose
   manifest cannot be read is kept, so an unreadable file can never remove a
   real program from the index. */
static const WCHAR APPX_FILTER[] =
    L" | Where-Object { $i=$_.InstallLocation; if(-not $i){return $true};"
    L"$m=Join-Path $i 'AppxManifest.xml';"
    L"try{$r=(Get-Content -LiteralPath $m -Raw) -replace '(?s)<!--.*?-->','';"
    L"$t=[regex]::Matches($r,'<Application[\\s/>]').Count;"
    L"$n=[regex]::Matches($r,'AppListEntry\\s*=\\s*\\u0022none\\u0022').Count;"
    L"return $t -gt $n}catch{return $true} }";
/* The filter reaches powershell inside a command line, so it must not carry a
   double quote of its own: the shell keeps or drops them depending on how the
   line was quoted, and a dropped one turns the pattern into a parse error.
   " is the regex escape for the same character and survives every
   quoting rule unchanged, so the pattern uses that instead. */
#define APPX_CMD_CAP 4096

/* Offset of the first case-insensitive occurrence of token, or (DWORD)-1. */
static DWORD text_offset(LPCWSTR text, LPCWSTR token) {
    DWORD i, j;
    if (!text || !token) return (DWORD)-1;
    for (i = 0; text[i]; ++i) {
        for (j = 0; token[j] && text[i+j] && lower(text[i+j]) == lower(token[j]); ++j) {}
        if (!token[j]) return i;
    }
    return (DWORD)-1;
}
/* Extends an app-list enumeration with the filter above. FALSE means the
   command is something else, or too long to extend: the caller then runs its
   own command unchanged, which is always correct behaviour. */
static BOOL appx_filter_command(LPCWSTR cmd, WCHAR *out, DWORD count) {
    static const WCHAR token[] = L"Get-AppxPackage";
    DWORD cut, len, extra;
    if (!cmd || !out || count < 32) return FALSE;
    cut = text_offset(cmd, token);
    if (cut == (DWORD)-1) return FALSE;
    cut += sizeof(token)/sizeof(token[0]) - 1;
    len = lstrlenW(cmd);
    extra = lstrlenW(APPX_FILTER);
    if (len + extra >= count) return FALSE;
    CopyMemory(out, cmd, cut*sizeof(WCHAR));
    CopyMemory(out+cut, APPX_FILTER, extra*sizeof(WCHAR));
    CopyMemory(out+cut+extra, cmd+cut, (len-cut+1)*sizeof(WCHAR));
    return TRUE;
}

BOOL WINAPI Guard_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    WCHAR filtered[APPX_CMD_CAP];
    (void)pa; (void)ta; (void)inherit; (void)flags; (void)env; (void)dir; (void)si; (void)pi;
    if (!spawn_target(app, cmd)) { SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    if (appx_filter_command(cmd, filtered, APPX_CMD_CAP)) cmd = filtered;
    return CreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}
BOOL WINAPI Guard_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir,
    LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi) {
    WCHAR a[1024], c[APPX_CMD_CAP], filtered[APPX_CMD_CAP]; CHAR out[APPX_CMD_CAP*2];
    (void)pa; (void)ta; (void)inherit; (void)flags; (void)env; (void)dir; (void)si; (void)pi;
    if (!wide(app,a,1024) || !wide(cmd,c,APPX_CMD_CAP) || !spawn_target(a,c)) {
        SetLastError(ERROR_ACCESS_DENIED); return FALSE;
    }
    if (appx_filter_command(c, filtered, APPX_CMD_CAP) &&
        WideCharToMultiByte(CP_ACP,0,filtered,-1,out,sizeof(out),NULL,NULL))
        return CreateProcessA(app, out, pa, ta, inherit, flags, env, dir, si, pi);
    return CreateProcessA(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}
UINT WINAPI Guard_WinExec(LPCSTR cmd, UINT show) {
    WCHAR c[APPX_CMD_CAP], filtered[APPX_CMD_CAP]; CHAR out[APPX_CMD_CAP*2];
    if (!wide(cmd,c,APPX_CMD_CAP) || !spawn_target(c,c)) { SetLastError(ERROR_ACCESS_DENIED); return 0; }
    if (appx_filter_command(c, filtered, APPX_CMD_CAP) &&
        WideCharToMultiByte(CP_ACP,0,filtered,-1,out,sizeof(out),NULL,NULL)) return WinExec(out,show);
    return WinExec(cmd, show);
}

LSTATUS WINAPI Guard_RegSetValueExW(HKEY key,LPCWSTR name,DWORD reserved,DWORD type,const BYTE *data,DWORD bytes) {
    WCHAR dir[STARTUP_CAP],command[STARTUP_CAP],value[STARTUP_CAP]={0};
    if(name && !lstrcmpiW(name,L"HuoChat") && type==REG_SZ && data && bytes>=2 && bytes%2==0 &&
       bytes<sizeof(value) && IsStartupKey(key)) {
        CopyMemory(value,data,bytes); /* The original SHSetValueW omits the NUL. */
        if(!module_dir(self_module,dir,STARTUP_CAP)) return ERROR_BUFFER_OVERFLOW;
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
