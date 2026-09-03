#ifndef HUOCHAT_BACKEND_H
#define HUOCHAT_BACKEND_H
#include "portable.h"

typedef struct {
    BOOL modern;
    WCHAR root[PATH_CAP],exe[PATH_CAP],index[PATH_CAP],config[PATH_CAP],database[PATH_CAP];
    WCHAR instance[64],service[64],window[128],pipe[128];
} BackendPaths;

static BOOL SameBackendFile(LPCWSTR first,LPCWSTR second) {
    WCHAR a[PATH_CAP],b[PATH_CAP];DWORD na=GetLongPathNameW(first,a,PATH_CAP),nb=GetLongPathNameW(second,b,PATH_CAP);
    return !lstrcmpiW(na && na<PATH_CAP ? a:first,nb && nb<PATH_CAP ? b:second);
}

static BOOL BackendFromDirectory(BackendPaths *out,LPCWSTR dir) {
    WCHAR full[PATH_CAP],longname[PATH_CAP];DWORD n;size_t i;ULONGLONG hash=14695981039346656037ULL;
    ZeroMemory(out,sizeof(*out));n=GetFullPathNameW(dir,PATH_CAP,full,NULL);
    if(!n || n>=PATH_CAP)return FALSE;
    n=GetLongPathNameW(full,longname,PATH_CAP);
    if(n && n<PATH_CAP)StringCchCopyW(full,PATH_CAP,longname);
    n=lstrlenW(full);while(n>3 && full[n-1]==L'\\')full[--n]=0;
    StringCchCopyW(out->root,PATH_CAP,full);
    if(!JoinPath(out->exe,PATH_CAP,full,L"Engine\\Everything.exe"))return FALSE;
    out->modern=GetFileAttributesW(out->exe)!=INVALID_FILE_ATTRIBUTES;
    if(!out->modern) {
        JoinPath(out->exe,PATH_CAP,full,L"hc_engine.exe");
        JoinPath(out->index,PATH_CAP,full,L"Data\\Index");
        JoinPath(out->config,PATH_CAP,full,L"Data\\Index.ini");
        StringCchCopyW(out->service,64,L"Everything");
        StringCchCopyW(out->window,128,L"EVERYTHING_TASKBAR_NOTIFICATION");
    } else {
        /* Stable, case-insensitive identity shared by the launcher, broker,
           SDK bridge and service routing. No environment-controlled instance. */
        LCMapStringW(LOCALE_INVARIANT,LCMAP_LOWERCASE,full,-1,longname,PATH_CAP);
        for(i=0;longname[i];i++){hash^=(WORD)longname[i];hash*=1099511628211ULL;}
        StringCchPrintfW(out->instance,64,L"HuoChat15-%016I64x",hash);
        StringCchCopyW(out->service,64,out->instance);
        StringCchPrintfW(out->window,128,L"EVERYTHING_TASKBAR_NOTIFICATION_(%s)",out->instance);
        StringCchPrintfW(out->pipe,128,L"\\\\.\\PIPE\\%s",out->instance);
        JoinPath(out->index,PATH_CAP,full,L"Data\\Index-1.5");
        JoinPath(out->config,PATH_CAP,out->index,L"Index.ini");
    }
    return JoinPath(out->database,PATH_CAP,out->index,L"Everything.db");
}
static BOOL BackendFromModule(BackendPaths *out,HMODULE module) {
    WCHAR path[PATH_CAP];DWORD n=GetModuleFileNameW(module,path,PATH_CAP);
    if(!n || n>=PATH_CAP)return FALSE;
    while(n && path[n-1]!=L'\\')--n;if(!n)return FALSE;path[n]=0;
    return BackendFromDirectory(out,path);
}
static BOOL WriteBackendPolicy(const BackendPaths *paths) {
    WCHAR dir[PATH_CAP],file[PATH_CAP],temporary[PATH_CAP],wide[2048];CHAR value[4096],old[4096];
    HANDLE handle;DWORD size,wrote;int bytes;BOOL ok;
    if(!JoinPath(dir,PATH_CAP,paths->root,L"Engine") || !JoinPath(file,PATH_CAP,dir,L"Everything.ini"))return FALSE;
    StringCchPrintfW(wide,2048,L"[Everything]\r\nservice_name=%s\r\nallow_check_for_updates=0\r\n"
        L"allow_http_server=0\r\nallow_etp_server=0\r\nallow_plugins=0\r\nallow_connect_to_etp_server=0\r\n"
        L"allow_url_protocol=0\r\nallow_efu_association=0\r\n",paths->service);
    bytes=WideCharToMultiByte(CP_UTF8,0,wide,-1,value,sizeof(value),NULL,NULL);if(!bytes)return FALSE;bytes--;
    handle=CreateFileW(file,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(handle!=INVALID_HANDLE_VALUE) {
        ok=ReadFile(handle,old,sizeof(old),&size,NULL);CloseHandle(handle);
        if(ok && size==(DWORD)bytes && !memcmp(old,value,bytes))return TRUE;
    }
    if(!GetTempFileNameW(dir,L"hce",0,temporary))return FALSE;
    handle=CreateFileW(temporary,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(handle==INVALID_HANDLE_VALUE){DeleteFileW(temporary);return FALSE;}
    ok=WriteFile(handle,value,bytes,&wrote,NULL) && wrote==(DWORD)bytes && FlushFileBuffers(handle);
    CloseHandle(handle);
    if(ok)ok=MoveFileExW(temporary,file,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);
    if(!ok){DWORD error=GetLastError();DeleteFileW(temporary);SetLastError(error);}return ok;
}
static BOOL PrepareBackend(const BackendPaths *paths) {
    WCHAR seed[PATH_CAP];
    const IniSetting settings[]={
        {L"run_as_admin",L"0",FALSE},{L"run_in_background",L"1",FALSE},
        {L"db_multi_user_filename",L"0",FALSE},{L"session_store",L"0",FALSE},
        {L"service_pipe_name",paths->pipe,FALSE},{L"allow_plugins",L"0",FALSE},
        {L"auto_include_remote_volumes",L"0",FALSE}
    };
    if(!paths->modern)return TRUE;
    /* This INI value is a literal pipe path. The CLI -service-pipe-name is an
       install/configuration action and exits instead of starting a client. */
    if(!EnsureDirectory(paths->index))return FALSE;
    if(GetFileAttributesW(paths->config)==INVALID_FILE_ATTRIBUTES) {
        if(!JoinPath(seed,PATH_CAP,paths->root,L"Data\\Index.ini") || !CopyFileW(seed,paths->config,TRUE))return FALSE;
    }
    /* Copy preferences once; never hand a 1.4 DB to 1.5 or modify it for rollback. */
    return UpdateConfigurationFile(paths->index,paths->index,L"Index.ini",settings,sizeof(settings)/sizeof(settings[0])) && WriteBackendPolicy(paths);
}
#endif
