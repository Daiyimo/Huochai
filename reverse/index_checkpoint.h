#ifndef HUOCHAT_INDEX_CHECKPOINT_H
#define HUOCHAT_INDEX_CHECKPOINT_H
#include "portable.h"
#include "backend.h"

/* Public Everything IPC: WM_USER / IS_DB_LOADED=401 / SAVE_DB=407.
   SAVE_DB is posted, never synchronously awaited on the launcher exit path.
   The pinned engine writes Everything.db.tmp before replacing Everything.db. */
#ifndef HC_CHECKPOINT_INTERVAL_MS
#define HC_CHECKPOINT_INTERVAL_MS 300000
#endif
#ifndef HC_CHECKPOINT_RETRY_MS
#define HC_CHECKPOINT_RETRY_MS 30000
#endif
#ifndef HC_CHECKPOINT_SAVE_WAIT_MS
#define HC_CHECKPOINT_SAVE_WAIT_MS 60000
#endif
typedef struct {
    BOOL exists;
    FILETIME write;
    DWORD high,low;
} IndexStamp;
typedef struct {
    DWORD pid;
    HWND window;
    WCHAR database[PATH_CAP],temporary[PATH_CAP];
    ULONGLONG next,requested;
    BOOL pending;
    IndexStamp before,working;
} IndexCheckpoint;

static IndexStamp ReadIndexStamp(LPCWSTR path) {
    WIN32_FILE_ATTRIBUTE_DATA data;IndexStamp result={0};
    if(GetFileAttributesExW(path,GetFileExInfoStandard,&data) &&
       !(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) && (data.nFileSizeHigh || data.nFileSizeLow)) {
        result.exists=TRUE;result.write=data.ftLastWriteTime;
        result.high=data.nFileSizeHigh;result.low=data.nFileSizeLow;
    }
    return result;
}
static BOOL SameIndexStamp(IndexStamp a,IndexStamp b) {
    return a.exists==b.exists && a.high==b.high && a.low==b.low &&
        CompareFileTime(&a.write,&b.write)==0;
}
/* A scratch file that only appeared, or was rewritten, after the request means
   the engine has not committed yet. A file left behind by an earlier cancelled
   run must never block confirmation, so it is compared with the snapshot. */
static BOOL IndexWriteInProgress(const IndexCheckpoint *state) {
    IndexStamp writing=ReadIndexStamp(state->temporary);
    return writing.exists && !SameIndexStamp(writing,state->working);
}
static BOOL CALLBACK FindCheckpointWindow(HWND window,LPARAM parameter) {
    IndexCheckpoint *state=(IndexCheckpoint*)parameter;DWORD pid=0;WCHAR name[128];
    const WCHAR prefix[]=L"EVERYTHING_TASKBAR_NOTIFICATION";
    GetWindowThreadProcessId(window,&pid);
    if(pid==state->pid && GetClassNameW(window,name,128) && !wcsncmp(name,prefix,wcslen(prefix))) {
        state->window=window;return FALSE;
    }
    return TRUE;
}
static void InitCheckpoint(IndexCheckpoint *state,HANDLE engine,LPCWSTR dir) {
    BackendPaths backend;
    ZeroMemory(state,sizeof(*state));state->pid=GetProcessId(engine);
    if(!BackendFromDirectory(&backend,dir) ||
       FAILED(StringCchCopyW(state->database,PATH_CAP,backend.database)) ||
       FAILED(StringCchPrintfW(state->temporary,PATH_CAP,L"%s.tmp",backend.database)))state->pid=0;
}
static BOOL CanReplaceIndex(LPCWSTR database) {
    HANDLE file;DWORD attributes=GetFileAttributesW(database);
    if(attributes==INVALID_FILE_ATTRIBUTES)return GetLastError()==ERROR_FILE_NOT_FOUND;
    if(attributes&(FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_DIRECTORY))return FALSE;
    /* Avoid asking the engine to show a save-error dialog for a known locked
       cache. The engine still owns the actual atomic write/replace operation. */
    file=CreateFileW(database,DELETE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
    if(file==INVALID_HANDLE_VALUE)return FALSE;
    CloseHandle(file);return TRUE;
}
static DWORD TickCheckpoint(IndexCheckpoint *state,HANDLE engine,HANDLE stopping) {
    ULONGLONG now=GetTickCount64();DWORD pid=0;DWORD_PTR loaded=0;
    if(!state->pid || WaitForSingleObject(stopping,0)==WAIT_OBJECT_0 ||
       WaitForSingleObject(engine,0)==WAIT_OBJECT_0)return INFINITE;
    if(now<state->next)return (DWORD)(state->next-now);
    state->next=now+1000;
    if(state->pending) {
        IndexStamp current=ReadIndexStamp(state->database);
        if(current.exists && !SameIndexStamp(current,state->before) && !IndexWriteInProgress(state)) {
            LogEvent(L"搜索索引缓存已保存",0);state->pending=FALSE;
            state->next=now+HC_CHECKPOINT_INTERVAL_MS;
        } else if(now-state->requested>=HC_CHECKPOINT_SAVE_WAIT_MS) {
            /* No new committed file: keep the old cache and retry. A successful
               IPC post alone does not prove that a database write completed. */
            LogEvent(L"本轮索引保存未确认，保留已有缓存并稍后重试",0);
            state->pending=FALSE;state->next=now+HC_CHECKPOINT_RETRY_MS;
        }
        return (DWORD)(state->next-now);
    }
    if(state->window)GetWindowThreadProcessId(state->window,&pid);
    if(pid!=state->pid) {state->window=NULL;EnumWindows(FindCheckpointWindow,(LPARAM)state);}
    if(!state->window)return 1000;
    if(!SendMessageTimeoutW(state->window,WM_USER,401,0,SMTO_ABORTIFHUNG|SMTO_BLOCK,100,&loaded) || !loaded)return 1000;
    GetWindowThreadProcessId(state->window,&pid);
    if(pid!=state->pid || WaitForSingleObject(stopping,0)==WAIT_OBJECT_0 ||
       WaitForSingleObject(engine,0)==WAIT_OBJECT_0)return 1000;
    if(!CanReplaceIndex(state->database)) {
        LogEvent(L"索引缓存暂时不可替换，保留原文件并稍后重试",0);
        state->next=now+HC_CHECKPOINT_RETRY_MS;return HC_CHECKPOINT_RETRY_MS;
    }
    state->before=ReadIndexStamp(state->database);
    state->working=ReadIndexStamp(state->temporary);
    if(PostMessageW(state->window,WM_USER,407,0)) {
        state->requested=now;state->pending=TRUE;
        LogEvent(L"已请求后台保存搜索索引",0);
    } else {
        LogEvent(L"无法请求保存搜索索引，将稍后重试",GetLastError());
        state->next=now+HC_CHECKPOINT_RETRY_MS;
    }
    return (DWORD)(state->next-now);
}
#endif
