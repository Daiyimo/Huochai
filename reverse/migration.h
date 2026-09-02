#ifndef HUOCHAT_MIGRATION_H
#define HUOCHAT_MIGRATION_H
#include "portable.h"

typedef struct { LPCWSTR oldname,newname; WCHAR from[PATH_CAP],to[PATH_CAP]; BOOL exists,moved,prune; } DataMove;
typedef struct { HANDLE *items; size_t used,capacity; } MigrationLocks;

/* Every name in the migration table is relative to this payload root. Reject
   reparse points in ancestors and visited children before any directory move. */
static BOOL PlainPath(LPCWSTR path) {
    WCHAR copy[PATH_CAP]; DWORD i,attributes,error;
    if(FAILED(StringCchCopyW(copy,PATH_CAP,path)) || copy[1]!=L':') { SetLastError(ERROR_BAD_PATHNAME); return FALSE; }
    for(i=3;;i++) if(!copy[i] || copy[i]==L'\\') {
        WCHAR saved=copy[i]; copy[i]=0;
        attributes=GetFileAttributesW(copy); error=GetLastError(); copy[i]=saved;
        if(attributes!=INVALID_FILE_ATTRIBUTES && (attributes&FILE_ATTRIBUTE_REPARSE_POINT)) { SetLastError(ERROR_REPARSE_TAG_INVALID); return FALSE; }
        if(attributes==INVALID_FILE_ATTRIBUTES && error!=ERROR_FILE_NOT_FOUND && error!=ERROR_PATH_NOT_FOUND) { SetLastError(error); return FALSE; }
        if(!saved) return TRUE;
    }
}

static BOOL HoldTree(LPCWSTR path,MigrationLocks *locks) {
    DWORD attributes=GetFileAttributesW(path); HANDLE file,find; WIN32_FIND_DATAW entry;
    WCHAR pattern[PATH_CAP],child[PATH_CAP]; DWORD error;
    if(attributes==INVALID_FILE_ATTRIBUTES) return FALSE;
    if(attributes&FILE_ATTRIBUTE_REPARSE_POINT) { SetLastError(ERROR_REPARSE_TAG_INVALID); return FALSE; }
    if(attributes&FILE_ATTRIBUTE_DIRECTORY) {
        if(FAILED(StringCchPrintfW(pattern,PATH_CAP,L"%s\\*",path))) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
        find=FindFirstFileW(pattern,&entry);
        if(find==INVALID_HANDLE_VALUE) return GetLastError()==ERROR_FILE_NOT_FOUND;
        do {
            if(!lstrcmpW(entry.cFileName,L".") || !lstrcmpW(entry.cFileName,L"..")) continue;
            if(FAILED(StringCchPrintfW(child,PATH_CAP,L"%s\\%s",path,entry.cFileName)) || !HoldTree(child,locks)) {
                error=GetLastError(); FindClose(find); SetLastError(error); return FALSE;
            }
        } while(FindNextFileW(find,&entry));
        error=GetLastError(); FindClose(find);
        if(error!=ERROR_NO_MORE_FILES) { SetLastError(error); return FALSE; }
        return TRUE;
    }
    /* Detect active writers during preflight. Windows directory renames cannot
       proceed while our own child-file handles remain open. */
    file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
    if(file==INVALID_HANDLE_VALUE) return FALSE;
    if(locks->used==locks->capacity) {
        size_t capacity=locks->capacity ? locks->capacity*2:256; HANDLE *items;
        if(capacity>65536) { CloseHandle(file); SetLastError(ERROR_TOO_MANY_OPEN_FILES); return FALSE; }
        items=locks->items ? (HANDLE*)HeapReAlloc(GetProcessHeap(),0,locks->items,capacity*sizeof(HANDLE)):
                            (HANDLE*)HeapAlloc(GetProcessHeap(),0,capacity*sizeof(HANDLE));
        if(!items) { CloseHandle(file); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        locks->items=items; locks->capacity=capacity;
    }
    locks->items[locks->used++]=file; return TRUE;
}

/* Windows can recreate empty profile/cache directories after a migration.
   Only known app directories may be pruned, and RemoveDirectory never deletes
   files even if another process creates one between the check and removal. */
static BOOL EmptyTree(LPCWSTR path,BOOL remove) {
    DWORD attr=GetFileAttributesW(path),error; HANDLE find; WIN32_FIND_DATAW entry;
    WCHAR pattern[PATH_CAP],child[PATH_CAP];
    if(attr==INVALID_FILE_ATTRIBUTES) return FALSE;
    if((attr&FILE_ATTRIBUTE_REPARSE_POINT) || !(attr&FILE_ATTRIBUTE_DIRECTORY)) {
        SetLastError(ERROR_DIR_NOT_EMPTY); return FALSE;
    }
    if(FAILED(StringCchPrintfW(pattern,PATH_CAP,L"%s\\*",path))) return FALSE;
    find=FindFirstFileW(pattern,&entry);
    if(find!=INVALID_HANDLE_VALUE) {
        do {
            if(!lstrcmpW(entry.cFileName,L".") || !lstrcmpW(entry.cFileName,L"..")) continue;
            if(FAILED(StringCchPrintfW(child,PATH_CAP,L"%s\\%s",path,entry.cFileName)) || !EmptyTree(child,remove)) {
                error=GetLastError(); FindClose(find); SetLastError(error); return FALSE;
            }
        } while(FindNextFileW(find,&entry));
        error=GetLastError(); FindClose(find);
        if(error!=ERROR_NO_MORE_FILES) { SetLastError(error); return FALSE; }
    } else if(GetLastError()!=ERROR_FILE_NOT_FOUND) return FALSE;
    return remove ? RemoveDirectoryW(path):TRUE;
}

static BOOL PrepareData(LPCWSTR dir) {
    DataMove moves[]={
        {L"user data",L"Data\\User"}, {L"HuoChatIndex",L"Data\\Index"},
        {L"Everything.ini",L"Data\\Index.ini"}, {L"site.db",L"Data\\Sites.db"},
        {L"HuoChat",L"Data\\HuoChat"}, {L"Temp",L"Data\\Temp"},
        {L"Tencent",L"Data\\Apps\\Tencent"}, {L"BRD",L"Data\\Apps\\BRD"},
        {L"claude-cli-nodejs",L"Data\\Apps\\claude-cli-nodejs"},
        {L"uv",L"Data\\Apps\\uv"}, {L"Microsoft",L"Data\\Apps\\Microsoft"},
        {L"NVIDIA",L"Data\\Apps\\NVIDIA"},
        {L"offline.log",L"Data\\previous-offline.log"}, {L"offline.log.1",L"Data\\previous-offline.log.1"},
        {L"Everything.db",L"Data\\Index\\Everything.db"}
    };
    WCHAR path[PATH_CAP],root[PATH_CAP],recovery[PATH_CAP]={0},record[PATH_CAP];
    size_t i,j; DWORD error=0,n; BOOL ok=FALSE,established=FALSE,archive_cache=FALSE;
    MigrationLocks locks={0}; const size_t count=sizeof(moves)/sizeof(moves[0]);
    n=GetFullPathNameW(dir,PATH_CAP,root,NULL);
    if(!n || n>=PATH_CAP-1) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    if(root[n-1]!=L'\\') { root[n++]=L'\\'; root[n]=0; }
    dir=root; /* Fixed relative targets now resolve beneath this canonical root. */
    if(!PlainPath(dir) || !JoinPath(path,PATH_CAP,dir,L"Data") || !PlainPath(path) || !EnsureDirectory(path)) return FALSE;
    if(!JoinPath(log_path,PATH_CAP,dir,L"Data\\offline.log")) return FALSE;
    if(!JoinPath(path,PATH_CAP,dir,L"Data\\Apps") || !PlainPath(path) || !EnsureDirectory(path)) return FALSE;
    /* Version .1 could regenerate default root files after a successful move.
       An established layout keeps its canonical settings/cache. Archive those
       stray files together without merging, overwriting, or deleting either. */
    if(!JoinPath(path,PATH_CAP,dir,L"Data\\layout.ini") || !PlainPath(path)) return FALSE;
    if(GetPrivateProfileStringW(L"Layout",L"root",L"",record,PATH_CAP,path)) {
        DWORD attr;
        if(!JoinPath(path,PATH_CAP,dir,L"Data\\Index.ini") || !PlainPath(path)) return FALSE;
        attr=GetFileAttributesW(path);
        established=attr!=INVALID_FILE_ATTRIBUTES && !(attr&FILE_ATTRIBUTE_DIRECTORY);
    }
    if(established) {
        BOOL stray=FALSE; SYSTEMTIME now;
        if(!JoinPath(path,PATH_CAP,dir,L"Data\\Index\\Everything.db") || !PlainPath(path)) return FALSE;
        archive_cache=GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES;
        for(i=0;i<2;i++) {
            if(!JoinPath(path,PATH_CAP,dir,i ? L"Everything.db":L"Everything.ini")) return FALSE;
            if(GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES) stray=TRUE;
        }
        if(stray) {
            if(!JoinPath(path,PATH_CAP,dir,L"Data\\Recovery") || !PlainPath(path) || !EnsureDirectory(path)) return FALSE;
            GetLocalTime(&now);
            if(FAILED(StringCchPrintfW(recovery,PATH_CAP,L"%s\\engine-%04u%02u%02u-%02u%02u%02u-%lu-%llu",
                path,now.wYear,now.wMonth,now.wDay,now.wHour,now.wMinute,now.wSecond,GetCurrentProcessId(),GetTickCount64())) ||
                !PlainPath(recovery) || !CreateDirectoryW(recovery,NULL)) return FALSE;
        }
    }
    for(i=0;i<count;i++) {
        DWORD attr;
        if(!JoinPath(moves[i].from,PATH_CAP,dir,moves[i].oldname) || !JoinPath(moves[i].to,PATH_CAP,dir,moves[i].newname)) { error=GetLastError(); goto done; }
        if(recovery[0] && (i==2 || (i==14 && archive_cache)) && FAILED(StringCchPrintfW(moves[i].to,PATH_CAP,L"%s\\%s",recovery,moves[i].oldname))) {
            error=ERROR_FILENAME_EXCED_RANGE; goto done;
        }
        attr=GetFileAttributesW(moves[i].from);
        if(attr==INVALID_FILE_ATTRIBUTES) {
            error=GetLastError();
            if(error!=ERROR_FILE_NOT_FOUND && error!=ERROR_PATH_NOT_FOUND) goto done;
            continue;
        }
        moves[i].exists=TRUE;
        if(((i==0 || i==1 || (i>=4 && i<=11)) ? TRUE:FALSE)!=((attr&FILE_ATTRIBUTE_DIRECTORY)!=0)) {
            error=ERROR_DIRECTORY; LogEvent(moves[i].from,error); goto done;
        }
        if(!PlainPath(moves[i].from) || !PlainPath(moves[i].to)) { error=GetLastError(); goto done; }
        if(GetFileAttributesW(moves[i].to)!=INVALID_FILE_ATTRIBUTES) {
            if(i>=6 && i<=11 && (GetFileAttributesW(moves[i].to)&FILE_ATTRIBUTE_DIRECTORY) && EmptyTree(moves[i].from,FALSE)) {
                moves[i].prune=TRUE; continue;
            }
            error=ERROR_ALREADY_EXISTS; LogEvent(moves[i].to,error); goto done;
        }
        error=GetLastError(); if(error!=ERROR_FILE_NOT_FOUND && error!=ERROR_PATH_NOT_FOUND) goto done;
        if(!HoldTree(moves[i].from,&locks)) { error=GetLastError(); LogEvent(moves[i].from,error); goto done; }
    }
    for(i=0;i<locks.used;i++) CloseHandle(locks.items[i]);
    locks.used=0;
    for(i=0;i<count;i++) if(moves[i].exists) {
        if(moves[i].prune) {
            if(!EmptyTree(moves[i].from,TRUE)) { error=GetLastError(); goto rollback; }
            continue;
        }
        if(i==14 && !(recovery[0] && archive_cache)) {
            if(!JoinPath(path,PATH_CAP,dir,L"Data\\Index") || !PlainPath(path) || !EnsureDirectory(path)) {
                error=GetLastError(); goto rollback;
            }
        }
        /* No copy/delete fallback, replacement, merging or cross-volume moves. */
        if(!MoveFileExW(moves[i].from,moves[i].to,MOVEFILE_WRITE_THROUGH)) {
            error=GetLastError(); LogEvent(moves[i].from,error);
rollback:
            for(j=i;j>0;j--) if(moves[j-1].moved && !MoveFileExW(moves[j-1].to,moves[j-1].from,MOVEFILE_WRITE_THROUGH))
                LogEvent(L"迁移回退失败，请保留新旧目录并查看迁移记录",GetLastError());
            goto done;
        }
        moves[i].moved=TRUE;
        LogEvent(moves[i].to,0);
    }
    ok=TRUE;
done:
    for(i=0;i<locks.used;i++) CloseHandle(locks.items[i]);
    if(locks.items) HeapFree(GetProcessHeap(),0,locks.items);
    if(!ok) { LogEvent(L"数据整理未完成：请退出火柴及由其启动的程序，检查重名目录或文件占用后重试",error); SetLastError(error); }
    return ok;
}
#endif
