#ifndef HUOCHAT_PORTABLE_H
#define HUOCHAT_PORTABLE_H
#include <strsafe.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

#define PATH_CAP 1024
static WCHAR log_path[PATH_CAP];

static BOOL JoinPath(WCHAR *out, size_t count, LPCWSTR dir, LPCWSTR name) {
    if (FAILED(StringCchPrintfW(out,count,L"%s%s%s",dir,
            dir[0] && dir[lstrlenW(dir)-1]==L'\\' ? L"" : L"\\",name))) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE); return FALSE;
    }
    return TRUE;
}

static void LogEvent(LPCWSTR message,DWORD error) {
    WCHAR line[2048], backup[PATH_CAP]; CHAR utf8[8192];
    HANDLE file; DWORD wrote; SYSTEMTIME time; LARGE_INTEGER size; int bytes;
    if (!log_path[0]) return;
    file=CreateFileW(log_path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if (file!=INVALID_HANDLE_VALUE) {
        BOOL rotate=GetFileSizeEx(file,&size) && size.QuadPart>262144;
        CloseHandle(file);
        if (rotate && SUCCEEDED(StringCchPrintfW(backup,PATH_CAP,L"%s.1",log_path)))
            MoveFileExW(log_path,backup,MOVEFILE_REPLACE_EXISTING);
    }
    GetLocalTime(&time);
    StringCchPrintfW(line,2048,L"%04u-%02u-%02u %02u:%02u:%02u %s (error=%lu)\r\n",
        time.wYear,time.wMonth,time.wDay,time.wHour,time.wMinute,time.wSecond,message,error);
    bytes=WideCharToMultiByte(CP_UTF8,0,line,-1,utf8,sizeof(utf8),NULL,NULL);
    if (!bytes) return;
    file=CreateFileW(log_path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (file==INVALID_HANDLE_VALUE) return;
    WriteFile(file,utf8,(DWORD)bytes-1,&wrote,NULL); CloseHandle(file);
}

static void ReportFailure(LPCWSTR message,DWORD error) {
    WCHAR text[2400], detail[512]={0};
    LogEvent(message,error);
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,NULL,error,0,detail,512,NULL);
    StringCchPrintfW(text,2400,L"%s\r\n\r\n系统错误 %lu：%s\r\n详情见 Data\\offline.log。",message,error,detail);
    MessageBoxW(NULL,text,L"火柴离线版",MB_OK|MB_ICONERROR);
}

static BOOL EnsureDirectory(LPCWSTR path) {
    DWORD attributes;
    if (CreateDirectoryW(path,NULL)) return TRUE;
    if (GetLastError()!=ERROR_ALREADY_EXISTS) return FALSE;
    attributes=GetFileAttributesW(path);
    if (attributes!=INVALID_FILE_ATTRIBUTES && (attributes&FILE_ATTRIBUTE_DIRECTORY)) return TRUE;
    SetLastError(ERROR_DIRECTORY); return FALSE;
}

typedef struct { LPCWSTR key; LPCWSTR value; BOOL seen; } IniSetting;

static BOOL AppendSetting(WCHAR *out,size_t capacity,IniSetting *item) {
    return SUCCEEDED(StringCchCatW(out,capacity,item->key)) &&
        SUCCEEDED(StringCchCatW(out,capacity,L"=")) &&
        SUCCEEDED(StringCchCatW(out,capacity,item->value)) &&
        SUCCEEDED(StringCchCatW(out,capacity,L"\r\n"));
}

static BOOL MissingSettings(WCHAR *out,size_t capacity,IniSetting *settings,size_t count) {
    size_t i;
    for(i=0;i<count;i++) if(!settings[i].seen) {
        if(!AppendSetting(out,capacity,&settings[i])) return FALSE;
        settings[i].seen=TRUE;
    }
    return TRUE;
}

/* Preserve local indexing preferences and unknown sections. Only the database
   location and mandatory offline settings are maintained by this launcher.
   The old file is never deleted before the complete replacement is flushed. */
static BOOL UpdateConfiguration(LPCWSTR dir,LPCWSTR index) {
    IniSetting settings[]={
        {L"db_location",index,FALSE},
        {L"show_tray_icon",L"0",FALSE}, {L"show_in_taskbar",L"0",FALSE},
        {L"check_for_updates_on_startup",L"0",FALSE}, {L"beta_updates",L"0",FALSE},
        {L"http_server_enabled",L"0",FALSE}, {L"etp_server_enabled",L"0",FALSE},
        {L"allow_http_server",L"0",FALSE}, {L"allow_etp_server",L"0",FALSE},
        {L"etp_server_allow_file_download",L"0",FALSE}, {L"http_server_allow_file_download",L"0",FALSE},
        {L"ftp_allow_port",L"0",FALSE}, {L"index_etp_server",L"",FALSE},
        {L"connect_history_hosts",L"",FALSE}, {L"connect_history_ports",L"",FALSE},
        {L"connect_history_usernames",L"",FALSE}
    };
    WCHAR ini[PATH_CAP], temporary[PATH_CAP]={0}, *input=NULL,*output=NULL,*cursor;
    BYTE *raw=NULL; CHAR *encoded=NULL; HANDLE file=INVALID_HANDLE_VALUE;
    DWORD length,received,error=ERROR_INVALID_DATA; int chars,bytes; size_t capacity,i;
    BOOL inside=FALSE,found=FALSE,ok=FALSE; const size_t count=sizeof(settings)/sizeof(settings[0]);
    if(!JoinPath(ini,PATH_CAP,dir,L"Index.ini")) return FALSE;
    file=CreateFileW(ini,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE) return FALSE;
    length=GetFileSize(file,NULL);
    if(length==INVALID_FILE_SIZE || length>4*1024*1024) goto done;
    raw=(BYTE*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(SIZE_T)length+2);
    if(!raw) { error=ERROR_NOT_ENOUGH_MEMORY; goto done; }
    if(!ReadFile(file,raw,length,&received,NULL) || received!=length) { error=GetLastError(); goto done; }
    CloseHandle(file); file=INVALID_HANDLE_VALUE;
    if(length>=2 && raw[0]==0xff && raw[1]==0xfe) {
        if(length%2) goto done;
        chars=(int)(length-2)/2;
        input=(WCHAR*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,((SIZE_T)chars+1)*sizeof(WCHAR));
        if(input) CopyMemory(input,raw+2,chars*sizeof(WCHAR));
    } else {
        DWORD offset=length>=3 && raw[0]==0xef && raw[1]==0xbb && raw[2]==0xbf ? 3:0;
        UINT page=CP_UTF8;
        chars=MultiByteToWideChar(page,MB_ERR_INVALID_CHARS,(LPCSTR)raw+offset,length-offset,NULL,0);
        if(!chars && length>offset) { page=CP_ACP; chars=MultiByteToWideChar(page,0,(LPCSTR)raw+offset,length-offset,NULL,0); }
        input=(WCHAR*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,((SIZE_T)chars+1)*sizeof(WCHAR));
        if(input && chars) MultiByteToWideChar(page,0,(LPCSTR)raw+offset,length-offset,input,chars);
    }
    capacity=(SIZE_T)chars+16384;
    output=(WCHAR*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,capacity*sizeof(WCHAR));
    if(!input || !output) { error=ERROR_NOT_ENOUGH_MEMORY; goto done; }
    if((size_t)lstrlenW(input)!=(size_t)chars) goto done; /* refuse embedded NULs */
    cursor=input;
    while(*cursor) {
        WCHAR *line=cursor,*end=wcschr(cursor,L'\n'),*trim,*equal; BOOL handled=FALSE;
        if(end) { *end=0; cursor=end+1; } else cursor+=lstrlenW(cursor);
        i=lstrlenW(line); if(i && line[i-1]==L'\r') line[i-1]=0;
        trim=line; while(*trim==L' ' || *trim==L'\t') trim++;
        if(*trim==L'[') {
            if(inside && !MissingSettings(output,capacity,settings,count)) goto done;
            inside=_wcsnicmp(trim,L"[Everything]",12)==0;
            if(inside) found=TRUE;
        } else if(inside && *trim!=L';' && *trim!=L'#' && (equal=wcschr(trim,L'='))) {
            WCHAR *keyend=equal; while(keyend>trim && (keyend[-1]==L' ' || keyend[-1]==L'\t')) keyend--;
            for(i=0;i<count;i++) if((size_t)(keyend-trim)==wcslen(settings[i].key) &&
                    !_wcsnicmp(trim,settings[i].key,keyend-trim)) {
                if(!settings[i].seen && !AppendSetting(output,capacity,&settings[i])) goto done;
                settings[i].seen=TRUE; handled=TRUE; break;
            }
        }
        if(!handled && (FAILED(StringCchCatW(output,capacity,line)) ||
                       FAILED(StringCchCatW(output,capacity,L"\r\n")))) goto done;
    }
    if(!found && FAILED(StringCchCatW(output,capacity,L"[Everything]\r\n"))) goto done;
    if(!MissingSettings(output,capacity,settings,count)) goto done;
    bytes=WideCharToMultiByte(CP_UTF8,0,output,-1,NULL,0,NULL,NULL);
    encoded=(CHAR*)HeapAlloc(GetProcessHeap(),0,bytes);
    if(!encoded) { error=ERROR_NOT_ENOUGH_MEMORY; goto done; }
    WideCharToMultiByte(CP_UTF8,0,output,-1,encoded,bytes,NULL,NULL); bytes--;
    if((DWORD)bytes==length && !memcmp(encoded,raw,length)) { ok=TRUE; goto done; }
    if(!GetTempFileNameW(dir,L"hci",0,temporary)) { error=GetLastError(); goto done; }
    file=CreateFileW(temporary,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE) { error=GetLastError(); goto done; }
    if(!WriteFile(file,encoded,bytes,&received,NULL) || received!=(DWORD)bytes || !FlushFileBuffers(file)) {
        error=GetLastError(); goto done;
    }
    CloseHandle(file); file=INVALID_HANDLE_VALUE;
    if(!MoveFileExW(temporary,ini,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) { error=GetLastError(); goto done; }
    temporary[0]=0; ok=TRUE;
done:
    if(file!=INVALID_HANDLE_VALUE) CloseHandle(file);
    if(temporary[0]) DeleteFileW(temporary);
    if(encoded) HeapFree(GetProcessHeap(),0,encoded);
    if(output) HeapFree(GetProcessHeap(),0,output);
    if(input) HeapFree(GetProcessHeap(),0,input);
    if(raw) HeapFree(GetProcessHeap(),0,raw);
    if(!ok) SetLastError(error);
    return ok;
}
#endif
