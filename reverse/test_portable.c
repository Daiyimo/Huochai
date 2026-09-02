#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "portable.h"
#define CHECK(x) do { if(!(x)) { printf("FAILED %d: %s (error=%lu)\n",__LINE__,#x,GetLastError()); return 1; } } while(0)

static BOOL WriteBytes(LPCWSTR path,const char *text) {
    DWORD n; HANDLE f=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    if(f==INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(f,text,(DWORD)strlen(text),&n,NULL); CloseHandle(f); return n==strlen(text);
}
static BOOL ReadBytes(LPCWSTR path,char *text,DWORD size) {
    DWORD n; HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(f==INVALID_HANDLE_VALUE) return FALSE;
    if(!ReadFile(f,text,size-1,&n,NULL)) { CloseHandle(f); return FALSE; }
    text[n]=0; CloseHandle(f); return TRUE;
}

int wmain(int argc,WCHAR **argv) {
    WCHAR ini[PATH_CAP],index[PATH_CAP]; char before[32768],after[32768]; HANDLE lock;
    CHECK(argc==2); CHECK(EnsureDirectory(argv[1]));
    CHECK(JoinPath(ini,PATH_CAP,argv[1],L"Index.ini"));
    CHECK(JoinPath(index,PATH_CAP,argv[1],L"索引 space"));
    CHECK(WriteBytes(ini,"; keep comment\n[Everything]\nexclude_folders=C:\\Keep\nfolders=C:\\Local\n db_location =old\nDB_LOCATION=duplicate\nhttp_server_enabled=1\n[Other]\ndb_location=keep-other\ncustom=value\n"));
    CHECK(UpdateConfiguration(argv[1],index)); CHECK(ReadBytes(ini,after,sizeof(after)));
    CHECK(strstr(after,"exclude_folders=C:\\Keep\r\n")); CHECK(strstr(after,"folders=C:\\Local\r\n"));
    CHECK(strstr(after,"http_server_enabled=0\r\n")); CHECK(strstr(after,"[Other]\r\ndb_location=keep-other"));
    CHECK(strstr(after,"show_tray_icon=0\r\n")); CHECK(strstr(after,"show_in_taskbar=0\r\n"));
    CHECK(!strstr(after,"=old")); CHECK(!strstr(after,"duplicate"));
    strcpy_s(before,sizeof(before),after);
    CHECK(UpdateConfiguration(argv[1],index)); CHECK(ReadBytes(ini,after,sizeof(after))); CHECK(!strcmp(before,after));
    /* A replacement blocked by an open handle must retain every original byte. */
    lock=CreateFileW(ini,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL); CHECK(lock!=INVALID_HANDLE_VALUE);
    CHECK(!UpdateConfiguration(argv[1],L"E:\\moved\\索引")); CloseHandle(lock);
    CHECK(ReadBytes(ini,after,sizeof(after))); CHECK(!strcmp(before,after));
    CHECK(UpdateConfiguration(argv[1],L"E:\\moved\\索引"));
    CHECK(WriteBytes(ini,"[Other]\nkey=keep\n")); CHECK(UpdateConfiguration(argv[1],index));
    CHECK(ReadBytes(ini,after,sizeof(after))); CHECK(strstr(after,"[Everything]\r\n")); CHECK(strstr(after,"key=keep"));
    puts("Portable configuration passed: Unicode, preserved preferences, duplicate keys, idempotence, atomic failure, missing section.");
    return 0;
}
