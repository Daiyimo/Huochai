/* Exercise the actual packaged x86 SDK, including IPC v2 metadata. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
typedef DWORD(WINAPI *NUMBER)(void);
typedef void(WINAPI *SETNUM)(DWORD);
typedef void(WINAPI *SETTEXT)(LPCWSTR);
typedef BOOL(WINAPI *QUERY)(BOOL);
typedef DWORD(WINAPI *FULLPATH)(DWORD,LPWSTR,DWORD);
typedef BOOL(WINAPI *SDK_SIZE)(DWORD,LARGE_INTEGER*);
typedef BOOL(WINAPI *DATE)(DWORD,FILETIME*);
#define FN(type,name) ((type)GetProcAddress(dll,name))
int wmain(int argc,WCHAR **argv) {
    HMODULE dll;DWORD count,i;WCHAR path[32768];CHAR utf8[131072];LARGE_INTEGER size;FILETIME date;
    if(argc!=2)return 2;dll=LoadLibraryW(L"Everything32.dll");if(!dll)return 3;
    if(!FN(NUMBER,"Everything_IsDBLoaded")())return 4;
    FN(SETTEXT,"Everything_SetSearchW")(argv[1]);FN(SETNUM,"Everything_SetMax")(10);
    FN(SETNUM,"Everything_SetRequestFlags")(0x1|0x2|0x8|0x10|0x40);
    FN(SETNUM,"Everything_SetSort")(1);
    if(!FN(QUERY,"Everything_QueryW")(TRUE))return 5;
    count=FN(NUMBER,"Everything_GetNumResults")();
    printf("admin=%lu\ntotal=%lu\n",FN(NUMBER,"Everything_IsAdmin")(),FN(NUMBER,"Everything_GetTotResults")());
    printf("version=%lu.%lu.%lu.%lu\ncount=%lu\n",FN(NUMBER,"Everything_GetMajorVersion")(),
        FN(NUMBER,"Everything_GetMinorVersion")(),FN(NUMBER,"Everything_GetRevision")(),FN(NUMBER,"Everything_GetBuildNumber")(),count);
    for(i=0;i<count;i++) {
        if(!FN(FULLPATH,"Everything_GetResultFullPathNameW")(i,path,32768))return 6;
        if(!WideCharToMultiByte(CP_UTF8,0,path,-1,utf8,sizeof(utf8),NULL,NULL))return 7;
        printf("file=%s\n",utf8);
        if(!FN(SDK_SIZE,"Everything_GetResultSize")(i,&size) || !FN(DATE,"Everything_GetResultDateModified")(i,&date))return 8;
        printf("size=%I64d\n",size.QuadPart);
    }
    return 0;
}
