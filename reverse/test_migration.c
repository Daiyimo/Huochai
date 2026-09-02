#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "migration.h"
int wmain(int argc,WCHAR **argv) {
    WCHAR dir[PATH_CAP];
    if(argc!=2 || FAILED(StringCchPrintfW(dir,PATH_CAP,L"%s\\",argv[1]))) return 2;
    if(!PrepareData(dir)) { printf("Migration refused: %lu\n",GetLastError()); return 21; }
    puts("Migration completed"); return 0;
}
