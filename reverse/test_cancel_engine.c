/* Calls the production cancellation code on an isolated real-engine folder. */
#define WinMain UnusedLauncherMain
#include "launcher.c"
#include <stdio.h>
int wmain(int argc,WCHAR **argv) {
    WCHAR dir[PATH_CAP];DWORD begin=GetTickCount();
    if(argc!=2 || !JoinPath(dir,PATH_CAP,argv[1],L"")) return 2;
    if(!ShutdownEngines(dir)) return 3;
    printf("Real engine cancellation took %lu ms\n",GetTickCount()-begin);
    return 0;
}
