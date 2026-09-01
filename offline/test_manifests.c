/* Parse standalone manifest XML with Windows SxS. No target PE is loaded. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
int wmain(int count,wchar_t **paths) {
    int i;
    for(i=1;i<count;++i) {
        ACTCTXW spec={0}; HANDLE context;
        spec.cbSize=sizeof(spec); spec.lpSource=paths[i];
        context=CreateActCtxW(&spec);
        if(context==INVALID_HANDLE_VALUE) { printf("Manifest %d failed: %lu\n",i,GetLastError()); return 1; }
        ReleaseActCtx(context);
    }
    printf("Windows x86 manifest parser: %d manifests passed; no target module loaded.\n",count-1);
    return 0;
}
