/* Replay HuoChat 2.1.0.11's actual WM_COPYDATA query block in a private
   mapping. The GUI object/config are fixtures; its window lookup, packet
   construction and asynchronous IPC use the shipped imports and real engine. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
static BYTE *query_start,*query_frame;
static HWND reply_window;
static BYTE config[0x120];
static BOOL received,found;
static LPCWSTR expected;
static void *GetConfig(void) { return config; }
static void Jump(BYTE *at,void *target) { at[0]=0xe9;*(DWORD*)(at+1)=(DWORD)target-(DWORD)at-5; }
static LRESULT CALLBACK Reply(HWND hwnd,UINT msg,WPARAM w,LPARAM l) {
    if(msg==WM_COPYDATA) {
        COPYDATASTRUCT *cds=(COPYDATASTRUCT*)l;DWORD *words=(DWORD*)cds->lpData,i;
        if(cds->dwData==0x432 && cds->cbData>=28) {
            /* Public IPC v1 LISTW: seven DWORDs, then 12-byte ITEMW entries. */
            DWORD count=words[5];received=TRUE;
            for(i=0;i<count && 28+(i+1)*12<=cds->cbData;i++) {
                DWORD offset=words[7+i*3+1];WCHAR *name;
                if(offset>=cds->cbData || (cds->cbData-offset)%2)continue;
                name=(WCHAR*)((BYTE*)words+offset);
                if((wcslen(expected)+1)*sizeof(WCHAR)<=cds->cbData-offset && !memcmp(name,expected,(wcslen(expected)+1)*sizeof(WCHAR)))found=TRUE;
            }
            return TRUE;
        }
    }
    return DefWindowProcW(hwnd,msg,w,l);
}
static BOOL Resolve(BYTE *image,IMAGE_NT_HEADERS *nt,LPCSTR wanted) {
    IMAGE_IMPORT_DESCRIPTOR *desc=(IMAGE_IMPORT_DESCRIPTOR*)(image+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for(;desc->Name;desc++) {
        IMAGE_THUNK_DATA *names=(IMAGE_THUNK_DATA*)(image+desc->OriginalFirstThunk),*iat=(IMAGE_THUNK_DATA*)(image+desc->FirstThunk);
        for(;names->u1.AddressOfData;names++,iat++) {
            IMAGE_IMPORT_BY_NAME *item;
            if(IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal))continue;
            item=(IMAGE_IMPORT_BY_NAME*)(image+names->u1.AddressOfData);
            if(!strcmp((char*)item->Name,wanted)) {
                HMODULE dll=LoadLibraryA((char*)image+desc->Name);FARPROC fn=dll ? GetProcAddress(dll,wanted):NULL;
                if(!fn)return FALSE;iat->u1.Function=(DWORD)fn;return TRUE;
            }
        }
    }
    return FALSE;
}
__declspec(naked) static void Replay(void) {
    __asm {
        push ebp
        push ebx
        push esi
        push edi
        mov ebp,query_frame
        mov eax,reply_window
        call query_start
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret
    }
}
int wmain(int argc,WCHAR **argv) {
    HMODULE mapped;BYTE *image;IMAGE_NT_HEADERS *nt;DWORD old,delta,i;MSG message;ULONGLONG deadline;
    BYTE frame[0x800]={0};WCHAR directory[32768];WNDCLASSW wc={0};
    const char *imports[]={"FindWindowW","SendMessageW","GetProcessHeap","HeapAlloc","HeapFree"};
    if(argc!=4)return 2;
    expected=argv[3];if(wcslen(argv[2])<8)return 3;
    GetFullPathNameW(argv[1],32768,directory,NULL);*wcsrchr(directory,L'\\')=0;SetDllDirectoryW(directory);
    mapped=LoadLibraryExW(argv[1],NULL,DONT_RESOLVE_DLL_REFERENCES);if(!mapped)return 4;
    image=(BYTE*)mapped;nt=(IMAGE_NT_HEADERS*)(image+((IMAGE_DOS_HEADER*)image)->e_lfanew);
    if(!VirtualProtect(image,nt->OptionalHeader.SizeOfImage,PAGE_EXECUTE_READWRITE,&old))return 5;
    /* Mapping an EXE does not resolve its imports or base relocations. */
    delta=(DWORD)image-0x400000;
    if(delta && *(DWORD*)(image+0x1ae661)==0x7cf9c0) {
        IMAGE_BASE_RELOCATION *block=(IMAGE_BASE_RELOCATION*)(image+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        BYTE *end=(BYTE*)block+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        while((BYTE*)block<end && block->SizeOfBlock>=sizeof(*block)) {
            WORD *entries=(WORD*)(block+1);DWORD count=(block->SizeOfBlock-sizeof(*block))/sizeof(WORD);
            for(i=0;i<count;i++)if((entries[i]>>12)==IMAGE_REL_BASED_HIGHLOW)*(DWORD*)(image+block->VirtualAddress+(entries[i]&0xfff))+=delta;
            block=(IMAGE_BASE_RELOCATION*)((BYTE*)block+block->SizeOfBlock);
        }
    }
    if(image[0x1ae65e]!=0x6a || image[0x1ae65f]!=0 || image[0x1ae660]!=0x68 ||
       *(DWORD*)(image+0x1ae661)!=(DWORD)image+0x3cf9c0 || image[0x1ae76f]!=0xe8)return 6;
    for(i=0;i<sizeof(imports)/sizeof(imports[0]);i++)if(!Resolve(image,nt,imports[i]))return 7;
    Jump(image+0xcdf40,GetConfig);Jump(image+0xce320,GetConfig);Jump(image+0x3138b0,memcpy);
    image[0x1ae76f]=0xc3;query_start=image+0x1ae65e;query_frame=frame+0x400;
    *(LPCWSTR*)(query_frame-0x2c)=argv[2];*(DWORD*)(query_frame-0x18)=(DWORD)wcslen(argv[2]);
    wc.lpfnWndProc=Reply;wc.hInstance=GetModuleHandleW(NULL);wc.lpszClassName=L"HuoChatOriginalQueryTest";
    if(!RegisterClassW(&wc))return 8;
    reply_window=CreateWindowW(wc.lpszClassName,L"",0,0,0,0,0,NULL,NULL,wc.hInstance,NULL);if(!reply_window)return 9;
    Replay();deadline=GetTickCount64()+5000;
    if(*(HWND*)(query_frame-0x2bc))while(!received && GetTickCount64()<deadline) {
        while(PeekMessageW(&message,NULL,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}Sleep(10);
    }
    printf("original_ui_query: window=%p reply=%d expected_file=%d\n",*(HWND*)(query_frame-0x2bc),received,found);
    if(received && found) {
        typedef HWND(WINAPI *LOOKUP)(LPCWSTR,LPCWSTR);
        LOOKUP lookup=*(LOOKUP*)(image+0x3956d0);HWND foreign;
        wc.lpszClassName=L"EVERYTHING";if(!RegisterClassW(&wc))return 11;
        foreign=CreateWindowW(wc.lpszClassName,L"",0,0,0,0,0,NULL,NULL,wc.hInstance,NULL);
        if(!foreign || lookup(L"EVERYTHING",NULL)==foreign ||
           lookup(L"HuoChatOriginalQueryTest",NULL)!=reply_window)return 12;
        DestroyWindow(foreign);
    }
    DestroyWindow(reply_window);return received && found ? 0:10;
}
