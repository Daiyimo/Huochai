/* Launch only the test-supplied command with this administrator's linked,
   filtered user token. The helper's PID is never confused with the child. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
int wmain(int argc,WCHAR **argv) {
    HANDLE token;TOKEN_LINKED_TOKEN linked;DWORD bytes;STARTUPINFOW si={0};PROCESS_INFORMATION pi={0};
    SID_IDENTIFIER_AUTHORITY nt=SECURITY_NT_AUTHORITY,mandatory=SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID administrators=NULL,medium=NULL;SID_AND_ATTRIBUTES disabled;TOKEN_MANDATORY_LABEL label;
    if(argc!=3)return 2;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_DEFAULT,&token))return 3;
    if(!GetTokenInformation(token,TokenLinkedToken,&linked,sizeof(linked),&bytes)) {
        /* Hosts with UAC disabled have no linked token. Drop admin membership,
           privileges and integrity in a new token; do not change the account. */
        if(!AllocateAndInitializeSid(&nt,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&administrators))return 4;
        disabled.Sid=administrators;disabled.Attributes=0;
        if(!CreateRestrictedToken(token,DISABLE_MAX_PRIVILEGE,1,&disabled,0,NULL,0,NULL,&linked.LinkedToken))return 4;
        FreeSid(administrators);
        if(!AllocateAndInitializeSid(&mandatory,1,SECURITY_MANDATORY_MEDIUM_RID,0,0,0,0,0,0,0,&medium))return 4;
        label.Label.Sid=medium;label.Label.Attributes=SE_GROUP_INTEGRITY;
        if(!SetTokenInformation(linked.LinkedToken,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(medium))){printf("integrity error=%lu\n",GetLastError());return 4;}
        FreeSid(medium);
    }
    CloseHandle(token);si.cb=sizeof(si);
    if(!CreateProcessAsUserW(linked.LinkedToken,NULL,argv[2],NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,argv[1],&si,&pi)) {
        printf("error=%lu\n",GetLastError());CloseHandle(linked.LinkedToken);return 5;
    }
    printf("%lu\n",pi.dwProcessId);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(linked.LinkedToken);return 0;
}
