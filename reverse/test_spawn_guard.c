/* Regression coverage for the process-spawn guard.
   Verifies that local helpers still start while browser and remote targets are
   refused. Runs against the built hcg.dll only; no original module is loaded. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <objbase.h>
#include <stdio.h>

static int failures;

static void check(int condition, const char *what) {
    if (!condition) { printf("FAIL %s (err=%lu)\n", what, GetLastError()); ++failures; }
    else printf("ok   %s\n", what);
}

/* The guard's decision is what matters: a bare name such as "hc_engine.exe"
   only resolves against the caller's working directory, which does not exist
   here, so a permitted target can still fail with ERROR_FILE_NOT_FOUND.
   Anything other than ERROR_ACCESS_DENIED means the guard let it through. */
static int denied_create(HMODULE guard, LPCWSTR app) {
    typedef BOOL (WINAPI *FN)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    FN fn = (FN)GetProcAddress(guard, "CreateProcessW");
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    if (!fn) return -1;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    SetLastError(0);
    BOOL ok = fn(app, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (ok) {
        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread) CloseHandle(pi.hThread);
        return 0;                       /* guard permitted it */
    }
    DWORD err = GetLastError();
    return err == ERROR_ACCESS_DENIED ? 1 : 0;   /* any other failure = permitted */
}

int main(void) {
    HMODULE guard = LoadLibraryW(L"hcg.dll");
    if (!guard) { printf("cannot load hcg.dll: %lu\n", GetLastError()); return 2; }

    /* Local helpers must keep starting. A bare name resolves against the
       caller's directory, so the negative case uses a name that does not exist
       there and only checks that the guard did not refuse it; the positive
       case launches a real system executable. */
    check(denied_create(guard, L"hc_engine.exe") == 0, "local bare engine name allowed");
    check(denied_create(guard, L".\\hc_engine.exe") == 0, "local relative engine path allowed");
    {
        WCHAR sys[MAX_PATH];
        UINT n = GetSystemDirectoryW(sys, MAX_PATH);
        if (n && n < MAX_PATH) {
            lstrcatW(sys, L"\\cmd.exe");
            STARTUPINFOW si; PROCESS_INFORMATION pi;
            typedef BOOL (WINAPI *FN)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
                LPPROCESS_INFORMATION);
            FN fn = (FN)GetProcAddress(guard, "CreateProcessW");
            ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
            ZeroMemory(&pi, sizeof(pi));
            BOOL ok = fn ? fn(sys, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) : FALSE;
            check(ok != FALSE, "local absolute executable actually starts");
            if (ok) {
                /* A live process proves the guard forwarded the call intact. */
                DWORD code = 0;
                GetExitCodeProcess(pi.hProcess, &code);
                check(code == STILL_ACTIVE, "spawned process is running");
                TerminateProcess(pi.hProcess, 0);
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
        }
    }

    /* Network-capable targets must be refused. */
    check(denied_create(guard, L"HYBrowser.exe") == 1, "stripped browser component denied");
    check(denied_create(guard, L"msedge.exe") == 1, "edge denied");
    check(denied_create(guard, L"chrome.exe") == 1, "chrome denied");
    check(denied_create(guard, L"http://evil.example/payload.exe") == 1, "http target denied");
    check(denied_create(guard, L"https://jf.huoying666.com/x.exe") == 1,
          "business-host target denied");
    check(denied_create(guard, L"\\\\server\\share\\tool.exe") == 1, "UNC target denied");

    /* WinExec follows the same policy. */
    typedef UINT (WINAPI *WE)(LPCSTR, UINT);
    WE we = (WE)GetProcAddress(guard, "WinExec");
    check(we != NULL, "WinExec is guarded");
    if (we) {
        SetLastError(0);
        UINT local = we("cmd.exe /c exit 0", SW_HIDE);
        check(local > 31, "WinExec local command allowed");
        SetLastError(0);
        UINT remote = we("http://evil.example/x", SW_HIDE);
        check(remote == 0 && GetLastError() == ERROR_ACCESS_DENIED, "WinExec remote denied");
    }

    printf(failures ? "\nSPAWN GUARD: %d failure(s)\n" : "\nspawn guard passed\n", failures);
    return failures ? 1 : 0;
}
