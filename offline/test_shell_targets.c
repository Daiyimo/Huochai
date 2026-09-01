/* Exercise the actual exported guards, without starting HuoChat/Everything.
   NO_UI makes the old broken guard fail deterministically without a dialog. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

typedef HINSTANCE (WINAPI *SHELLW)(HWND,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,INT);
typedef HINSTANCE (WINAPI *SHELLA)(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);
typedef BOOL (WINAPI *SHELLEXW)(SHELLEXECUTEINFOW *);
typedef BOOL (WINAPI *SHELLEXA)(SHELLEXECUTEINFOA *);
#define CHECK(x) do { if (!(x)) { printf("FAILED line %d: %s (last_error=%lu)\n", __LINE__, #x, GetLastError()); return 1; } } while (0)

int wmain(int argc, WCHAR **argv) {
    HMODULE guard;
    SHELLW shellw; SHELLA shella; SHELLEXW exw; SHELLEXA exa;
    SHELLEXECUTEINFOW w = {0}; SHELLEXECUTEINFOA a = {0};
    WCHAR self[MAX_PATH]; DWORD code;
    const WCHAR *targets[] = {
        L"C:\\fixture\\HuoChatOffline-v1-single\\                      ",
        L"E:\\portable test\\HuoChatOffline-v1-single\\                      ",
        L"C:\\fixture\\HuoChatOffline-v1-green\\                      ",
        L"                      ", L"\t \r\n",
        L"\"D:\\portable test\\                      \"",
        L"D:/portable test/                      ",
        L"", L"\"\"", L"D:                      "
    };
    unsigned i;
    if (argc > 1 && !lstrcmpW(argv[1], L"--child")) return 23;
    guard = LoadLibraryW(argc > 1 ? argv[1] : L"hcg.dll");
    CHECK(guard);
    shellw = (SHELLW)GetProcAddress(guard, "ShellExecuteW");
    shella = (SHELLA)GetProcAddress(guard, "ShellExecuteA");
    exw = (SHELLEXW)GetProcAddress(guard, "ShellExecuteExW");
    exa = (SHELLEXA)GetProcAddress(guard, "ShellExecuteExA");
    CHECK(shellw && shella && exw && exa);
    for (i = 0; i < sizeof(targets)/sizeof(targets[0]); ++i) {
        CHAR narrow[1024];
        CHECK(WideCharToMultiByte(CP_ACP, 0, targets[i], -1, narrow, sizeof(narrow), NULL, NULL));
        ZeroMemory(&w, sizeof(w)); w.cbSize = sizeof(w);
        w.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS;
        w.lpVerb = L"open"; w.lpFile = targets[i]; w.nShow = SW_HIDE;
        SetLastError(0);
        CHECK(!exw(&w));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        CHECK(w.hInstApp == (HINSTANCE)SE_ERR_ACCESSDENIED && !w.hProcess);
        ZeroMemory(&a, sizeof(a)); a.cbSize = sizeof(a);
        a.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS;
        a.lpVerb = "open"; a.lpFile = narrow; a.nShow = SW_HIDE;
        CHECK(!exa(&a));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        CHECK(a.hInstApp == (HINSTANCE)SE_ERR_ACCESSDENIED && !a.hProcess);
        CHECK(shellw(NULL, L"open", targets[i], NULL, NULL, SW_HIDE) == (HINSTANCE)SE_ERR_ACCESSDENIED);
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        CHECK(shella(NULL, "open", narrow, NULL, NULL, SW_HIDE) == (HINSTANCE)SE_ERR_ACCESSDENIED);
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
    }
    /* A real local executable, including a path with spaces, must still work.
       The child is this test itself and immediately exits with a known code. */
    CHECK(GetModuleFileNameW(NULL, self, MAX_PATH));
    ZeroMemory(&w, sizeof(w)); w.cbSize = sizeof(w);
    w.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    w.lpVerb = L"open"; w.lpFile = self; w.lpParameters = L"--child"; w.nShow = SW_HIDE;
    CHECK(exw(&w)); CHECK(w.hProcess);
    CHECK(WaitForSingleObject(w.hProcess, 10000) == WAIT_OBJECT_0);
    CHECK(GetExitCodeProcess(w.hProcess, &code)); CloseHandle(w.hProcess);
    CHECK(code == 23);
    FreeLibrary(guard);
    puts("Shell target regression passed: blank component paths denied in A/W/Ex; local executable launch preserved.");
    return 0;
}
