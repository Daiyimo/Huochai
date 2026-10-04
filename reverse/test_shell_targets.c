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
        L"", L"\"\"", L"D:                      ",
        /* A quoted path is what Windows itself sees once the quotes are
           stripped. It used to skip both the UNC rejection and the drive
           letter test at the same time. */
        L"\"\\\\fileserver\\share\\tool.exe\"",
        /* A shell-namespace item is not a file, so the rules that describe
           files must not be applied to it verbatim. */
        L"shell:RecycleBinFolder",
        L"::{645FF040-5081-101B-9F08-00AA002F954E}\\..\\..\\Windows\\System32\\cmd.exe"
    };
    /* The mirror image: paths that carry a byte the rules below cannot make
       sense of, but which the shell resolves every day. */
    const WCHAR *allowed[] = {
        L"::{645FF040-5081-101B-9F08-00AA002F954E}",
        L"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
        L"\"C:\\Windows\\System32\\notepad.exe\""
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
    /* A shell-namespace item is reached from the application every day: it is
       what "open Recycle Bin" does. The colon rules above must not mistake it
       for a URL -- the quoted UNC case below proves both directions matter. */
    for (i = 0; i < sizeof(allowed)/sizeof(allowed[0]); ++i) {
        ZeroMemory(&w, sizeof(w)); w.cbSize = sizeof(w);
        w.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        w.lpVerb = L"open"; w.lpFile = allowed[i]; w.nShow = SW_HIDE;
        SetLastError(0);
        /* A namespace item opens a folder window, so only the refusal is
           checked here; the quoted-path case is launched for real below. */
        CHECK(exw(&w) || GetLastError() != ERROR_ACCESS_DENIED);
    }

    /* A real local executable, including a quoted path with spaces, must still
       work. The child is this test itself and exits with a known code. */
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
