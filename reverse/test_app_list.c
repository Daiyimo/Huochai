/* Regression coverage for the app-list enumeration filter.

   The program index treats every package Get-AppxPackage reports as a
   program. A package that only registers a shell extension -- share target,
   print dialog, context menu -- is listed as a program too even though Windows
   never starts one: its manifest marks the application AppListEntry="none".
   Clicking such an entry does nothing.

   The guard extends that enumeration with a filter that keeps only packages
   with at least one application Windows would list, and leaves every other
   command line untouched. A package whose manifest cannot be read is kept, so
   an unreadable file never drops a real program.

   Runs against the built hcg.dll only; no original module is loaded. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>

static int failures;

static void check(int condition, const char *what) {
    if (!condition) { printf("FAIL %s (err=%lu)\n", what, GetLastError()); ++failures; }
    else printf("ok   %s\n", what);
}

typedef BOOL (WINAPI *CREATEW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

/* Runs a command line to completion. "spawn" is the guard under test, or NULL
   for the plain entry this test imports itself. CreateProcessW overwrites the
   command line it is given, so the unfiltered run needs a writable copy. */
static int run_line(CREATEW spawn, const WCHAR *cmdline) {
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    DWORD code = 0;
    BOOL ok;
    LPWSTR copy = _wcsdup(cmdline);
    if (!copy) return 0;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    ok = spawn ? spawn(NULL, copy, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)
               : CreateProcessW(NULL, copy, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    free(copy);
    if (!ok) return 0;
    WaitForSingleObject(pi.hProcess, 180000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code == 0;
}

static int read_file(const WCHAR *path, unsigned char *buf, DWORD cap) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD got = 0;
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!ReadFile(h, buf, cap - 1, &got, NULL)) got = 0;
    CloseHandle(h);
    buf[got] = 0;
    return (int)got;
}

/* One block per package, so counting blocks counts packages. */
static int count_packages(const unsigned char *buf, int n) {
    int total = 0, at_line = 1, i;
    for (i = 0; i + 4 <= n; ++i) {
        if (at_line && memcmp(buf + i, "Name", 4) == 0) ++total;
        at_line = (buf[i] == '\n');
    }
    return total;
}

typedef struct { unsigned char *next, *end; } BLOCKS;

/* Blank-line separated blocks, separators skipped. Empty runs -- the BOM line
   at the head of the file, trailing blank lines -- are skipped rather than
   reported as a block, so one block is one package. */
static int next_block(BLOCKS *it, unsigned char **block, int *len) {
    for (;;) {
        unsigned char *start = it->next, *p, *stop = NULL;
        if (!start || start >= it->end) return 0;
        for (p = start; p < it->end; ++p) {
            if (p + 1 < it->end && p[0] == '\n' && p[1] == '\n') { stop = p; break; }
            if (p + 1 < it->end && p[0] == '\r' && p[1] == '\n' &&
                p + 2 < it->end && p[2] == '\r' && p[3] == '\n') { stop = p; break; }
        }
        if (!stop) {
            *block = start; *len = (int)(it->end - start);
            it->next = it->end;
            return *len > 0;
        }
        it->next = stop;
        while (it->next < it->end && (*it->next == '\n' || *it->next == '\r')) ++it->next;
        if (stop > start) { *block = start; *len = (int)(stop - start); return 1; }
    }
}

/* Independent oracle for the rule the filter encodes, so a filter that keeps an
   extension package or drops a real program fails here. */
static int application_elements(const unsigned char *hay, int n) {
    int total = 0, i;
    for (i = 0; i + 12 <= n; ++i) {
        char next;
        if (hay[i] != '<' || memcmp(hay + i, "<Application", 12) != 0) continue;
        next = (char)hay[i + 12];          /* <Applications> is the container */
        if (next == ' ' || next == '\t' || next == '\r' || next == '\n' ||
            next == '/' || next == '>') ++total;
    }
    return total;
}
static int applist_none_entries(const unsigned char *hay, int n) {
    int total = 0, i;
    for (i = 0; i + 12 < n; ++i) {
        int j;
        if (memcmp(hay + i, "AppListEntry", 12) != 0) continue;
        for (j = i + 12; j < n && (hay[j] == ' ' || hay[j] == '\t'); ++j) {}
        if (j >= n || hay[j] != '=') continue;
        for (++j; j < n && (hay[j] == ' ' || hay[j] == '\t'); ++j) {}
        if (j + 6 <= n && memcmp(hay + j, "\"none\"", 6) == 0) ++total;
    }
    return total;
}

/* Reports whether one package block describes an application Windows would
   start. A missing InstallLocation or an unreadable manifest counts as
   launchable, which is exactly what the filter keeps. */
static int block_is_launchable(const unsigned char *block, int len) {
    static unsigned char manifest[1 << 20];
    WCHAR location[1024], path[1100];
    int at_line = 1, i;
    for (i = 0; i + 15 < len; ++i) {
        int start, end, bytes;
        if (!(at_line && memcmp(block + i, "InstallLocation", 15) == 0)) {
            at_line = (block[i] == '\n');
            continue;
        }
        for (start = i + 15; start < len && (block[start] == ' ' || block[start] == '\t'); ++start) {}
        for (end = start; end < len && block[end] != '\r' && block[end] != '\n'; ++end) {}
        while (end > start && (block[end-1] == ' ' || block[end-1] == '\t')) --end;
        if (MultiByteToWideChar(CP_UTF8, 0, (LPCCH)block + start, end - start, location, 1024) <= 0)
            return 1;
        location[end - start < 1024 ? end - start : 1023] = 0;
        if (FAILED(StringCchPrintfW(path, 1100, L"%s\\AppxManifest.xml", location))) return 1;
        bytes = read_file(path, manifest, sizeof(manifest));
        if (bytes <= 0) return 1;
        return application_elements(manifest, bytes) > applist_none_entries(manifest, bytes);
    }
    return 1;
}

int main(void) {
    HMODULE guard = LoadLibraryW(L"hcg.dll");
    CREATEW spawn;
    WCHAR dir[MAX_PATH], base[MAX_PATH + 64], filtered[MAX_PATH + 64], marker[MAX_PATH + 64];
    static unsigned char list[1 << 21];
    WCHAR cmd[2048];
    int n, all, kept;

    if (!guard) { printf("cannot load hcg.dll: %lu\n", GetLastError()); return 2; }
    spawn = (CREATEW)GetProcAddress(guard, "CreateProcessW");
    check(spawn != NULL, "CreateProcessW is guarded");
    if (!spawn) return 2;

    if (!GetTempPathW(MAX_PATH, dir)) { printf("no temp directory: %lu\n", GetLastError()); return 2; }
    if (FAILED(StringCchPrintfW(base, MAX_PATH + 64, L"%sappx-baseline.txt", dir)) ||
        FAILED(StringCchPrintfW(filtered, MAX_PATH + 64, L"%sappx-guarded.txt", dir)) ||
        FAILED(StringCchPrintfW(marker, MAX_PATH + 64, L"%sappx-unrelated.txt", dir))) {
        printf("temp path too long\n"); return 2;
    }
    DeleteFileW(base); DeleteFileW(filtered); DeleteFileW(marker);

    /* The enumeration as the program runs it, written by an unfiltered spawn. */
    if (FAILED(StringCchPrintfW(cmd, 2048,
            L"powershell Get-AppxPackage | Out-File -Encoding utf8 '%s'", base))) {
        printf("command line too long\n"); return 2;
    }
    check(run_line(NULL, cmd), "unfiltered enumeration runs");
    n = read_file(base, list, sizeof(list));
    if (n <= 0) { printf("baseline list not written: %lu\n", GetLastError()); return 2; }
    all = count_packages(list, n);
    printf(".  baseline packages: %d\n", all);

    /* The same enumeration through the guard. The output has to stay in the
       program's own format, minus the packages Windows never starts. */
    if (FAILED(StringCchPrintfW(cmd, 2048,
            L"powershell Get-AppxPackage | Out-File -Encoding utf8 '%s'", filtered))) {
        printf("command line too long\n"); return 2;
    }
    check(run_line(spawn, cmd), "guarded enumeration runs");
    n = read_file(filtered, list, sizeof(list));
    if (n <= 0) { printf("guarded list not written: %lu\n", GetLastError()); return 2; }
    kept = count_packages(list, n);
    printf(".  guarded packages: %d\n", kept);
    check(kept <= all, "guarded list is not larger than the baseline");

    if (all == 0) {
        printf(".  no packages on this machine; list comparison skipped\n");
    } else {
        BLOCKS it; unsigned char *block; int len, bad = 0, blocks = 0;
        check(kept > 0, "guarded list still lists programs");
        it.next = list; it.end = list + n;
        if (n >= 3 && list[0] == 0xEF && list[1] == 0xBB && list[2] == 0xBF)
            it.next = list + 3;                      /* Out-File writes a UTF-8 BOM */
        while (next_block(&it, &block, &len)) {
            ++blocks;
            if (!block_is_launchable(block, len)) ++bad;
        }
        check(bad == 0, "every listed package has a launchable application");
        check(blocks == kept, "every guarded block is one package");
        printf(".  package blocks checked: %d\n", blocks);
    }

    /* A command line that is not an enumeration must reach Windows unchanged. */
    {
        WCHAR sys[MAX_PATH];
        UINT sn = GetSystemDirectoryW(sys, MAX_PATH);
        check(sn > 0 && sn + 64 < MAX_PATH, "system directory resolved");
        if (sn > 0 && sn + 64 < MAX_PATH &&
            SUCCEEDED(StringCchPrintfW(cmd, 2048,
                L"%s\\cmd.exe /c echo appx-filter-not-applied > %s", sys, marker))) {
            check(run_line(spawn, cmd), "unrelated command through the guard runs");
            n = read_file(marker, list, sizeof(list));
            check(n > 0 && strstr((char *)list, "appx-filter-not-applied") != NULL,
                  "unrelated command line is not rewritten");
        }
    }

    printf(failures ? "\nAPP LIST FILTER: %d failure(s)\n" : "\napp list filter passed\n", failures);
    return failures ? 1 : 0;
}
