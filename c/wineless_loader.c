/*
 * wineless_loader.c — Run Windows x64 PE binaries on Linux, no Wine required.
 *
 * A single-file userland PE loader:
 *   1. Parses the PE64 header set (DOS / COFF / Optional / Sections).
 *   2. Maps the image into memory (preferred ImageBase with anonymous mmap fallback).
 *   3. Copies headers + sections, applies DIR64 base relocations.
 *   4. Resolves the Import Address Table against a hand-written kernel32/crt hook table
 *      (Microsoft x64 calling convention, `ms_abi`).
 *   5. Emulates the Windows thread environment: fake TEB + PEB installed via GS (arch_prctl).
 *   6. Jumps to the entry point. ExitProcess() is captured with setjmp/longjmp.
 *
 * Build:   cc -O2 -o wineless_loader wineless_loader.c
 * Usage:   ./wineless_loader <target.exe> [args passed to GetCommandLineA]...
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <setjmp.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <wchar.h>
#include <signal.h>
#include <execinfo.h>
#include <ucontext.h>

static int siginfo_read(uintptr_t addr, void **out) {
    FILE *f = fopen("/proc/self/mem", "rb");
    if (!f) return -1;
    int ok = fseek(f, (long)addr, SEEK_SET) == 0 && fread(out, sizeof(void *), 1, f) == 1;
    fclose(f);
    return ok ? 0 : -1;
}

static uint8_t *g_image_base_fwd;

static void crash_handler(int sig, siginfo_t *info, void *uctx) {
    uint8_t *image_base = g_image_base_fwd;
    ucontext_t *uc = (ucontext_t *)uctx;
    uintptr_t rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    const char *where = "PE image";
    if (rip < (uintptr_t)image_base || rip >= (uintptr_t)image_base + 0x100000000ull)
        where = "loader/libc";
    fprintf(stderr, "[wineless] FATAL signal %d at RIP %p (%s) fault_addr=%p\n",
            sig, (void *)rip, where, info->si_addr);
    uintptr_t rsp = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    for (int k = 0; k < 4; k++) {
        void *stack_val;
        if (siginfo_read(rsp + k * sizeof(void *), &stack_val) == 0)
            fprintf(stderr, "  [rsp+%d] %p\n", k * 8, stack_val);
    }
    void *bt[32];
    int n = backtrace(bt, 32);
    for (int i = 1; i < n; i++) fprintf(stderr, "  [%d] %p\n", i, bt[i]);
    _exit(139);
}

/* ------------------------------------------------------------------ */
/* Global loader state                                                 */
/* ------------------------------------------------------------------ */

static jmp_buf g_exit_env;
static int     g_exit_code   = 0;
static uint8_t *g_image_base = NULL;
static uint8_t *g_image_base_fwd; /* for the crash handler */
static char     g_cmdline[4096];

/* ------------------------------------------------------------------ */
/* Windows TEB / PEB (the parts userland actually touches)             */
/* ------------------------------------------------------------------ */

typedef struct {
    /* offsets follow the real x64 PEB layout */
    uint8_t  InheritedAddressSpace;      /* 0x00 */
    uint8_t  ReadImageFileExecOptions;   /* 0x01 */
    uint8_t  BeingDebugged;              /* 0x02 */
    uint8_t  BitField;                   /* 0x03 */
    uint8_t  Pad[4];
    void    *Mutant;                     /* 0x08 */
    void    *ImageBaseAddress;           /* 0x10 */
    void    *Ldr;                        /* 0x18 */
    void    *ProcessParameters;          /* 0x20 */
    void    *SubSystemData;              /* 0x28 */
    void    *ProcessHeap;                /* 0x30 */
    void    *FastPebLock;                /* 0x38 */
    void    *AtlThunkSListPtr;           /* 0x40 */
    void    *IFEOKey;                    /* 0x48 */
    void    *CrossProcessFlags;          /* 0x50 */
    void    *KernelCallbackTable;        /* 0x58 */
    uint32_t SystemReserved[2];          /* 0x60 */
    void    *ApiSetMap;                  /* 0x68 */
    uint32_t TlsExpansionCounter;        /* 0x70 */
    uint32_t TlsPad;
    void    *TlsBitmap;                  /* 0x78 */
    uint32_t TlsBitmapBits[2];           /* 0x80 */
    void    *ReadOnlySharedMemoryBase;   /* 0x88 */
    void    *SharedData;                 /* 0x90 */
    void   **ReadOnlyStaticServerData;   /* 0x98 */
    void    *AnsiCodePageData;           /* 0xa0 */
    void    *OemCodePageData;            /* 0xa8 */
    void    *UnicodeCaseTableData;       /* 0xb0 */
    uint32_t NumberOfProcessors;         /* 0xb8 */
    uint32_t NtGlobalFlag;               /* 0xbc */
} WIN_PEB;

typedef struct {
    void    *ExceptionList;               /* +0x00 */
    void    *StackBase;                   /* +0x08 */
    void    *StackLimit;                  /* +0x10 */
    void    *SubSystemTib;                /* +0x18 */
    void    *FiberData;                   /* +0x20 */
    void    *ArbitraryUserPointer;        /* +0x28 */
    void    *Self;                        /* +0x30 : gs:[0x30] = &TEB */
    void    *EnvironmentPointer;          /* +0x38 */
    uint64_t ProcessId;                   /* +0x40 */
    uint64_t ThreadId;                    /* +0x48 */
    void    *ActiveRpcHandle;             /* +0x50 */
    void   **ThreadLocalStoragePointer;   /* +0x58 : gs:[0x58] */
    WIN_PEB *ProcessEnvironmentBlock;     /* +0x60 : gs:[0x60] = &PEB */
    uint32_t LastErrorValue;              /* +0x68 */
    uint32_t Pad;
} __attribute__((packed)) WIN_TEB;

#define WINELESS_TLS_SLOTS 64
static WIN_TEB g_teb;
static WIN_PEB g_peb;
static void   *g_tls_array[WINELESS_TLS_SLOTS];
static uint8_t g_tls_blocks[WINELESS_TLS_SLOTS][65536];

#define MS_ABI __attribute__((ms_abi))

/* Windows wchar_t is 2-byte UTF-16; Linux wchar_t is 4 bytes.
 * Every wide-string hook speaks UTF-16 explicitly. */
typedef uint16_t win_wchar;

static size_t win_wcslen(const win_wchar *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

/* ------------------------------------------------------------------ */
/* kernel32 / crt hooks (Microsoft x64 ABI)                            */
/* ------------------------------------------------------------------ */

MS_ABI void *hook_GetModuleHandleA(const char *name) { (void)name; return g_image_base; }
MS_ABI void *hook_GetModuleHandleW(const win_wchar *name) { (void)name; return g_image_base; }

MS_ABI void *hook_GetStdHandle(uint32_t nStdHandle) {
    if (nStdHandle == (uint32_t)-11) return (void *)1;  /* STD_OUTPUT_HANDLE */
    if (nStdHandle == (uint32_t)-12) return (void *)2;  /* STD_ERROR_HANDLE  */
    return (void *)0;                                   /* STD_INPUT_HANDLE  */
}

MS_ABI char *hook_GetCommandLineA(void) { return g_cmdline; }
MS_ABI win_wchar *hook_GetCommandLineW(void) {
    static win_wchar wcmd[2048];
    size_t i;
    for (i = 0; i < sizeof(g_cmdline) - 1 && g_cmdline[i]; i++)
        wcmd[i] = (win_wchar)(unsigned char)g_cmdline[i];
    wcmd[i] = 0;
    return wcmd;
}

MS_ABI void *hook_GetProcessHeap(void) { return (void *)0x50000; }
MS_ABI void *hook_HeapAlloc(void *h, uint32_t flags, size_t sz) { (void)h; (void)flags; return malloc(sz); }
MS_ABI int   hook_HeapFree(void *h, uint32_t flags, void *p) { (void)h; (void)flags; free(p); return 1; }
MS_ABI void *hook_HeapReAlloc(void *h, uint32_t flags, void *p, size_t sz) { (void)h; (void)flags; return realloc(p, sz); }

MS_ABI int hook_WriteFile(void *hFile, const void *buf, uint32_t n, uint32_t *written, void *overlapped) {
    (void)overlapped;
    int fd = (int)(uintptr_t)hFile;
    if (fd != 1 && fd != 2) fd = 1;
    ssize_t r = write(fd, buf, n);
    if (written && r > 0) *written = (uint32_t)r;
    return r >= 0;
}

MS_ABI int hook_ReadFile(void *hFile, void *buf, uint32_t n, uint32_t *read, void *overlapped) {
    (void)hFile; (void)buf; (void)n; (void)overlapped;
    if (read) *read = 0;
    return 0; /* EOF — consoles are write-only for now */
}

MS_ABI int hook_WriteConsoleA(void *hConsole, const void *buf, uint32_t n, uint32_t *written, void *reserved) {
    return hook_WriteFile(hConsole, buf, n, written, reserved);
}

MS_ABI void hook_ExitProcess(uint32_t code) {
    g_exit_code = (int)code;
    longjmp(g_exit_env, 1);
}

MS_ABI uint32_t hook_GetFileType(void *h) { (void)h; return 0x0002; } /* FILE_TYPE_CHAR */
MS_ABI int hook_GetConsoleMode(void *h, uint32_t *mode) { (void)h; if (mode) *mode = 7; return 1; }
MS_ABI int hook_SetConsoleMode(void *h, uint32_t mode) { (void)h; (void)mode; return 1; }
MS_ABI uint32_t hook_GetLastError(void) { return 0; }
MS_ABI void hook_SetLastError(uint32_t e) { (void)e; }
MS_ABI void *hook_SetUnhandledExceptionFilter(void *f) { (void)f; return NULL; }
MS_ABI uint32_t hook_GetCurrentProcessId(void) { return (uint32_t)getpid(); }
MS_ABI uint32_t hook_GetCurrentThreadId(void) { return (uint32_t)getpid(); }
MS_ABI void hook_GetSystemTimeAsFileTime(void *p) { memset(p, 0, 8); }
MS_ABI void hook_InitializeCriticalSection(void *p) { (void)p; }
MS_ABI void hook_EnterCriticalSection(void *p) { (void)p; }
MS_ABI void hook_LeaveCriticalSection(void *p) { (void)p; }
MS_ABI void hook_DeleteCriticalSection(void *p) { (void)p; }

MS_ABI void *hook_VirtualAlloc(void *addr, size_t sz, uint32_t type, uint32_t prot) {
    (void)addr; (void)type;
    return mmap(NULL, sz ? sz : 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
MS_ABI int hook_VirtualFree(void *addr, size_t sz, uint32_t type) { (void)type; return munmap(addr, sz) == 0; }

MS_ABI void *hook_TlsAlloc(void) { return (void *)(uintptr_t)1; }
MS_ABI void *hook_TlsGetValue(uint32_t i) { (void)i; return NULL; }
MS_ABI int   hook_TlsSetValue(uint32_t i, void *v) { (void)i; (void)v; return 1; }
MS_ABI int   hook_TlsFree(uint32_t i) { (void)i; return 1; }

MS_ABI int hook_MultiByteToWideChar(uint32_t cp, uint32_t flags, const char *src, int csrc,
                                    win_wchar *dst, int cdst) {
    (void)cp; (void)flags;
    if (csrc == -1) csrc = (int)strlen(src) + 1;
    if (cdst == 0) return csrc;
    for (int i = 0; i < csrc && i < cdst; i++) dst[i] = (win_wchar)(unsigned char)src[i];
    return csrc;
}

MS_ABI int hook_WideCharToMultiByte(uint32_t cp, uint32_t flags, const win_wchar *src, int csrc,
                                    char *dst, int cdst, const char *def, int *used) {
    (void)cp; (void)flags; (void)def;
    if (used) *used = 0;
    if (csrc == -1) csrc = (int)win_wcslen(src) + 1;
    if (cdst == 0) return csrc;
    for (int i = 0; i < csrc && i < cdst; i++) dst[i] = (char)src[i];
    return csrc;
}

MS_ABI int hook_GetSystemMetrics(int idx) {
    /* SM_CXSCREEN / SM_CYSCREEN: headless-friendly defaults */
    if (idx == 0) return 1920;
    if (idx == 1) return 1080;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CRT / libm bridge: every hook is ms_abi, libc underneath            */
/* ------------------------------------------------------------------ */

#include <errno.h>
#include <ctype.h>
#include <locale.h>
#include <math.h>
#include <time.h>

extern char **environ;

#ifndef MS_ABI
#define MS_ABI __attribute__((ms_abi))
#endif

/* Windows wchar_t is 2-byte UTF-16; Linux wchar_t is 4 bytes.
 * Every wide-string hook below speaks UTF-16 explicitly. */
typedef uint16_t win_wchar;



/* --- memory --------------------------------------------------------- */
MS_ABI void *hook_malloc(size_t n) { return malloc(n); }
MS_ABI void *hook_calloc(size_t a, size_t b) { return calloc(a, b); }
MS_ABI void *hook_realloc(void *p, size_t n) { return realloc(p, n); }
MS_ABI void  hook_free(void *p) { free(p); }

/* --- string (ms_abi: rcx, rdx, r8 — not SysV rdi, rsi!) -------------- */
MS_ABI size_t hook_strlen(const char *s) { return strlen(s); }
int g_trace_wcslen = 0;

MS_ABI size_t hook_wcslen(const win_wchar *s) {
    static int trace_on = -1;
    if (trace_on == -1) trace_on = g_trace_wcslen;
    if (trace_on) {
        void *ra = __builtin_return_address(0);
        fprintf(stderr, "[trace] wcslen(%p) from %p\n", (void *)s, ra);
    }
    if (!s) return 0;
    /* tolerate wild pointers: validate via /proc-free heuristic */
    if ((uintptr_t)s < 0x10000) return 0;
    return win_wcslen(s);
}
MS_ABI char *hook_strcpy(char *d, const char *s) { return strcpy(d, s); }
MS_ABI char *hook_strncpy(char *d, const char *s, size_t n) { return strncpy(d, s, n); }
MS_ABI char *hook_strcat(char *d, const char *s) { return strcat(d, s); }
MS_ABI int   hook_strcmp(const char *a, const char *b) { return strcmp(a, b); }
MS_ABI int   hook_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
MS_ABI int   hook__strnicmp(const char *a, const char *b, size_t n) { return strncasecmp(a, b, n); }
MS_ABI char *hook_strchr(const char *s, int c) { return strchr(s, c); }
MS_ABI char *hook_strrchr(const char *s, int c) { return strrchr(s, c); }
MS_ABI char *hook_strstr(const char *h, const char *n) { return strstr(h, n); }
MS_ABI size_t hook_strspn(const char *s, const char *acc) { return strspn(s, acc); }
MS_ABI char *hook__strdup(const char *s) { return strdup(s); }
MS_ABI void *hook_memchr(const void *s, int c, size_t n) { return memchr(s, c, n); }
MS_ABI int   hook_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
MS_ABI void *hook_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
MS_ABI void *hook_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
MS_ABI void *hook_memset(void *d, int c, size_t n) { return memset(d, c, n); }
MS_ABI int   hook_atoi(const char *s) { return atoi(s); }
MS_ABI char *hook__ultoa(unsigned long v, char *buf, int base) {
    if (base == 10) { snprintf(buf, 33, "%lu", v); return buf; }
    snprintf(buf, 33, "%lx", v);
    return buf;
}
MS_ABI size_t hook_mbrtowc(wchar_t *dst, const char *src, size_t n, void *ps) {
    mbstate_t st; memset(&st, 0, sizeof(st));
    return mbrtowc(dst, src, n, ps ? (mbstate_t *)ps : &st);
}
MS_ABI size_t hook_wcrtomb(char *dst, wchar_t wc, void *ps) {
    mbstate_t st; memset(&st, 0, sizeof(st));
    return wcrtomb(dst, wc, ps ? (mbstate_t *)ps : &st);
}
MS_ABI int hook_isalnum(int c) { return isalnum(c); }
MS_ABI int hook_isalpha(int c) { return isalpha(c); }
MS_ABI int hook_isspace(int c) { return isspace(c); }

/* --- stdio (all FILE* are libc FILE* produced by our own hooks) ------ */
MS_ABI size_t hook_fwrite(const void *p, size_t sz, size_t n, FILE *f) { return fwrite(p, sz, n, f); }
MS_ABI size_t hook_fread(void *p, size_t sz, size_t n, FILE *f) { return fread(p, sz, n, f); }
MS_ABI int    hook_fputc(int c, FILE *f) { return fputc(c, f); }
MS_ABI char * hook_fgets(char *buf, int n, FILE *f) { return fgets(buf, n, f); }
MS_ABI int    hook_getc(FILE *f) { return getc(f); }
MS_ABI int    hook_fflush(FILE *f) { return fflush(f); }
MS_ABI int    hook_fclose(FILE *f) { return fclose(f); }
MS_ABI int    hook_feof(FILE *f) { return feof(f); }
MS_ABI int    hook_ferror(FILE *f) { return ferror(f); }
MS_ABI void   hook_clearerr(FILE *f) { clearerr(f); }
MS_ABI int    hook__fileno(FILE *f) { return fileno(f); }
MS_ABI int    hook__isatty(int fd) { return isatty(fd); }
MS_ABI intptr_t hook__get_osfhandle(int fd) { return fd; }
MS_ABI int    hook__write(int fd, const void *buf, unsigned n) {
    ssize_t r = write(fd, buf, n);
    return (int)r;
}
MS_ABI int    hook__close(int fd) { return close(fd); }
MS_ABI int    hook__setmode(int fd, int mode) { (void)fd; (void)mode; return 0; }

MS_ABI FILE *hook___acrt_iob_func(unsigned idx) {
    static FILE *table[3];
    table[0] = stdin; table[1] = stdout; table[2] = stderr;
    return idx < 3 ? table[idx] : stderr;
}

/* MSVC forwards *printf through __stdio_common_v*. The last parameter is
 * an MS-ABI va_list; we re-declare the hook as ms-variadic, so GCC's
 * __builtin_ms_va_arg can extract arguments correctly, and format with a
 * small printf engine that delegates each specifier to libc snprintf. */
typedef __builtin_ms_va_list ms_va_list;

static int ms_format(char *out, size_t cap, const char *fmt, ms_va_list args);

MS_ABI int hook___stdio_common_vfprintf(unsigned long long opts, void *stream,
                                        const char *fmt, void *locale, ...) {
    (void)opts; (void)locale;
    char buf[16384];
    ms_va_list args;
    __builtin_ms_va_start(args, locale);
    int n = ms_format(buf, sizeof(buf), fmt, args);
    __builtin_ms_va_end(args);
    if (n > 0) fwrite(buf, 1, (size_t)n, (FILE *)stream);
    return n;
}

MS_ABI int hook___stdio_common_vsprintf(unsigned long long opts, char *buffer,
                                        size_t bufsize, const char *fmt,
                                        void *locale, ...) {
    (void)opts; (void)locale;
    ms_va_list args;
    __builtin_ms_va_start(args, locale);
    int n = ms_format(buffer, bufsize ? bufsize : 1, fmt, args);
    __builtin_ms_va_end(args);
    return n;
}

MS_ABI int hook___stdio_common_vfwprintf(unsigned long long opts, void *stream,
                                         const wchar_t *fmt, void *locale, ...) {
    (void)opts; (void)stream; (void)fmt; (void)locale;
    return 0; /* wide printf: rare path, silently dropped for now */
}

/* --- a small MS-ABI printf engine ------------------------------------- */
static const char *skip_lenmod(const char *p) {
    while (*p && !strchr("diuxXocsfgeEp%", *p)) p++;
    return p;
}

static int ms_format(char *out, size_t cap, const char *fmt, ms_va_list args) {
    size_t pos = 0;
    char spec[64];

#define EMIT(...) do { \
        int _n = snprintf(out + pos, cap > pos ? cap - pos : 0, __VA_ARGS__); \
        if (_n < 0) return -1; \
        pos += (size_t)_n; \
    } while (0)

    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            if (pos + 1 < cap) out[pos] = *p;
            pos++;
            continue;
        }
        /* copy the whole specifier into spec[] */
        const char *q = p + 1;
        size_t k = 0;
        spec[k++] = '%';
        while (*q && k < sizeof(spec) - 2) {
            spec[k++] = *q;
            int conv = strchr("diuxXocsfgeEp%", *q) != NULL;
            q++;
            if (conv) break;
        }
        spec[k] = '\0';
        char conv = spec[k - 1];
        const char *lenmod = spec + 1;
        while (*lenmod && strchr("-+ 0#123456789.", *lenmod)) lenmod++;
        /* length modifier: h, hh, l, ll, w, I64, z, j, t */
        int is_l = 0, is_ll = 0, is_h = 0, is_hh = 0, is_i64 = 0, is_z = 0;
        if (!strncmp(lenmod, "I64", 3)) is_i64 = 1;
        else if (!strncmp(lenmod, "ll", 2)) is_ll = 1;
        else if (!strncmp(lenmod, "l", 1) || !strncmp(lenmod, "w", 1)) is_l = 1;
        else if (!strncmp(lenmod, "hh", 2)) is_hh = 1;
        else if (!strncmp(lenmod, "h", 1)) is_h = 1;
        else if (!strncmp(lenmod, "z", 1) || !strncmp(lenmod, "j", 1) || !strncmp(lenmod, "t", 1)) is_z = 1;

        switch (conv) {
        case '%':
            EMIT("%%");
            break;
        case 's': {
            char *s = __builtin_va_arg(args, char *);
            /* build a %s spec preserving flags/width/precision */
            char sspec[64]; size_t a = 0, b = 0;
            while (spec[a] && spec[a] != 's') { if (spec[a] == 'l' || spec[a] == 'w') { a++; continue; } sspec[b++] = spec[a++]; }
            sspec[b++] = 's'; sspec[b] = 0;
            EMIT(sspec, s ? s : "(null)");
            break;
        }
        case 'c': {
            int c = __builtin_va_arg(args, int);
            EMIT("%c", c);
            break;
        }
        case 'd': case 'i': {
            long long v;
            if (is_ll || is_i64) v = __builtin_va_arg(args, long long);
            else if (is_l || is_z) v = __builtin_va_arg(args, long);
            else if (is_h) v = (short)__builtin_va_arg(args, int);
            else if (is_hh) v = (signed char)__builtin_va_arg(args, int);
            else v = __builtin_va_arg(args, int);
            EMIT(spec, v);
            break;
        }
        case 'u': case 'x': case 'X': case 'o': {
            unsigned long long v;
            if (is_ll || is_i64) v = __builtin_va_arg(args, unsigned long long);
            else if (is_l || is_z) v = __builtin_va_arg(args, unsigned long);
            else if (is_h) v = (unsigned short)__builtin_va_arg(args, int);
            else if (is_hh) v = (unsigned char)__builtin_va_arg(args, int);
            else v = __builtin_va_arg(args, unsigned int);
            EMIT(spec, v);
            break;
        }
        case 'f': case 'e': case 'E': case 'g': case 'G': {
            double v = __builtin_va_arg(args, double);
            EMIT(spec, v);
            break;
        }
        case 'p': {
            void *v = __builtin_va_arg(args, void *);
            EMIT("%p", v);
            break;
        }
        default:
            /* unknown conversion: emit literally */
            EMIT("%s", spec);
            /* still consume one int arg conservatively */
            (void)__builtin_va_arg(args, int);
            break;
        }
        p = q - 1;
    }
    if (pos < cap) out[pos] = '\0';
    else if (cap) out[cap - 1] = '\0';
    return (int)pos;
#undef EMIT
}

/* --- MSVC environment / CRT plumbing --------------------------------- */
static char  *g_argv_store[64];
static int    g_argc_store = 0;
static win_wchar *g_wargv_store[64];
static win_wchar  g_warg_buf[64][512];
static char  *g_dummy_environ[1] = { NULL };
static int    g_dummy_int = 0;

static void parse_cmdline(void) {
    /* split g_cmdline honoring double quotes; fill both argv and wargv */
    static char argv_buf[4096];
    char *out = argv_buf;
    size_t cap = sizeof(argv_buf);
    char *p = g_cmdline;
    while (*p && g_argc_store < 64) {
        while (*p == ' ') p++;
        if (!*p) break;
        char *dst = out;
        int quoted = 0;
        if (*p == '"') { quoted = 1; p++; }
        while (*p && (quoted || *p != ' ')) {
            if (quoted && *p == '"') { p++; break; }
            if (cap < 2) break;
            *dst++ = *p++;
            cap--;
        }
        *dst++ = '\0';
        cap--;
        g_argv_store[g_argc_store] = out;
        {
            win_wchar *w = g_warg_buf[g_argc_store];
            const char *c = out;
            size_t wi = 0;
            for (; c[wi] && wi < 511; wi++) w[wi] = (win_wchar)(unsigned char)c[wi];
            w[wi] = 0;
        }
        g_wargv_store[g_argc_store] = g_warg_buf[g_argc_store];
        g_argc_store++;
        out = dst;
    }
}

/* UCRT __p___X family returns the ADDRESS OF the CRT variable, so the
 * caller does `*__p___argv()` to get the array itself. */
static char      **g_argv_var = g_argv_store;
static win_wchar **g_wargv_var = g_wargv_store;
static char       *g_env_null[1] = { NULL };
static char      **g_env_var = g_env_null;
static win_wchar  *g_wenv_null[1] = { NULL };
static win_wchar **g_wenv_var = g_wenv_null;

MS_ABI int *hook___p___argc(void) { return &g_argc_store; }
MS_ABI char ***hook___p___argv(void) { return &g_argv_var; }
MS_ABI win_wchar ***hook___p___wargv(void) { return &g_wargv_var; }
MS_ABI char ***hook___p__environ(void) { return &g_env_var; }
MS_ABI win_wchar ***hook___p__wenviron(void) { return &g_wenv_var; }
MS_ABI int *hook___p__commode(void) { return &g_dummy_int; }
MS_ABI int *hook___p__fmode(void) { return &g_dummy_int; }
MS_ABI char *hook_getenv(const char *k) { return getenv(k); }
MS_ABI int *hook__errno(void) { return &errno; }
MS_ABI char *hook_strerror(int e) { return strerror(e); }
MS_ABI void hook_perror(const char *s) { perror(s); }
MS_ABI void hook__wassert(const win_wchar *msg, const win_wchar *file, unsigned line) {
    (void)msg;
    fprintf(stderr, "[wineless] assertion failed at utf16 file:%u\n", line);
    abort();
}
MS_ABI void hook_abort(void) { abort(); }
MS_ABI void hook_exit(int code) { fflush(NULL); g_exit_code = code; longjmp(g_exit_env, 1); }
MS_ABI int  hook__exit(int code) { hook_exit(code); return code; }
MS_ABI void hook__tzset(void) { tzset(); }
MS_ABI int *hook___daylight(void) { return &daylight; }
MS_ABI long *hook___timezone(void) { return &timezone; }
MS_ABI char **hook___tzname(void) { return tzname; }
MS_ABI long long hook__time64(long long *t) {
    time_t now = time(NULL);
    if (t) *t = now;
    return now;
}
MS_ABI struct tm *hook__localtime64(const long long *t) {
    time_t tt = (time_t)*t;
    return localtime(&tt);
}
MS_ABI int hook__localtime64_s(struct tm *out, const long long *t) {
    time_t tt = (time_t)*t;
    if (!out || !localtime_r(&tt, out)) return 1;
    return 0;
}
MS_ABI long long hook__mkgmtime64(struct tm *tm) { return (long long)timegm(tm); }
MS_ABI struct tm *hook__gmtime64(const long long *t) {
    time_t tt = (time_t)*t;
    return gmtime(&tt);
}
MS_ABI size_t hook_strftime(char *buf, size_t max, const char *fmt, const struct tm *tm) {
    return strftime(buf, max, fmt, tm);
}
MS_ABI void *hook__fullpath(char *abs, const char *rel, size_t len) {
    char resolved[4096];
    if (!realpath(rel, resolved)) return NULL;
    if (abs) { snprintf(abs, len, "%s", resolved); return abs; }
    return strdup(resolved);
}
MS_ABI int hook__stat64(const char *path, void *buf) { (void)path; (void)buf; return -1; }
MS_ABI int hook__fstat64(int fd, void *buf) { (void)fd; (void)buf; return -1; }
MS_ABI FILE *hook__wfopen(const win_wchar *path, const win_wchar *mode) {
    char p[1024], m[16];
    size_t i;
    for (i = 0; i < sizeof(p) - 1 && path[i]; i++) p[i] = (char)path[i];
    p[i] = 0;
    for (i = 0; i < sizeof(m) - 1 && mode[i]; i++) m[i] = (char)mode[i];
    m[i] = 0;
    return fopen(p, m);
}
MS_ABI int hook__set_new_mode(int m) { (void)m; return 0; }
MS_ABI void hook__lock_file(FILE *f) { (void)f; }
MS_ABI void hook__unlock_file(FILE *f) { (void)f; }
MS_ABI int hook__initterm(void (**start)(void), void (**end)(void)) {
    for (; start < end; start++)
        if (*start) (*start)();
    return 0;
}
MS_ABI int hook__configure_narrow_argv(int mode) { (void)mode; return 0; }
MS_ABI int hook__initialize_narrow_environment(void) { return 0; }
MS_ABI void hook__set_app_type(int t) { (void)t; }
MS_ABI void hook__setusermatherr(void *f) { (void)f; }
MS_ABI void hook__set_invalid_parameter_handler(void *h) { (void)h; }
MS_ABI int hook__crt_atexit(void *f) { (void)f; return 0; }
MS_ABI int hook__crt_at_quick_exit(void *f) { (void)f; return 0; }
MS_ABI unsigned int hook__beginthreadex(void *sec, size_t stack, void *start,
                                        void *param, unsigned flags, unsigned *tid) {
    (void)sec; (void)stack; (void)start; (void)param; (void)flags;
    if (tid) *tid = 1;
    return 0; /* single-threaded mode: pretend the thread exists */
}
MS_ABI void hook__endthreadex(unsigned r) { (void)r; }
MS_ABI void *hook_localeconv(void) { return localeconv(); }
MS_ABI char *hook_setlocale(int cat, const char *loc) { return setlocale(cat, loc); }
MS_ABI void hook_signal(int sig, void *h) { (void)sig; (void)h; }
MS_ABI int hook_raise(int sig) { (void)sig; return 0; }

/* --- qsort with an MS-ABI comparator (libc qsort would mis-call it) --- */
typedef int (*ms_cmp2)(const void *, const void *);
typedef int (*ms_cmp3)(const void *, const void *, void *);

static void ms_isort2(char *base, size_t n, size_t w, ms_cmp2 cmp) {
    char *tmp = malloc(w);
    for (size_t i = 1; i < n; i++) {
        memcpy(tmp, base + i * w, w);
        size_t j = i;
        while (j > 0 && cmp(base + (j - 1) * w, tmp) > 0) {
            memcpy(base + j * w, base + (j - 1) * w, w);
            j--;
        }
        memcpy(base + j * w, tmp, w);
    }
    free(tmp);
}

static void ms_isort3(char *base, size_t n, size_t w, ms_cmp3 cmp, void *ctx) {
    char *tmp = malloc(w);
    for (size_t i = 1; i < n; i++) {
        memcpy(tmp, base + i * w, w);
        size_t j = i;
        while (j > 0 && cmp(base + (j - 1) * w, tmp, ctx) > 0) {
            memcpy(base + j * w, base + (j - 1) * w, w);
            j--;
        }
        memcpy(base + j * w, tmp, w);
    }
    free(tmp);
}

MS_ABI void hook_qsort(void *base, size_t n, size_t w, ms_cmp2 cmp) {
    if (n > 1 && w > 0) ms_isort2(base, n, w, cmp);
}
MS_ABI void hook_qsort_s(void *base, size_t n, size_t w, ms_cmp3 cmp, void *ctx) {
    if (n > 1 && w > 0) ms_isort3(base, n, w, cmp, ctx);
}

MS_ABI void hook_srand(unsigned s) { srand(s); }
MS_ABI int hook_rand(void) { return rand(); }
MS_ABI int hook_rand_s(unsigned *out) { if (out) *out = (unsigned)rand(); return 0; }

/* --- libm: doubles travel in xmm0/1 in both ABIs; pointers handled by attr */
#define MATH1(name) MS_ABI double hook_##name(double x) { return name(x); }
#define MATH2(name) MS_ABI double hook_##name(double x, double y) { return name(x, y); }

MATH1(acos) MATH1(acosh) MATH1(asin) MATH1(asinh) MATH1(atan) MATH1(atanh)
MATH1(cbrt) MATH1(cos) MATH1(cosh) MATH1(erf) MATH1(erfc) MATH1(exp)
MATH1(exp2) MATH1(expm1) MATH1(floor) MATH1(log) MATH1(log10) MATH1(log1p)
MATH1(log2) MATH1(logb) MATH1(nearbyint) MATH1(sin) MATH1(sinh) MATH1(sqrt)
MATH1(tan) MATH1(tanh) MATH1(tgamma) MATH1(round) MATH1(trunc)
MATH2(atan2) MATH2(copysign) MATH2(fdim) MATH2(fmax) MATH2(fmin) MATH2(fmod)
MATH2(nextafter) MATH2(pow) MATH2(remainder) MATH2(hypot)

MS_ABI double hook_fma(double x, double y, double z) { return fma(x, y, z); }
MS_ABI double hook_modf(double x, double *ip) { return modf(x, ip); }
MS_ABI double hook_frexp(double x, int *e) { return frexp(x, e); }
MS_ABI double hook__j0(double x) { return j0(x); }
MS_ABI double hook__j1(double x) { return j1(x); }
MS_ABI double hook__jn(int n, double x) { return jn(n, x); }
MS_ABI double hook__y0(double x) { return y0(x); }
MS_ABI double hook__y1(double x) { return y1(x); }
MS_ABI double hook__yn(int n, double x) { return yn(n, x); }

/* --- kernel32 the rest ---------------------------------------------- */
MS_ABI int hook_AreFileApisANSI(void) { return 1; }
MS_ABI int hook_CloseHandle(void *h) { (void)h; return 1; }
MS_ABI void *hook_CreateEventA(void *sa, int manual, int state, const char *name) {
    (void)sa; (void)manual; (void)state; (void)name;
    return (void *)(uintptr_t)0x400;
}
MS_ABI void *hook_CreateSemaphoreA(void *sa, long init, long max, const char *name) {
    (void)sa; (void)init; (void)max; (void)name;
    return (void *)(uintptr_t)0x401;
}
MS_ABI int hook_ReleaseSemaphore(void *h, long inc, long *prev) {
    (void)h; (void)inc; if (prev) *prev = 0; return 1;
}
MS_ABI int hook_SetEvent(void *h) { (void)h; return 1; }
MS_ABI int hook_ResetEvent(void *h) { (void)h; return 1; }
MS_ABI int hook_WaitForSingleObject(void *h, uint32_t ms) { (void)h; (void)ms; return 0; }
MS_ABI int hook_WaitForMultipleObjects(uint32_t n, void **h, int all, uint32_t ms) {
    (void)n; (void)h; (void)all; (void)ms; return 0;
}
MS_ABI int hook_DuplicateHandle(void *src_proc, void *src, void *dst_proc, void **dst,
                                uint32_t access, int inherit, uint32_t opts) {
    (void)src_proc; (void)dst_proc; (void)access; (void)inherit; (void)opts;
    if (dst) *dst = src;
    return 1;
}
MS_ABI void *hook_GetCurrentProcess(void) { return (void *)(uintptr_t)-1; }
MS_ABI void *hook_GetCurrentThread(void) { return (void *)(uintptr_t)-2; }
MS_ABI int hook_GetHandleInformation(void *h, uint32_t *flags) {
    (void)h; if (flags) *flags = 0; return 1;
}
MS_ABI int hook_GetProcessAffinityMask(void *p, uint64_t *pmask, uint64_t *smask) {
    (void)p;
    if (pmask) *pmask = 1;
    if (smask) *smask = 1;
    return 1;
}
MS_ABI int hook_SetProcessAffinityMask(void *p, uint64_t m) { (void)p; (void)m; return 1; }
MS_ABI int hook_GetThreadContext(void *t, void *ctx) { (void)t; (void)ctx; return 1; }
MS_ABI int hook_SetThreadContext(void *t, const void *ctx) { (void)t; (void)ctx; return 1; }
MS_ABI int hook_GetThreadPriority(void *t) { (void)t; return 0; }
MS_ABI int hook_SetThreadPriority(void *t, int pr) { (void)t; (void)pr; return 1; }
MS_ABI int hook_ResumeThread(void *t) { (void)t; return 0; }
MS_ABI int hook_SuspendThread(void *t) { (void)t; return 0; }
MS_ABI uint32_t hook_GetTickCount(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
MS_ABI int hook_QueryPerformanceCounter(uint64_t *out) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (out) *out = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    return 1;
}
MS_ABI int hook_QueryPerformanceFrequency(uint64_t *out) {
    if (out) *out = 1000000000ull;
    return 1;
}
MS_ABI uint32_t hook_GetTimeZoneInformation(void *tz) {
    (void)tz;
    return 0; /* TIME_ZONE_ID_UNKNOWN */
}
MS_ABI int hook_IsDBCSLeadByteEx(uint32_t cp, uint8_t b) { (void)cp; (void)b; return 0; }
MS_ABI int hook_IsDebuggerPresent(void) { return 0; }
MS_ABI int hook_IsProcessorFeaturePresent(uint32_t f) {
    (void)f;
    return 0; /* conservative: no special CPU features advertised */
}
MS_ABI void *hook_OpenProcess(uint32_t access, int inherit, uint32_t pid) {
    (void)access; (void)inherit; (void)pid;
    return (void *)(uintptr_t)0x402;
}
MS_ABI void hook_OutputDebugStringA(const char *s) { (void)s; }
MS_ABI void hook_RaiseException(uint32_t code, uint32_t flags, uint32_t nargs, const uint64_t *args) {
    (void)code; (void)flags; (void)nargs; (void)args;
    /* exceptions are swallowed; MSVC SEH is not emulated yet */
}
MS_ABI int hook_TryEnterCriticalSection(void *cs) { (void)cs; return 1; }
MS_ABI int hook_VirtualProtect(void *addr, size_t sz, uint32_t prot, uint32_t *old) {
    (void)addr; (void)sz; (void)prot; if (old) *old = 4 /* PAGE_READWRITE */;
    return 1;
}
MS_ABI size_t hook_VirtualQuery(void *addr, void *buf, size_t len) {
    (void)addr; (void)buf; (void)len; return 0;
}
MS_ABI void hook_Sleep(uint32_t ms) { usleep(ms * 1000u); }
MS_ABI void hook_TerminateProcess(void *h, uint32_t code) { (void)h; hook_ExitProcess(code); }
MS_ABI int hook_WriteConsoleW(void *h, const void *buf, uint32_t n, uint32_t *written, void *res) {
    /* UTF-16 -> ASCII (low byte) approximation; good enough for ASCII output */
    (void)h; (void)res;
    const uint16_t *w = buf;
    char tmp[4096];
    uint32_t k = n < sizeof(tmp) ? n : sizeof(tmp);
    for (uint32_t i = 0; i < k; i++) tmp[i] = (char)(w[i] & 0xFF);
    ssize_t r = write(STDOUT_FILENO, tmp, k);
    if (written) *written = (uint32_t)r;
    return 1;
}
MS_ABI uint64_t hook_GetTickCount64(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
MS_ABI void *hook_AddVectoredExceptionHandler(uint32_t first, void *handler) {
    (void)first; (void)handler;
    return (void *)(uintptr_t)0x900; /* fake VEH handle: pretend it is installed */
}
MS_ABI uint32_t hook_RemoveVectoredExceptionHandler(void *h) { (void)h; return 1; }

MS_ABI void *hook_DecodePointer(void *p) { return p; }
MS_ABI void *hook_EncodePointer(void *p) { return p; }
MS_ABI int hook_PathIsRelativeA(const char *p) { (void)p; return 0; }
MS_ABI long hook_longjmp(void *env, int val) { (void)env; (void)val; abort(); }
MS_ABI int hook___intrinsic_setjmpex(void *buf) { (void)buf; return 0; }
MS_ABI long hook___C_specific_handler(void *a, void *b, void *c, void *d) {
    (void)a; (void)b; (void)c; (void)d; return 0;
}


MS_ABI FILE *hook__fdopen(int fd, const char *mode) { return fdopen(fd, mode); }
MS_ABI void hook__cexit(void) { fflush(NULL); }
MS_ABI int hook__configure_wide_argv(int mode) { (void)mode; return 0; }
MS_ABI int hook__initialize_wide_environment(void) { return 0; }
MS_ABI int hook__open(const char *path, int flags, ...) { (void)path; (void)flags; return -1; }
MS_ABI void *hook_GetProcessHeap2(void) { return (void *)0x50000; }

/* symbol table additions live here */

/* ------------------------------------------------------------------ */
/* Symbol table + dynamic resolution                                   */
/* ------------------------------------------------------------------ */

static void *resolve_symbol(const char *name);

MS_ABI void *hook_GetProcAddress(void *mod, const char *name) {
    (void)mod;
    void *fn = resolve_symbol(name);
    if (!fn && getenv("WINELESS_TRACE"))
        fprintf(stderr, "[trace] GetProcAddress miss: %s\n", name ? name : "(ordinal)");
    return fn;
}
typedef struct { const char *name; void *func; } SymbolEntry;

static SymbolEntry g_symbols[] = {
    {"GetModuleHandleA", hook_GetModuleHandleA},
    {"GetModuleHandleW", hook_GetModuleHandleW},
    {"GetStdHandle", hook_GetStdHandle},
    {"GetCommandLineA", hook_GetCommandLineA},
    {"GetCommandLineW", hook_GetCommandLineW},
    {"GetProcessHeap", hook_GetProcessHeap},
    {"HeapAlloc", hook_HeapAlloc},
    {"HeapFree", hook_HeapFree},
    {"HeapReAlloc", hook_HeapReAlloc},
    {"WriteFile", hook_WriteFile},
    {"ReadFile", hook_ReadFile},
    {"WriteConsoleA", hook_WriteConsoleA},
    {"ExitProcess", hook_ExitProcess},
    {"GetFileType", hook_GetFileType},
    {"GetConsoleMode", hook_GetConsoleMode},
    {"SetConsoleMode", hook_SetConsoleMode},
    {"GetLastError", hook_GetLastError},
    {"SetLastError", hook_SetLastError},
    {"SetUnhandledExceptionFilter", hook_SetUnhandledExceptionFilter},
    {"GetCurrentProcessId", hook_GetCurrentProcessId},
    {"GetCurrentThreadId", hook_GetCurrentThreadId},
    {"GetSystemTimeAsFileTime", hook_GetSystemTimeAsFileTime},
    {"InitializeCriticalSection", hook_InitializeCriticalSection},
    {"EnterCriticalSection", hook_EnterCriticalSection},
    {"LeaveCriticalSection", hook_LeaveCriticalSection},
    {"DeleteCriticalSection", hook_DeleteCriticalSection},
    {"VirtualAlloc", hook_VirtualAlloc},
    {"VirtualFree", hook_VirtualFree},
    {"TlsAlloc", hook_TlsAlloc},
    {"TlsGetValue", hook_TlsGetValue},
    {"TlsSetValue", hook_TlsSetValue},
    {"TlsFree", hook_TlsFree},
    {"MultiByteToWideChar", hook_MultiByteToWideChar},
    {"WideCharToMultiByte", hook_WideCharToMultiByte},
    {"GetSystemMetrics", hook_GetSystemMetrics},
    {"GetProcAddress", hook_GetProcAddress},
    /* --- CRT bridge --- */
    {"malloc", hook_malloc}, {"calloc", hook_calloc},
    {"realloc", hook_realloc}, {"free", hook_free},
    {"strlen", hook_strlen}, {"wcslen", hook_wcslen},
    {"strcpy", hook_strcpy}, {"strncpy", hook_strncpy}, {"strcat", hook_strcat},
    {"strcmp", hook_strcmp}, {"strncmp", hook_strncmp}, {"_strnicmp", hook__strnicmp},
    {"strchr", hook_strchr}, {"strrchr", hook_strrchr}, {"strstr", hook_strstr},
    {"strspn", hook_strspn}, {"_strdup", hook__strdup},
    {"memchr", hook_memchr}, {"memcmp", hook_memcmp}, {"memcpy", hook_memcpy},
    {"memmove", hook_memmove}, {"memset", hook_memset},
    {"atoi", hook_atoi}, {"_ultoa", hook__ultoa},
    {"mbrtowc", hook_mbrtowc}, {"wcrtomb", hook_wcrtomb},
    {"isalnum", hook_isalnum}, {"isalpha", hook_isalpha}, {"isspace", hook_isspace},
    {"fwrite", hook_fwrite}, {"fread", hook_fread}, {"fputc", hook_fputc},
    {"fgets", hook_fgets}, {"getc", hook_getc}, {"fflush", hook_fflush},
    {"fclose", hook_fclose}, {"feof", hook_feof}, {"ferror", hook_ferror},
    {"clearerr", hook_clearerr}, {"_fileno", hook__fileno}, {"_isatty", hook__isatty},
    {"_get_osfhandle", hook__get_osfhandle}, {"_write", hook__write},
    {"_close", hook__close}, {"_setmode", hook__setmode},
    {"__acrt_iob_func", hook___acrt_iob_func},
    {"__stdio_common_vfprintf", hook___stdio_common_vfprintf},
    {"__stdio_common_vsprintf", hook___stdio_common_vsprintf},
    {"__stdio_common_vfwprintf", hook___stdio_common_vfwprintf},
    {"__p___argc", hook___p___argc}, {"__p___argv", hook___p___argv},
    {"__p___wargv", hook___p___wargv}, {"__p__environ", hook___p__environ},
    {"__p__wenviron", hook___p__wenviron}, {"__p__commode", hook___p__commode},
    {"__p__fmode", hook___p__fmode},
    {"getenv", hook_getenv}, {"_errno", hook__errno}, {"strerror", hook_strerror},
    {"perror", hook_perror}, {"_wassert", hook__wassert}, {"abort", hook_abort},
    {"exit", hook_exit}, {"_exit", hook__exit},
    {"_tzset", hook__tzset}, {"__daylight", hook___daylight},
    {"__timezone", hook___timezone}, {"__tzname", hook___tzname},
    {"_time64", hook__time64}, {"_localtime64", hook__localtime64},
    {"_localtime64_s", hook__localtime64_s}, {"_mkgmtime64", hook__mkgmtime64},
    {"_gmtime64", hook__gmtime64}, {"strftime", hook_strftime},
    {"_fullpath", hook__fullpath}, {"_stat64", hook__stat64}, {"_fstat64", hook__fstat64},
    {"_wfopen", hook__wfopen}, {"_set_new_mode", hook__set_new_mode},
    {"_lock_file", hook__lock_file}, {"_unlock_file", hook__unlock_file},
    {"_initterm", hook__initterm},
    {"_configure_narrow_argv", hook__configure_narrow_argv},
    {"_initialize_narrow_environment", hook__initialize_narrow_environment},
    {"_set_app_type", hook__set_app_type},
    {"__setusermatherr", hook__setusermatherr},
    {"_set_invalid_parameter_handler", hook__set_invalid_parameter_handler},
    {"_crt_atexit", hook__crt_atexit}, {"_crt_at_quick_exit", hook__crt_at_quick_exit},
    {"_beginthreadex", hook__beginthreadex}, {"_endthreadex", hook__endthreadex},
    {"localeconv", hook_localeconv}, {"setlocale", hook_setlocale},
    {"signal", hook_signal}, {"raise", hook_raise},
    {"qsort", hook_qsort}, {"qsort_s", hook_qsort_s},
    {"_fdopen", hook__fdopen}, {"_cexit", hook__cexit},
    {"_configure_wide_argv", hook__configure_wide_argv},
    {"_initialize_wide_environment", hook__initialize_wide_environment},
    {"_open", hook__open},
    {"srand", hook_srand}, {"rand", hook_rand}, {"rand_s", hook_rand_s},
    /* --- libm --- */
    {"acos", hook_acos}, {"acosh", hook_acosh}, {"asin", hook_asin}, {"asinh", hook_asinh},
    {"atan", hook_atan}, {"atanh", hook_atanh}, {"cbrt", hook_cbrt},
    {"cos", hook_cos}, {"cosh", hook_cosh}, {"erf", hook_erf}, {"erfc", hook_erfc},
    {"exp", hook_exp}, {"exp2", hook_exp2}, {"expm1", hook_expm1},
    {"floor", hook_floor}, {"log", hook_log}, {"log10", hook_log10}, {"log1p", hook_log1p},
    {"log2", hook_log2}, {"logb", hook_logb}, {"nearbyint", hook_nearbyint},
    {"sin", hook_sin}, {"sinh", hook_sinh}, {"sqrt", hook_sqrt},
    {"tan", hook_tan}, {"tanh", hook_tanh}, {"tgamma", hook_tgamma},
    {"round", hook_round}, {"trunc", hook_trunc}, {"fma", hook_fma},
    {"atan2", hook_atan2}, {"copysign", hook_copysign}, {"fdim", hook_fdim},
    {"fmax", hook_fmax}, {"fmin", hook_fmin}, {"fmod", hook_fmod},
    {"nextafter", hook_nextafter}, {"pow", hook_pow}, {"remainder", hook_remainder},
    {"hypot", hook_hypot}, {"modf", hook_modf}, {"frexp", hook_frexp},
    {"_j0", hook__j0}, {"_j1", hook__j1}, {"_jn", hook__jn},
    {"_y0", hook__y0}, {"_y1", hook__y1}, {"_yn", hook__yn},
    /* --- kernel32, the long tail --- */
    {"AreFileApisANSI", hook_AreFileApisANSI}, {"CloseHandle", hook_CloseHandle},
    {"CreateEventA", hook_CreateEventA}, {"CreateSemaphoreA", hook_CreateSemaphoreA},
    {"ReleaseSemaphore", hook_ReleaseSemaphore},
    {"SetEvent", hook_SetEvent}, {"ResetEvent", hook_ResetEvent},
    {"WaitForSingleObject", hook_WaitForSingleObject},
    {"WaitForMultipleObjects", hook_WaitForMultipleObjects},
    {"DuplicateHandle", hook_DuplicateHandle},
    {"GetCurrentProcess", hook_GetCurrentProcess}, {"GetCurrentThread", hook_GetCurrentThread},
    {"GetHandleInformation", hook_GetHandleInformation},
    {"GetProcessAffinityMask", hook_GetProcessAffinityMask},
    {"SetProcessAffinityMask", hook_SetProcessAffinityMask},
    {"GetThreadContext", hook_GetThreadContext}, {"SetThreadContext", hook_SetThreadContext},
    {"GetThreadPriority", hook_GetThreadPriority}, {"SetThreadPriority", hook_SetThreadPriority},
    {"ResumeThread", hook_ResumeThread}, {"SuspendThread", hook_SuspendThread},
    {"GetTickCount", hook_GetTickCount},
    {"QueryPerformanceCounter", hook_QueryPerformanceCounter},
    {"QueryPerformanceFrequency", hook_QueryPerformanceFrequency},
    {"GetTimeZoneInformation", hook_GetTimeZoneInformation},
    {"IsDBCSLeadByteEx", hook_IsDBCSLeadByteEx},
    {"IsDebuggerPresent", hook_IsDebuggerPresent},
    {"IsProcessorFeaturePresent", hook_IsProcessorFeaturePresent},
    {"OpenProcess", hook_OpenProcess},
    {"OutputDebugStringA", hook_OutputDebugStringA},
    {"RaiseException", hook_RaiseException},
    {"TryEnterCriticalSection", hook_TryEnterCriticalSection},
    {"VirtualProtect", hook_VirtualProtect}, {"VirtualQuery", hook_VirtualQuery},
    {"Sleep", hook_Sleep}, {"TerminateProcess", hook_TerminateProcess},
    {"WriteConsoleW", hook_WriteConsoleW},
    {"GetTickCount64", hook_GetTickCount64},
    {"AddVectoredExceptionHandler", hook_AddVectoredExceptionHandler},
    {"RemoveVectoredExceptionHandler", hook_RemoveVectoredExceptionHandler},
    {"DecodePointer", hook_DecodePointer}, {"EncodePointer", hook_EncodePointer},
    {"PathIsRelativeA", hook_PathIsRelativeA},
    {"longjmp", hook_longjmp}, {"__intrinsic_setjmpex", hook___intrinsic_setjmpex},
    {"__C_specific_handler", hook___C_specific_handler},
    {NULL, NULL}
};

static void *resolve_symbol(const char *name) {
    for (int i = 0; g_symbols[i].name != NULL; i++)
        if (strcmp(g_symbols[i].name, name) == 0) return g_symbols[i].func;
    return NULL;
}



MS_ABI uint64_t generic_stub(void) { return 0; }

/* ------------------------------------------------------------------ */
/* PE64 loader                                                         */
/* ------------------------------------------------------------------ */

static void build_cmdline(int argc, char **argv) {
    /* argv[0] = loader, argv[1] = exe path, argv[2..] = emulated program args */
    const char *prog = argc > 1 ? argv[1] : "app.exe";
    const char *base = strrchr(prog, '/');
    base = base ? base + 1 : prog;
    snprintf(g_cmdline, sizeof(g_cmdline), "\"%s\"", base);
    for (int i = 2; i < argc; i++) {
        size_t len = strlen(g_cmdline);
        snprintf(g_cmdline + len, sizeof(g_cmdline) - len, " %s", argv[i]);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target.exe> [args...]\n", argv[0]);
        return 64;
    }
    build_cmdline(argc, argv);

    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "[-] cannot open %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 264) { fprintf(stderr, "[-] file too small to be a PE\n"); fclose(f); return 1; }
    uint8_t *pe = malloc((size_t)fsize);
    if (fread(pe, 1, (size_t)fsize, f) != (size_t)fsize) { fclose(f); return 1; }
    fclose(f);

    if (pe[0] != 'M' || pe[1] != 'Z') { fprintf(stderr, "[-] bad MZ signature\n"); return 1; }
    uint32_t e_lfanew = *(uint32_t *)(pe + 0x3C);
    if (memcmp(pe + e_lfanew, "PE\0\0", 4) != 0) { fprintf(stderr, "[-] bad PE signature\n"); return 1; }

    uint16_t num_sections = *(uint16_t *)(pe + e_lfanew + 0x6);
    uint8_t *opt = pe + e_lfanew + 0x18;
    if (*(uint16_t *)opt != 0x20B) { fprintf(stderr, "[-] only PE32+ (x64) is supported\n"); return 1; }

    uint64_t pref_base   = *(uint64_t *)(opt + 0x18);
    uint32_t entry_rva   = *(uint32_t *)(opt + 0x10);
    uint32_t image_size  = *(uint32_t *)(opt + 0x38);
    uint32_t headers_sz  = *(uint32_t *)(opt + 0x3C);
    uint8_t *data_dirs   = opt + 0x70;
    uint32_t import_rva  = *(uint32_t *)(data_dirs + 1 * 8 + 0);
    uint32_t reloc_rva   = *(uint32_t *)(data_dirs + 5 * 8 + 0);
    uint32_t reloc_size  = *(uint32_t *)(data_dirs + 5 * 8 + 4);

    /* 1. Map the image */
    g_image_base = mmap((void *)pref_base, image_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_image_base_fwd = g_image_base;
    if (g_image_base == MAP_FAILED)
        g_image_base = mmap(NULL, image_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_image_base == MAP_FAILED) { fprintf(stderr, "[-] mmap failed\n"); return 1; }

    /* 2. Copy headers + sections */
    memcpy(g_image_base, pe, headers_sz);
    uint8_t *sec_hdr = opt + *(uint16_t *)(pe + e_lfanew + 0x14);
    for (uint16_t i = 0; i < num_sections; i++) {
        uint8_t *s = sec_hdr + (size_t)i * 40;
        uint32_t va  = *(uint32_t *)(s + 12);
        uint32_t rsz = *(uint32_t *)(s + 16);
        uint32_t rptr = *(uint32_t *)(s + 20);
        if (rsz > 0 && va + rsz <= image_size && rptr + rsz <= (uint32_t)fsize)
            memcpy(g_image_base + va, pe + rptr, rsz);
    }

    /* 3. Apply DIR64 base relocations */
    int64_t delta = (int64_t)(intptr_t)g_image_base - (int64_t)pref_base;
    if (reloc_rva && delta != 0) {
        uint32_t off = 0;
        while (off + 8 <= reloc_size) {
            uint32_t page_rva  = *(uint32_t *)(pe + reloc_rva + off);
            uint32_t block_sz  = *(uint32_t *)(pe + reloc_rva + off + 4);
            if (!block_sz || off + block_sz > reloc_size) break;
            uint32_t count = (block_sz - 8) / 2;
            uint16_t *entries = (uint16_t *)(pe + reloc_rva + off + 8);
            for (uint32_t j = 0; j < count; j++) {
                uint16_t type = entries[j] >> 12, item = entries[j] & 0xFFF;
                if (type == 10) { /* IMAGE_REL_BASED_DIR64 */
                    uint64_t *tgt = (uint64_t *)(g_image_base + page_rva + item);
                    *tgt += (uint64_t)delta;
                }
            }
            off += block_sz;
        }
    }

    /* 4. Resolve the IAT against the hook table */
    if (import_rva) {
        uint8_t *desc = g_image_base + import_rva;
        while (1) {
            uint32_t oft = *(uint32_t *)(desc + 0);
            uint32_t ft  = *(uint32_t *)(desc + 16);
            if (!oft && !ft) break;
            uint32_t thunk_rva = oft ? oft : ft;
            uint64_t *thunk = (uint64_t *)(g_image_base + thunk_rva);
            uint64_t *iat   = (uint64_t *)(g_image_base + ft);
            while (*thunk) {
                if (!(*thunk >> 63)) { /* import by name */
                    char *name = (char *)(g_image_base + (*thunk & 0x7FFFFFFF) + 2);
                    void *fn = resolve_symbol(name);
                    if (fn) *iat = (uint64_t)(intptr_t)fn;
                    else {
                        fprintf(stderr, "[wineless] unresolved import '%s' -> stub\n", name);
                        *iat = (uint64_t)(intptr_t)generic_stub;
                    }
                } else *iat = (uint64_t)(intptr_t)generic_stub;
                thunk++; iat++;
            }
            desc += 20;
        }
    }

    /* 5. TEB / PEB via GS, with a working static-TLS array */
    memset(&g_teb, 0, sizeof(g_teb));
    memset(&g_peb, 0, sizeof(g_peb));
    for (int i = 0; i < WINELESS_TLS_SLOTS; i++) {
        g_tls_array[i] = g_tls_blocks[i]; /* zero-filled TLS storage per slot */
    }
    g_teb.Self = &g_teb;
    g_teb.ThreadLocalStoragePointer = g_tls_array;
    g_teb.ProcessEnvironmentBlock = &g_peb;
    g_teb.LastErrorValue = 0;
    g_peb.ImageBaseAddress = g_image_base;
    g_peb.ProcessHeap = (void *)0x50000;
    g_peb.NumberOfProcessors = 1;
    syscall(SYS_arch_prctl, ARCH_SET_GS, &g_teb);

    {
        const char *t = getenv("WINELESS_TRACE");
        extern int g_trace_wcslen;
        g_trace_wcslen = (t && *t);
    }
    struct sigaction sa = {0};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);

    parse_cmdline();

    /* 6. Jump */
    typedef void (*WinEntry)(void);
    WinEntry entry = (WinEntry)(g_image_base + entry_rva);

    fprintf(stderr, "[wineless] base=%p entry_rva=0x%x cmdline='%s'\n",
            (void *)g_image_base, entry_rva, g_cmdline);
    fprintf(stderr, "[wineless] executing PE entry point...\n");

    if (setjmp(g_exit_env) == 0) entry();

    fflush(NULL);
    fprintf(stderr, "[wineless] ExitProcess(%d) captured\n", g_exit_code);
    return g_exit_code;
}
