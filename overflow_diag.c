/*
 * overflow_diag.c — Determine if intf overflow actually happens
 * Build (x64): cl /O2 overflow_diag.c /Fe:overflow_diag.exe
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DEVICE_PATH       L"\\\\.\\CtxUsbMonitor"
#define IOCTL_SET_POLICY  0x222244
#define IOCTL_GET_POLICY  0x222240

typedef struct _MY_IO_STATUS_BLOCK {
    union {
        long Status;
        void *Pointer;
    };
    ULONG_PTR Information;
} MY_IOSB;

typedef long (__stdcall *NtDIOCF_t)(
    HANDLE FileHandle, HANDLE Event, void *ApcRoutine, void *ApcContext,
    MY_IOSB *IoStatusBlock, ULONG IoControlCode,
    void *InputBuffer, ULONG InputBufferLength,
    void *OutputBuffer, ULONG OutputBufferLength);

static NtDIOCF_t NtDIOCF = NULL;

static HANDLE open_dev(void) {
    return CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
}

/* Send policy with N intf entries (non-zero sequential) */
static BOOL send_policy_raw(HANDLE dev, int intf_count, MY_IOSB *iosb) {
    size_t maxlen = 64 + (size_t)intf_count * 4;
    WCHAR *pol = (WCHAR *)calloc(maxlen, sizeof(WCHAR));
    if (!pol) return FALSE;

    wcscpy(pol, L"allow: intf=");
    WCHAR *p = pol + wcslen(pol);
    for (int i = 0; i < intf_count; i++) {
        BYTE val = (BYTE)((i % 255) + 1);
        if (i < intf_count - 1)
            p += swprintf(p, 8, L"%02X,", val);
        else
            p += swprintf(p, 8, L"%02X", val);
    }

    DWORD bytes = (DWORD)(wcslen(pol) + 1) * sizeof(WCHAR);
    iosb->Status = 0;
    iosb->Information = 0;

    long st = NtDIOCF(dev, NULL, NULL, NULL, iosb,
                      IOCTL_SET_POLICY, pol, bytes, NULL, 0);
    free(pol);
    return (st >= 0);
}

/* ─── Test A: Probe read-back IOCTLs ─── */
static void test_get_ioctl(HANDLE dev) {
    printf("=== TEST A: Probe read-back IOCTLs ===\n\n");

    /* Send a known policy */
    printf("[*] Sending: allow: intf=01,02,03,04,05\n");
    WCHAR pol[] = L"allow: intf=01,02,03,04,05";
    DWORD ret = 0;
    DeviceIoControl(dev, IOCTL_SET_POLICY, pol, sizeof(pol), NULL, 0, &ret, NULL);

    /* Probe IOCTLs */
    DWORD codes[] = { 0x222240, 0x222248, 0x22224C, 0x222238, 0x222234, 0x222220, 0x222250 };
    int ncodes = 7;
    BYTE outbuf[4096];
    int i;

    for (i = 0; i < ncodes; i++) {
        DWORD returned = 0;
        memset(outbuf, 0xAA, sizeof(outbuf));
        SetLastError(0);
        BOOL ok = DeviceIoControl(dev, codes[i], NULL, 0,
                                   outbuf, sizeof(outbuf), &returned, NULL);
        printf("[*] IOCTL 0x%06X (no input):  ok=%d ret=%4lu err=%lu\n",
               codes[i], ok, returned, GetLastError());
        if (ok && returned > 0) {
            printf("    Data: ");
            DWORD j;
            for (j = 0; j < returned && j < 64; j++) printf("%02X ", outbuf[j]);
            printf("\n");
        }

        /* With input */
        returned = 0;
        memset(outbuf, 0xAA, sizeof(outbuf));
        ok = DeviceIoControl(dev, codes[i], pol, sizeof(pol),
                             outbuf, sizeof(outbuf), &returned, NULL);
        if (ok && returned > 0) {
            printf("    (w/input): ok=%d ret=%lu: ", ok, returned);
            DWORD j;
            for (j = 0; j < returned && j < 64; j++) printf("%02X ", outbuf[j]);
            printf("\n");
        }
    }
    printf("\n");
}

/* ─── Test B: Entry count scaling ─── */
static void test_entry_count(void) {
    printf("=== TEST B: Entry count scaling (key test) ===\n\n");
    printf("    Count  Status      Information  InputBytes\n");
    printf("    -----  ----------  -----------  ----------\n");

    int counts[] = { 10, 50, 100, 200, 250, 255, 256, 257, 258, 259, 260,
                     270, 300, 400, 500, 600, 800, 1000 };
    int nc = sizeof(counts) / sizeof(counts[0]);
    int i;

    for (i = 0; i < nc; i++) {
        HANDLE dev = open_dev();
        if (dev == INVALID_HANDLE_VALUE) continue;

        MY_IOSB iosb;
        int n = counts[i];

        /* Calculate input size for reference */
        size_t maxlen = 64 + (size_t)n * 4;
        WCHAR *pol = (WCHAR *)calloc(maxlen, sizeof(WCHAR));
        wcscpy(pol, L"allow: intf=");
        WCHAR *p = pol + wcslen(pol);
        int j;
        for (j = 0; j < n; j++) {
            BYTE val = (BYTE)((j % 255) + 1);
            if (j < n - 1) p += swprintf(p, 8, L"%02X,", val);
            else p += swprintf(p, 8, L"%02X", val);
        }
        DWORD polbytes = (DWORD)(wcslen(pol) + 1) * sizeof(WCHAR);

        iosb.Status = 0;
        iosb.Information = 0;
        long st = NtDIOCF(dev, NULL, NULL, NULL, &iosb,
                          IOCTL_SET_POLICY, pol, polbytes, NULL, 0);

        printf("    %5d  0x%08lX  %11llu  %10lu",
               n, (unsigned long)st, (unsigned long long)iosb.Information, polbytes);

        /* Mark the 258/259 boundary */
        if (n == 258) printf("  <-- safe limit");
        if (n == 259) printf("  <-- first overflow?");
        printf("\n");

        free(pol);
        CloseHandle(dev);
    }

    printf("\n[*] KEY: If Information/Status changes at 258→259, overflow is real.\n");
    printf("[*]       If unchanged through 1000, driver may truncate or alloc dynamically.\n\n");
}

/* ─── Test C: Output buffer on 0x222244 ─── */
static void test_output_on_set(void) {
    printf("=== TEST C: Does SET IOCTL also return output? ===\n\n");

    HANDLE dev = open_dev();
    if (dev == INVALID_HANDLE_VALUE) return;

    WCHAR pol[] = L"allow: intf=01,02,03";
    BYTE outbuf[4096];
    MY_IOSB iosb;

    memset(outbuf, 0xBB, sizeof(outbuf));
    iosb.Status = 0;
    iosb.Information = 0;

    long st = NtDIOCF(dev, NULL, NULL, NULL, &iosb,
                      IOCTL_SET_POLICY, pol, sizeof(pol),
                      outbuf, sizeof(outbuf));

    printf("[*] 0x222244 with output buffer (4096):\n");
    printf("    Status=0x%08lX Information=%llu\n",
           (unsigned long)st, (unsigned long long)iosb.Information);
    if (iosb.Information > 0 && iosb.Information < 4096) {
        printf("    Output: ");
        ULONG_PTR j;
        for (j = 0; j < iosb.Information && j < 64; j++)
            printf("%02X ", outbuf[j]);
        printf("\n");
    }

    CloseHandle(dev);
    printf("\n");
}

int main(void) {
    printf("=== ctxusbmon overflow diagnostic ===\n\n");

    NtDIOCF = (NtDIOCF_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtDeviceIoControlFile");
    if (!NtDIOCF) {
        printf("[-] Can't resolve NtDeviceIoControlFile\n");
        return 1;
    }

    HANDLE dev = open_dev();
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[-] Can't open device: %lu\n", GetLastError());
        return 1;
    }

    test_get_ioctl(dev);
    CloseHandle(dev);

    test_entry_count();
    test_output_on_set();

    printf("=== DONE ===\n");
    return 0;
}
