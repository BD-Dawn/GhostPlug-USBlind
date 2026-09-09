# GhostPlug & USBlind

Two vulnerabilities in the Citrix USB Monitor kernel driver (`ctxusbmon.sys`) that let any logged-in user silently bypass USB device policies.

- **GhostPlug** (CWE-787) - A memory overflow that corrupts USB deny rules, allowing blocked devices to connect undetected - like a ghost plugging in.
- **USBlind** (CWE-125) - A read bug that causes the driver to scan past its own memory boundaries, blindly reading data it was never meant to see.

## What's Affected
- **Driver:** ctxusbmon.sys v7.47.0.2290 (the Citrix component that controls which USB devices users are allowed to plug in)
- **OS:** Windows 10 22H2 (build 19045.6466), 64-bit
- **Who can trigger it:** Any logged-in user - no elevated privileges required

## The Bugs

Citrix installs a kernel driver called `ctxusbmon.sys` that enforces USB device policies - for example, "block all USB storage devices." This driver has two bugs that let a regular user bypass those policies entirely.

### USBlind - Reading Too Far (CWE-125)

When the driver receives a request from a user program, it needs to measure how long the input text is. The function it uses (`wcsnlen`) expects the length in *characters*, but the driver passes it in *bytes*. Since each character is 2 bytes wide, the function reads **twice as far** as it should - potentially reading sensitive data from neighboring memory.

What the driver does (wrong):
```c
// InputBufferLength is in BYTES (e.g., 100 bytes)
// But wcsnlen treats its second argument as a CHARACTER count
// Each wide character is 2 bytes, so this scans 100 characters = 200 bytes
length = wcsnlen(input_string, InputBufferLength);
```

What it should do (fixed):
```c
// Divide by 2 to convert bytes to characters
length = wcsnlen(input_string, InputBufferLength / sizeof(WCHAR));
```

### GhostPlug - Writing Past the End of a List (CWE-787)

When the driver parses a USB policy rule, it stores interface numbers in a fixed-size list that holds 256 entries. The problem: **it never checks whether the list is full.** If you send a rule with 300+ interface entries, it keeps writing past the end of the list and overwrites whatever data sits next to it in memory.

What the driver does (wrong):
```c
// The list only has room for 256 entries, but the loop never checks that
while (more_entries_to_parse) {
    value = parse_next_entry(input);
    rule->intf_array[index] = value;   // no check: is index < 256?
    index++;                            // keeps going past 256, 257, 258...
}
```

What it should do (fixed):
```c
while (more_entries_to_parse) {
    if (index >= 256) break;            // stop before we go out of bounds
    value = parse_next_entry(input);
    rule->intf_array[index] = value;
    index++;
}
```

Think of it like a notebook with 256 lines. The driver starts writing on line 1 and keeps going - but when it hits line 257, it doesn't stop. It just keeps writing onto whatever page comes next.

## How GhostPlug Works

### Setting Up the Overflow

The driver stores each USB policy rule as a block of memory (a "rule struct"). When you create multiple rules quickly from the same program, the system places them right next to each other in memory - like adjacent pages in that notebook.

The attack creates 64 rules in alternating order: allow, deny, allow, deny, and so on. Then it overflows the "allow" rules so the extra data spills into the neighboring "deny" rules.

### What Gets Overwritten

Each deny rule has match fields that control which devices it blocks:

- **Device class** (e.g., storage, keyboard, printer)
- **Vendor ID** (who made it)
- **Product ID** (which specific device)
- **And a few more**

When a field is set to the special "wildcard" value, it means "match everything." A "deny all USB" rule has every field set to wildcard so it blocks all devices.

The overflow replaces those wildcard values with a specific number (254). Now the deny rule only blocks devices that happen to have vendor ID 254 *and* product ID 254 *and* class 254 - a combination that doesn't match any real USB device. The deny rule is effectively **dead**.

### Why It's Reliable

Because the rules are the same size and created from the same program thread, the system's memory manager places them in a predictable, back-to-back layout. This isn't a lucky guess - it's how the Windows memory allocator works for same-size allocations. The overflow consistently lands on the intended target.

### Limitations

- Its direct impact is limited to **disabling USB policies**

## Why This Matters

In Citrix virtual desktop environments, USB policies are a key security control. Organizations use them to prevent:

- **Data theft** - blocking USB storage so users can't copy files out
- **Keystroke injection** - blocking USB keyboards that could type malicious commands
- **Unauthorized access** - blocking smart card readers or biometric devices in restricted sessions

GhostPlug lets any logged-in user **silently disable those controls.** The policies still *appear* active in the Citrix admin console, but in memory they've been corrupted and no longer match any device. A user could then plug in a USB drive and exfiltrate data without triggering any alert.

## Steps to Reproduce

1. Compile the proof-of-concept on 64-bit Windows:
   ```
   cl /O2 policy_bypass.c /Fe:policy_bypass.exe
   ```

2. Run it as a normal (non-admin) user:
   ```
   policy_bypass.exe
   ```

3. The tool opens the Citrix USB driver (which allows access to any logged-in user), creates a batch of alternating allow/deny rules, overflows the allow rules into the deny rules, and corrupts the deny rules' match fields.

4. To verify the full impact:
   - Set up a "deny all USB" policy in Citrix
   - Run the exploit
   - Plug in a USB device that was previously blocked
   - Observe that the device now connects successfully

## Proof-of-Concept Files

| File | Purpose |
|------|---------|
| `policy_bypass.c` | GhostPlug exploit - overflows rule structs to disable deny policies |
| `overflow_diag.c` | Confirms the driver processes 1000+ entries without any bounds check |
| `oob_leak.c` | USBlind exploit - demonstrates the read bug by leaking adjacent kernel memory |

## How to Fix It

1. **Add a bounds check:** Before writing each interface entry, verify the index hasn't exceeded 256 (the list capacity). This is a one-line fix in the driver code.

2. **Validate input length:** Count the number of interface values in the input *before* starting the write loop. Reject any request that exceeds the limit.

3. **Fix the read bug:** Divide the buffer length by 2 before passing it to the string length function, so it measures characters correctly instead of reading twice as far.

## Windows 11 Notes

This exploit is more likely to crash (blue screen) on Windows 11 than Windows 10. Windows 11 added several memory protection improvements:

- **Stricter memory bookkeeping:** Windows 11's memory manager validates blocks more aggressively when they're freed. Corrupted data near the edges of memory regions gets caught and triggers a crash instead of being silently accepted.
- **Guard pages:** Windows 11 places protective "tripwire" pages between memory regions more often. Overflows that would quietly hit the next allocation on Windows 10 hit these tripwires on Windows 11, causing an immediate crash.
- **Zero-initialization by default:** Windows 11 clears all new memory blocks to zero. On Windows 10, recycled memory could contain leftover data that happened to absorb partial overwrites without breaking anything - Windows 11 doesn't have that cushion.

**The bottom line:** The policy bypass itself still works on Windows 11 when the memory layout cooperates, but achieving that layout is harder, and failed attempts are more likely to crash the system instead of failing silently.

## Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-29 | Vulnerabilities discovered and confirmed |
| 2026-06-02 | Report submitted to Citrix's Cloud Software Group PSIRT |
| 2026-06-14 | Citrix Security Group requested follow-up details |
| 2026-06-15 | Additional details delivered |
| 2026-07-03 | Citrix confirmed the issue impacts the product, passed to engineering |
| 2026-09-08 | Patch release |
| 2026-09-08 | Public disclosure |

## References

- [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697034&articleURL=Citrix_Workspace_app_for_Windows_Security_Bulletin_CVE_2026_78546_and_CVE_2026_78547
