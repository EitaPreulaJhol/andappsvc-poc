// andappsvc-client — protocol definitions for andappsvc2_64.sys
//
// Reconstructed from the driver by static analysis (see re/analysis.md).
// The driver exposes a METHOD_BUFFERED, FILE_ANY_ACCESS control device and
// implements a small state machine per calling process ("session").
//
//   IRP_MJ_CREATE      -> CreateProcessSession   (session keyed by PID, max 100)
//   level 0            -> discovery: 0x...81C / 0x...824 / 0x...828
//   IOCTL 0x...828     -> authenticate (promotes the session to level 1 or 2)
//   level 1            -> full policy surface
//   IRP_MJ_CLEANUP     -> DeleteProcessSession   (drops the session, and the Ob
//                         callbacks once the table is empty)
//
// The driver protects *the process that owns the session*: the Ob pre-operation
// callback looks the handle target's PID up in the session table and only
// enforces the policy when that entry has Monitored != 0, which is only ever set
// by IOCTL 0xAA023800 issued *by that process*. A client therefore protects the
// process it runs in; protecting a foreign process requires running the
// sequence inside it (see the injected payload).
#pragma once

#include <cstdint>

namespace andappsvc {

// ---------------------------------------------------------------- device names
// CreateDriverDevice (0x140003E10) builds "\Device\Htsysm49BE01" from a stack
// DWORD pair plus DeobfuscateWideString(g_ObfuscatedNameTable).
inline constexpr wchar_t kDeviceName[] = L"Htsysm49BE01";
inline constexpr wchar_t kDeviceWin32Path[] = L"\\\\.\\Htsysm49BE01";
inline constexpr wchar_t kDeviceNtPath[] = L"\\??\\Htsysm49BE01";
inline constexpr wchar_t kDeviceObjectPath[] = L"\\Device\\Htsysm49BE01";

inline constexpr uint32_t kDeviceType = 0xAA02;      // IoCreateDevice DeviceType
inline constexpr uint32_t kProtocolVersion = 1100;   // 0x44C, returned by 0xAA02381C

// Session command level (PROC_TRACK_ENTRY.CommandLevel, entry+0x6C).
inline constexpr uint16_t kLevelDiscovery = 0;
inline constexpr uint16_t kLevelAuthenticated = 1;
inline constexpr uint16_t kLevelRejected = 2;

// -------------------------------------------------------------------- IOCTLs
// CTL_CODE(0xAA02, 0xE00 + n, METHOD_BUFFERED, FILE_ANY_ACCESS)
enum IoctlCode : uint32_t {
  kCmdSetProtectedImage   = 0xAA023800,  // in >= 0x208 bytes, out 0
  kCmdDisableProtection   = 0xAA023804,  // no buffers
  kCmdEnableProtection    = 0xAA023808,  // no buffers
  kCmdSetTrustedPids      = 0xAA02380C,  // in 20 bytes (5 x ULONG), out 0
  kCmdSetParentBlacklist  = 0xAA023810,  // in 12 bytes (3 x ULONG), out 0
  kCmdSetExpectedParent   = 0xAA023814,  // in 4 bytes (ULONG), out 0
  kCmdGetAccessLog        = 0xAA023818,  // in 0, out 48 bytes (12 x ULONG)
  kCmdGetProtocolVersion  = 0xAA02381C,  // in 0, out 4 bytes (level 0 OK)
  kCmdGetReturnAddress    = 0xAA023820,  // in 0, out 8 bytes (level 1 only)
  kCmdGetSessionInfo      = 0xAA023824,  // in 0, out 16 bytes (level 0 OK)
  kCmdAuthenticate        = 0xAA023828,  // in 4 bytes (token), out 0 (level 0 OK)
  kCmdHashDriverRange     = 0xAA02382C,  // in 8 bytes {rva,size}, out 4 (level 1)
};

// ---------------------------------------------------------------- data model
// PROC_TRACK_ENTRY, 0x70 bytes, 100 slots at g_ProcessTable (0x140006FE0).
struct ProcTrackEntry {
  uint32_t process_id;            // 0x00
  uint8_t protection_enabled;     // 0x04
  uint8_t monitored;              // 0x05
  uint8_t reserved06[2];          // 0x06
  uint32_t trusted_pids[5];       // 0x08  IOCTL 0xAA02380C
  uint32_t inherited_blacklist[3];// 0x1C  IOCTL 0xAA023810
  uint32_t expected_parent_pid;   // 0x28  IOCTL 0xAA023814
  uint32_t granted_access_pids[12];// 0x2C IOCTL 0xAA023818
  uint32_t denied_access_pids[3]; // 0x5C
  uint32_t last_denied_pid;       // 0x68
  uint16_t command_level;         // 0x6C
  uint8_t reserved6e[2];          // 0x6E
};
static_assert(sizeof(ProcTrackEntry) == 0x70, "PROC_TRACK_ENTRY size");

// Flags used inside GrantedAccessPids[] by ObPreOperationCallback (0x140001DF0).
inline constexpr uint32_t kGrantProtectionWasOff = 0x80000000u;  // recorded while ProtectionEnabled == 0
inline constexpr uint32_t kGrantTableFull = 0x20000000u;         // set in slot 0 when all 12 slots are used
inline constexpr uint32_t kLastDeniedMarker = 0x40000000u;       // OR'ed into LastDeniedPid by 0xAA023818

// Access bits stripped by the pre-operation callback (DesiredAccess &= 0xFFFFFFC5).
inline constexpr uint32_t kStrippedAccessMask = 0x3A;  // CREATE_THREAD|VM_OPERATION|VM_READ|VM_WRITE
inline constexpr uint32_t kStrippedAccessKept = 0xFFFFFFC5u;

// Names the pre-operation callback whitelists inside the protected image's
// directory (stored obfuscated in the driver, decoded by DeobfuscateAnsiString).
inline constexpr const char* kWhitelistedImages[] = {
    "svchost.exe", "csrss.exe", "lsass.exe", "conhost.exe"};

// ------------------------------------------------------- authentication model
// The session is promoted by IOCTL 0xAA023828:
//   token = HashBuffer[((pid >> 2) & 3)](2, 0, &pid_hash, 4)
// where pid_hash is the value returned by IOCTL 0xAA023824 for the calling
// process. HashBuffer_00..03 (0x1400035F0 / 0x140003760 / 0x1400038D0 /
// 0x140003A40) hash 512 bytes of the driver's own .text around the call site
// plus the 4-byte pid_hash, then mix the result with a purely address-derived
// constant through MixHashStep/MixHash_00..15 and MixTable_00..31.
// Everything is reproducible from this file's tables plus the *runtime* image
// base of the driver (leaked by 0xAA023824) — see auth.cpp.
inline constexpr uint32_t kHasherStride = 0x170;  // 368-byte stride between variants
inline constexpr uint32_t kMaxSessions = 100;

// Kernel runtime addresses needed by the hash chain are derived from the image
// base; these offsets are the return addresses of the indirect calls the driver
// uses (all verified against the disassembly, see auth.cpp).
inline constexpr uint32_t kOuterHasherCallRet = 0x3584;  // IrpMjDeviceControl -> HashBuffer_xx
inline constexpr uint32_t kMixHashStepCallRet[2] = {0x3185, 0x319A};
inline constexpr uint32_t kHasherRecursiveCallRet[4] = {0x36FF, 0x386D, 0x39DD, 0x3B4D};
inline constexpr uint32_t kMixHashCallRet[16] = {
    0x2546, 0x25B1, 0x2627, 0x2691, 0x2706, 0x2771, 0x27E7, 0x2851,
    0x28C6, 0x2931, 0x29A7, 0x2A11, 0x2A86, 0x2AF1, 0x2B67, 0x2BD1};
inline constexpr int32_t kMixTableDisp[32] = {
    22,   -46,  -114, 74,   -11,  -79,  109,  41,   -44,  -112, 76,   8,
    -77,  111,  43,   -25,  -110, 78,   10,   -58,  113,  45,   -23,  -91,
    80,   12,   -56,  -124, 47,   -21,  -89,  99};
// MixHash_00..15: {init xor, per-round xor, special round index, final xor}.
inline constexpr uint32_t kMixHashParams[16][4] = {
    {0x88322991, 0x1A66F780, 0, 0},        {0x00000000, 0x633A2F3C, 1, 0xF56EFD2B},
    {0x19D89909, 0xAC0D66F8, 2, 0},        {0x00000000, 0xF4E09EB4, 3, 0x87156CA3},
    {0x3DB3D670, 0xCFE8A45F, 0, 0},        {0x00000000, 0x18BBDC1B, 1, 0xAAF0AA0A},
    {0xCF5A45E8, 0x618F13D7, 2, 0},        {0x00000000, 0xAA624B93, 3, 0x3C971982},
    {0xF335834F, 0x856A513E, 0, 0},        {0x00000000, 0xCE3D88FA, 1, 0x607256E9},
    {0x84DBF2C7, 0x1710C0B6, 2, 0},        {0x00000000, 0x5FE3F872, 3, 0xF218C661},
    {0xA8B7302E, 0x3AEBFE1D, 0, 0},        {0x00000000, 0x83BF35D9, 1, 0x15F403C8},
    {0x3A5D9FA6, 0xCC926D95, 2, 0},        {0x00000000, 0x1565A551, 3, 0xA79A7340}};
// HashBuffer_00..03: {MixHashStep input, xor after MixHashStep}.
inline constexpr uint32_t kHasherKeys[4][2] = {
    {0xA4443C76, 0x5CF6D162},
    {0xED177432, 0x85C4293E},
    {0x35EAABEE, 0x9D8784DA},
    {0x7EBDE3AA, 0xC70ADC96}};

}  // namespace andappsvc
