// --- Metadata ---
// Function Name: calculateWindowsFileTimeFromUnix_406B02
// Address: 0x406B02
// Exported At: 20250518_111446
// Signature: unknown_signature
// ---------------
__int64 __cdecl calculateWindowsFileTimeFromUnix_406B02(int unixTimeSeconds)
{
  __int64 adjustedFiletimeBase; // rax

  adjustedFiletimeBase = unixTimeSeconds + 3054539008i64;// 베이스 오프셋 추가 
  HIDWORD(adjustedFiletimeBase) += 2;
  return 10000000 * adjustedFiletimeBase;
}
