// --- Metadata ---
// Function Name: isReaderValid_405CC7
// Address: 0x405CC7
// Exported At: 20250517_203130
// Signature: unknown_signature
// ---------------
BOOL __cdecl isReaderValid_405CC7(_BYTE *a1)
{
  return *a1 && a1[8];                          // 입력 객체 유효 상태 점검 
}
