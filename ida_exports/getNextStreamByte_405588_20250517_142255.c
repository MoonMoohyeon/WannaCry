// --- Metadata ---
// Function Name: getNextStreamByte_405588
// Address: 0x405588
// Exported At: 20250517_142255
// Signature: unknown_signature
// ---------------
int __cdecl getNextStreamByte_405588(int a1)
{
  int v1; // eax

  v1 = *(a1 + 8) & 0xFFFD;
  LOBYTE(v1) = v1 | 2;
  return (v1 * (v1 ^ 1)) >> 8;                  // 다음값 반환, 난수like 값
}
