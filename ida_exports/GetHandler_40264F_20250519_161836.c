// --- Metadata ---
// Function Name: GetHandler_40264F
// Address: 0x40264F
// Exported At: 20250519_161836
// Signature: unknown_signature
// ---------------
int __cdecl GetHandler_40264F(int a1, int a2)
{
  int result; // eax
  int v3; // ecx

  result = *(a2 + 16);                          // a2 + 16 값이 존재하면 핸들러로 반환 
  if ( !result )                                // 없으면 대체 핸들러 선택 
  {
    v3 = *(a2 + 36);
    if ( (v3 & 0x40) != 0 )
    {
      result = *(*a1 + 32);
    }
    else if ( (v3 & 0x80u) != 0 )
    {
      result = *(*a1 + 36);
    }
  }
  return result;
}
