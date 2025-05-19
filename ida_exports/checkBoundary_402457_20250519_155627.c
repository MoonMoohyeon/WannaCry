// --- Metadata ---
// Function Name: checkBoundary_402457
// Address: 0x402457
// Exported At: 20250519_155627
// Signature: unknown_signature
// ---------------
int __cdecl checkBoundary_402457(unsigned int a1, unsigned int a2)
{
  if ( a1 >= a2 )                               // a1 >= a2일 때 성공(1 반환) 
    return 1;
  SetLastError(13u);                            // ERROR_INVALID_DATA 오류 코드 
  return 0;
}
