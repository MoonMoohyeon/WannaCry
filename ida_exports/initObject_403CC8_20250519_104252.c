// --- Metadata ---
// Function Name: initObject_403CC8
// Address: 0x403CC8
// Exported At: 20250519_104252
// Signature: unknown_signature
// ---------------
int __cdecl initObject_403CC8(char a1, char a2, int a3, int a4, int a5)
{
  int result; // eax

  result = (*(a5 + 32))(*(a5 + 40), 1, 28);     // calloc 스타일 
  if ( result )
  {
    *result = 0;
    *(result + 16) = a1;                        // 구조체 객체 초기화 
    *(result + 17) = a2;
    *(result + 20) = a3;
    *(result + 24) = a4;
  }
  return result;
}
