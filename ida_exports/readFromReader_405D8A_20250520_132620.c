// --- Metadata ---
// Function Name: readFromReader_405D8A
// Address: 0x405D8A
// Exported At: 20250520_132620
// Signature: unknown_signature
// ---------------
unsigned int __cdecl readFromReader_405D8A(LPVOID lpBuffer, int a2, int a3, int a4)
{
  int v4; // esi
  size_t v5; // edi
  unsigned int v6; // eax
  int v7; // ecx
  unsigned int v8; // eax

  v4 = a4;
  v5 = a3 * a2;
  if ( *a4 )
  {
    if ( !ReadFile(*(a4 + 4), lpBuffer, a3 * a2, &lpBuffer, 0) )// 파일 또는 메모리에서 바이트 읽기 작업 
      *(v4 + 8) = 1;
    v6 = lpBuffer;
  }
  else
  {
    v7 = *(a4 + 28);
    v8 = *(a4 + 24);
    if ( v7 + v5 > v8 )
      v5 = v8 - v7;
    memcpy(lpBuffer, (v7 + *(a4 + 20)), v5);
    *(v4 + 28) += v5;
    v6 = v5;
  }
  return v6 / a2;
}
