// --- Metadata ---
// Function Name: CleanupCustomMemoryBlock_4029CC
// Address: 0x4029CC
// Exported At: 20250519_160359
// Signature: unknown_signature
// ---------------
void __cdecl CleanupCustomMemoryBlock_4029CC(LPVOID lpMem)
{
  int i; // edi
  int v2; // eax
  int v3; // eax
  HANDLE v4; // eax

  if ( lpMem )                                  // 입력으로 받은 포인터(lpMem)가 가리키는 커스텀 구조체 내부 자원들을 해제 
  {
    if ( *(lpMem + 4) )
      ((*(lpMem + 1) + *(*lpMem + 40)))(*(lpMem + 1), 0, 0);
    if ( *(lpMem + 2) )
    {
      for ( i = 0; i < *(lpMem + 3); ++i )
      {
        v2 = *(*(lpMem + 2) + 4 * i);
        if ( v2 )
          (*(lpMem + 11))(v2, *(lpMem + 12));
      }
      free(*(lpMem + 2));
    }
    v3 = *(lpMem + 1);
    if ( v3 )
      (*(lpMem + 8))(v3, 0, 0x8000, *(lpMem + 12));
    v4 = GetProcessHeap();
    HeapFree(v4, 0, lpMem);
  }
}
