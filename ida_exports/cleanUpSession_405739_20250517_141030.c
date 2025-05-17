// --- Metadata ---
// Function Name: cleanUpSession_405739
// Address: 0x405739
// Exported At: 20250517_141030
// Signature: unknown_signature
// ---------------
int __cdecl cleanUpSession_405739(_DWORD *a1)
{
  int v1; // eax
  _DWORD *v2; // eax

  if ( !a1 )
    return -2;
  v1 = a1[7];
  if ( !v1 || !a1[9] )                          // 세션/객체 해제, 구조체 해제(콜백 정리) 
    return -2;
  v2 = *(v1 + 20);
  if ( v2 )
    freeObject_404BE5(v2, a1);
  (a1[9])(a1[10], a1[7]);
  a1[7] = 0;
  return 0;
}
