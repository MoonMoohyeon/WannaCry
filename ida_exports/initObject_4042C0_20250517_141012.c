// --- Metadata ---
// Function Name: initObject_4042C0
// Address: 0x4042C0
// Exported At: 20250517_141012
// Signature: unknown_signature
// ---------------
int (__cdecl *__cdecl initObject_4042C0(_DWORD *a1, int a2, _DWORD *a3))(_DWORD, _DWORD, _DWORD)
{
  int v3; // eax
  int (__cdecl *result)(_DWORD, _DWORD, _DWORD); // eax

  if ( a3 )                                     // 구조체 초기화 
    *a3 = a1[15];
  if ( *a1 == 4 || *a1 == 5 )
    (*(a2 + 36))(*(a2 + 40), a1[3]);
  if ( *a1 == 6 )
    retFuncPointer_4042AF(a1[1], a2);
  v3 = a1[10];
  *a1 = 0;
  a1[13] = v3;
  a1[12] = v3;
  result = a1[14];
  a1[7] = 0;
  a1[8] = 0;
  if ( result )
  {
    result = result(0, 0, 0);
    a1[15] = result;
    *(a2 + 48) = result;
  }
  return result;
}
