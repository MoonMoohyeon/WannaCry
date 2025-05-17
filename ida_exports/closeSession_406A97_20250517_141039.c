// --- Metadata ---
// Function Name: closeSession_406A97
// Address: 0x406A97
// Exported At: 20250517_141039
// Signature: unknown_signature
// ---------------
int __cdecl closeSession_406A97(int a1)
{
  int v1; // esi
  int result; // eax
  bool v3; // zf
  int v4; // [esp+Ch] [ebp-4h]

  v4 = 0;
  if ( !a1 )
    return -102;
  v1 = *(a1 + 124);
  if ( !v1 )
    return -102;
  if ( !*(v1 + 92) && *(v1 + 80) != *(v1 + 84) )
    v4 = -105;
  if ( *v1 )                                    // 전체 종료 루틴, 내부 객체 해제 
  {
    free(*v1);
    *v1 = 0;
  }
  v3 = *(v1 + 64) == 0;
  *v1 = 0;
  if ( !v3 )
    cleanUpSession_405739((v1 + 4));
  *(v1 + 64) = 0;
  free(v1);
  result = v4;
  *(a1 + 124) = 0;
  return result;
}
