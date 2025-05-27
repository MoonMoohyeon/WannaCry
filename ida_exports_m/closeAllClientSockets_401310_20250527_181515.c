// --- Metadata ---
// Function Name: closeAllClientSockets_401310
// Address: 0x401310
// Exported At: 20250527_181515
// Signature: unknown_signature
// ---------------
_DWORD *closeAllClientSockets_401310()
{
  _DWORD *result; // eax
  _DWORD *v1; // esi
  _DWORD *v2; // eax

  result = dword_43146C;
  v1 = *dword_43146C;
  while ( v1 != dword_43146C )                  // 레드-블랙 트리 형태의 구조에서 노드를 순회하면서 소켓을 닫고 다음 노드로 이동 
  {
    closesocket(v1[4]);
    v2 = v1[2];
    if ( v2 == *&FileName[280] )
    {
      for ( result = v1[1]; v1 == result[2]; result = result[1] )
        v1 = result;
      if ( v1[2] != result )
        v1 = result;
    }
    else
    {
      v1 = v1[2];
      for ( result = *v2; result != *&FileName[280]; result = *result )
        v1 = result;
    }
  }
  return result;
}
