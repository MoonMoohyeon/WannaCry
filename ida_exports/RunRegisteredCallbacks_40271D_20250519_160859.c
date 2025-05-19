// --- Metadata ---
// Function Name: RunRegisteredCallbacks_40271D
// Address: 0x40271D
// Exported At: 20250519_160859
// Signature: unknown_signature
// ---------------
int __cdecl RunRegisteredCallbacks_40271D(_DWORD *a1)
{
  int baseAddr; // edi
  int offset; // eax
  void (__stdcall **v4)(_DWORD, int, _DWORD); // esi 콜백 함수 포인터 배열을 호출 

  baseAddr = a1[1];
  offset = *(*a1 + 192);
  if ( !offset )
    return 1;
  v4 = *(offset + baseAddr + 12);
  if ( v4 )
  {
    while ( *v4 )
      (*v4++)(baseAddr, 1, 0);
  }
  return 1;
}
