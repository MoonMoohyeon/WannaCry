// --- Metadata ---
// Function Name: CleanupCryptoObject_10001760
// Address: 0x10001760
// Exported At: 20250522_104253
// Signature: unknown_signature
// ---------------
int __thiscall CleanupCryptoObject_10001760(int this)
{
  _BYTE *v2; // eax
  int v3; // ecx
  _BYTE *v4; // eax
  int v5; // ecx
  void *v6; // eax
  const WCHAR *v7; // esi

  ReleaseCryptoResources_10003BB0((_DWORD *)(this + 4));
  ReleaseCryptoResources_10003BB0((_DWORD *)(this + 44));
  v2 = *(_BYTE **)(this + 1224);
  if ( v2 )                                     // 암호화 관련 작업이 포함된 객체의 소멸자 
  {
    v3 = 0x100000;
    do
    {
      *v2++ = 0;
      --v3;
    }
    while ( v3 );
    GlobalFree(*(HGLOBAL *)(this + 1224));
    *(_DWORD *)(this + 1224) = 0;
  }
  v4 = *(_BYTE **)(this + 1228);
  if ( v4 )
  {
    v5 = 0x100000;
    do
    {
      *v4++ = 0;
      --v5;
    }
    while ( v5 );
    GlobalFree(*(HGLOBAL *)(this + 1228));
    *(_DWORD *)(this + 1228) = 0;
  }
  v6 = *(void **)(this + 1240);
  if ( v6 )
  {
    *(_DWORD *)(this + 1244) = 1;
    WaitForSingleObject(v6, 0xFFFFFFFF);
    dword_1000D934(*(_DWORD *)(this + 1240));
    *(_DWORD *)(this + 1240) = 0;
  }
  DeleteCriticalSection((LPCRITICAL_SECTION)(this + 1260));
  v7 = (const WCHAR *)(this + 1804);
  if ( wcslen(v7) )
    DeleteFileW_0(v7);
  return 1;
}
