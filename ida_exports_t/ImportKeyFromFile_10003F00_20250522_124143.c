// --- Metadata ---
// Function Name: ImportKeyFromFile_10003F00
// Address: 0x10003F00
// Exported At: 20250522_124143
// Signature: unknown_signature
// ---------------
int __cdecl ImportKeyFromFile_10003F00(int a1, int a2, LPCSTR lpFileName)
{
  HANDLE v3; // eax
  void *v4; // edi
  DWORD v5; // eax
  DWORD v6; // esi
  BYTE *v7; // eax
  const BYTE *v8; // ebx
  DWORD NumberOfBytesRead; // [esp+18h] [ebp-1Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+1Ch] [ebp-18h] BYREF

  NumberOfBytesRead = 0;
  ms_exc.registration.TryLevel = 0;
  v3 = CreateFileA(lpFileName, 0x80000000, 1u, 0, 3u, 0, 0);
  v4 = v3;
  if ( v3 == (HANDLE)-1 )
  {
LABEL_9:                                        // 외부 파일에 저장된 암호화 키를 불러오는 동작 
    local_unwind2(&ms_exc.registration, -1);
    return 0;
  }
  v5 = GetFileSize(v3, 0);
  v6 = v5;
  if ( v5 != -1 && v5 <= 0x19000 )
  {
    v7 = (BYTE *)GlobalAlloc(0, v5);
    v8 = v7;
    if ( v7
      && ReadFile(v4, v7, v6, &NumberOfBytesRead, 0)
      && CryptImportKey(a1, v8, NumberOfBytesRead, 0, 0, (HCRYPTKEY *)a2) )
    {
      local_unwind2(&ms_exc.registration, -1);
      return 1;
    }
    goto LABEL_9;
  }
  local_unwind2(&ms_exc.registration, -1);
  return 0;
}
