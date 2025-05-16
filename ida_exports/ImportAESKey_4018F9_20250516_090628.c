// --- Metadata ---
// Function Name: ImportAESKey_4018F9
// Address: 0x4018F9
// Exported At: 20250516_090628
// Signature: unknown_signature
// ---------------
int __cdecl ImportAESKey_4018F9(int a1, int a2, LPCSTR lpFileName)
{
  int v3; // esi
  HANDLE v4; // eax
  DWORD v5; // eax
  DWORD v6; // edi
  HGLOBAL v7; // ebx
  HANDLE hFile; // [esp+Ch] [ebp-28h]
  DWORD NumberOfBytesRead; // [esp+18h] [ebp-1Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+1Ch] [ebp-18h] BYREF

  v3 = 0;
  NumberOfBytesRead = 0;
  ms_exc.registration.TryLevel = 0;             // 외부 키 파일에서 암호화/복호화 키를 가져옴 
  v4 = CreateFileA(lpFileName, 0x80000000, 1u, 0, 3u, 0, 0);// 키 파일 열기 
  hFile = v4;
  if ( v4 != -1 )
  {
    v5 = GetFileSize(v4, 0);
    v6 = v5;
    if ( v5 != -1 && v5 <= 0x19000 )
    {
      v7 = GlobalAlloc(0, v5);
      if ( v7 )
      {                                         // CryptoAPI 키 객체 생성 
        if ( ReadFile(hFile, v7, v6, &NumberOfBytesRead, 0) && CryptImportKey(a1, v7, NumberOfBytesRead, 0, 0, a2) )
          v3 = 1;
      }
    }
  }
  local_unwind2(&ms_exc.registration, -1);
  return v3;
}
