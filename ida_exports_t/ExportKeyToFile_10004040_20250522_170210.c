// --- Metadata ---
// Function Name: ExportKeyToFile_10004040
// Address: 0x10004040
// Exported At: 20250522_170210
// Signature: unknown_signature
// ---------------
int __cdecl ExportKeyToFile_10004040(int a1, HCRYPTKEY hKey, DWORD dwBlobType, LPCSTR lpFileName)
{
  HGLOBAL v4; // eax
  const void *v5; // esi
  int result; // eax
  HANDLE v7; // eax
  DWORD pdwDataLen; // [esp+10h] [ebp-24h] BYREF
  HGLOBAL hMem; // [esp+14h] [ebp-20h]
  DWORD NumberOfBytesWritten; // [esp+18h] [ebp-1Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+1Ch] [ebp-18h] BYREF

  pdwDataLen = 0;
  NumberOfBytesWritten = 0;
  hMem = 0;
  ms_exc.registration.TryLevel = 0;
  if ( CryptExportKey(hKey, 0, dwBlobType, 0, 0, &pdwDataLen)// 암호화 키를 파일로 내보내기 
    && (v4 = GlobalAlloc(0, pdwDataLen), v5 = v4, (hMem = v4) != 0)
    && CryptExportKey(hKey, 0, dwBlobType, 0, (BYTE *)v4, &pdwDataLen)
    && (v7 = CreateFileA(lpFileName, 0x40000000u, 0, 0, 2u, 0x80u, 0), v7 != (HANDLE)-1)
    && WriteFile(v7, v5, pdwDataLen, &NumberOfBytesWritten, 0) )
  {
    local_unwind2(&ms_exc.registration, -1);
    result = 1;
  }
  else
  {
    local_unwind2(&ms_exc.registration, -1);
    result = 0;
  }
  return result;
}
