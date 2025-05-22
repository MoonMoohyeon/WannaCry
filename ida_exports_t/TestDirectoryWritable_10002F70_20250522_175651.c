// --- Metadata ---
// Function Name: TestDirectoryWritable_10002F70
// Address: 0x10002F70
// Exported At: 20250522_175651
// Signature: unknown_signature
// ---------------
BOOL __cdecl TestDirectoryWritable_10002F70(LPCWSTR directoryPath)
{
  HANDLE hTempFile; // eax
  BOOL result; // eax
  WCHAR TempFileName; // [esp+20h] [ebp-2D0h] BYREF
  char v4[716]; // [esp+22h] [ebp-2CEh] BYREF
  __int16 v5; // [esp+2EEh] [ebp-2h]

  TempFileName = 0;
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  GetTempFileNameW(directoryPath, L"~SD", 0, &TempFileName);// 디렉토리 쓰기 권한이 있는지 확인 
  hTempFile = CreateFileW_0(&TempFileName, 0x40000000u, 0, 0, 2u, 2u, 0);
  result = 0;
  if ( hTempFile != (HANDLE)-1 )
  {
    dword_1000D934(hTempFile);
    if ( DeleteFileW_0(&TempFileName) )
      result = 1;
  }
  return result;
}
