// --- Metadata ---
// Function Name: runAttribInRecyclePath_10005060
// Address: 0x10005060
// Exported At: 20250522_173320
// Signature: unknown_signature
// ---------------
LPWSTR __cdecl runAttribInRecyclePath_10005060(int driveIndex, LPWSTR outPathBuffer)
{
  char commandLineBuffer[1024]; // [esp+8h] [ebp-400h] BYREF

  GetWindowsDirectoryW(outPathBuffer, 0x104u);
  if ( *outPathBuffer == driveIndex + 65 )      // 특정 드라이브에 $RECYCLE 폴더를 만들고 숨김 
  {
    GetTempPathW(0x104u, outPathBuffer);
    if ( wcslen(outPathBuffer) && outPathBuffer[wcslen(outPathBuffer) - 1] == 92 )
    {
      outPathBuffer[wcslen(outPathBuffer) - 1] = 0;
      return outPathBuffer;
    }
  }
  else
  {
    swprintf(outPathBuffer, (const size_t)L"%C:\\%s", (const wchar_t *const)(driveIndex + 65), L"$RECYCLE");
    CreateDirectoryW(outPathBuffer, 0);
    sprintf(commandLineBuffer, "attrib +h +s %C:\\%s", driveIndex + 65, "$RECYCLE");// attrib 실행 
    RunProcessWithTimeout_10001080(commandLineBuffer, 0, 0);
  }
  return outPathBuffer;
}
