// --- Metadata ---
// Function Name: saveDataInSystemDir_401B5F
// Address: 0x401B5F
// Exported At: 20250505_135202
// Signature: unknown_signature
// ---------------
BOOL __cdecl saveDataInSystemDir_401B5F(wchar_t *a1)
{
  WCHAR Buffer; // [esp+8h] [ebp-4D8h] BYREF
  __int16 v3[259]; // [esp+Ah] [ebp-4D6h] BYREF
  wchar_t FileName; // [esp+210h] [ebp-2D0h] BYREF
  char v5[516]; // [esp+212h] [ebp-2CEh] BYREF
  __int16 v6; // [esp+416h] [ebp-CAh]
  WCHAR WideCharStr; // [esp+418h] [ebp-C8h] BYREF
  char v8[196]; // [esp+41Ah] [ebp-C6h] BYREF
  __int16 v9; // [esp+4DEh] [ebp-2h]

  Buffer = Null_40F874;
  memset(v3, 0, 0x204u);
  v3[258] = 0;
  FileName = Null_40F874;
  memset(v5, 0, sizeof(v5));
  v6 = 0;
  WideCharStr = Null_40F874;
  memset(v8, 0, sizeof(v8));
  v9 = 0;
  MultiByteToWideChar(0, 0, DisplayName, -1, &WideCharStr, 99);
  GetWindowsDirectoryW(&Buffer, 0x104u);
  v3[1] = 0;
  swprintf(&FileName, L"%s\\ProgramData", &Buffer);// ProgramData 디렉토리 
  if ( GetFileAttributesW(&FileName) != -1 && createDirAndHide_401AF6(&FileName, &WideCharStr, a1) )
    return 1;
  swprintf(&FileName, L"%s\\Intel", &Buffer);   // Intel 디렉토리 
  if ( createDirAndHide_401AF6(&FileName, &WideCharStr, a1) || createDirAndHide_401AF6(&Buffer, &WideCharStr, a1) )
    return 1;
  GetTempPathW(0x104u, &FileName);              // 둘 다 안되면 임시 경로 
  if ( wcsrchr(&FileName, 0x5Cu) )
    *wcsrchr(&FileName, 0x5Cu) = 0;
  return createDirAndHide_401AF6(&FileName, &WideCharStr, a1) != 0;// 인자로 받은 파일을 생성한 후 숨김 
}
