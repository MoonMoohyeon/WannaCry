// --- Metadata ---
// Function Name: manageRegDir_4010FD
// Address: 0x4010FD
// Exported At: 20250505_133909
// Signature: unknown_signature
// ---------------
int __cdecl manageRegDir_4010FD(int a1)
{
  size_t v1; // eax
  BOOL v2; // esi
  LSTATUS v3; // eax
  CHAR Buffer; // [esp+8h] [ebp-2DCh] BYREF
  char v6[516]; // [esp+9h] [ebp-2DBh] BYREF
  __int16 v7; // [esp+20Dh] [ebp-D7h]
  char v8; // [esp+20Fh] [ebp-D5h]
  wchar_t Destination[10]; // [esp+210h] [ebp-D4h] BYREF
  char v10[180]; // [esp+224h] [ebp-C0h] BYREF
  DWORD cbData; // [esp+2D8h] [ebp-Ch] BYREF
  int v12; // [esp+2DCh] [ebp-8h]
  HKEY phkResult; // [esp+2E0h] [ebp-4h] BYREF

  qmemcpy(Destination, L"Software\\", sizeof(Destination));
  Buffer = 0;
  phkResult = 0;
  memset(v10, 0, sizeof(v10));
  memset(v6, 0, sizeof(v6));
  v7 = 0;
  v8 = 0;
  wcscat(Destination, L"WanaCrypt0r");          // 키 값 = Software\\WanaCrypt0
  v12 = 0;
  while ( 1 )
  {
    if ( v12 )
      RegCreateKeyW(HKEY_CURRENT_USER, Destination, &phkResult);// 레지스트리 경로1 = HKEY_CURRENT_USER
    else
      RegCreateKeyW(HKEY_LOCAL_MACHINE, Destination, &phkResult);// 레지스트리 경로2 = HKEY_LOCAL_MACHINE
    if ( phkResult )
    {
      if ( a1 )                                 // 인자로 1 값이 넘어옴 
      {
        GetCurrentDirectoryA(0x207u, &Buffer);  // 현재 작업 디렉토리 불러오기 
        v1 = strlen(&Buffer);
        v2 = RegSetValueExA(phkResult, "wd", 0, 1u, &Buffer, v1 + 1) == 0;// 레지스트리 키에 wd라는 이름으로 저장 
      }
      else
      {
        cbData = 519;
        v3 = RegQueryValueExA(phkResult, "wd", 0, 0, &Buffer, &cbData);
        v2 = v3 == 0;
        if ( !v3 )
          SetCurrentDirectoryA(&Buffer);
      }
      RegCloseKey(phkResult);
      if ( v2 )
        break;
    }
    if ( ++v12 >= 2 )
      return 0;
  }
  return 1;
}
