// --- Metadata ---
// Function Name: StartServiceWithCmd_401CE8
// Address: 0x401CE8
// Exported At: 20250515_223206
// Signature: unknown_signature
// ---------------
int __cdecl StartServiceWithCmd_401CE8(const char *a1)
{
  SC_HANDLE v1; // eax
  SC_HANDLE v3; // eax
  int v4; // esi
  SC_HANDLE v5; // eax
  SC_HANDLE v6; // esi
  char Buffer[1024]; // [esp+4h] [ebp-40Ch] BYREF
  SC_HANDLE hSCObject; // [esp+404h] [ebp-Ch]
  int v9; // [esp+408h] [ebp-8h]
  SC_HANDLE hSCManager; // [esp+40Ch] [ebp-4h]

  v9 = 0;
  v1 = OpenSCManagerA(0, 0, 0xF003Fu);          // 서비스 매니저 열기 
  hSCManager = v1;
  if ( !v1 )
    return 0;
  v3 = OpenServiceA(v1, DisplayName, 0xF01FFu); // 기존 서비스가 있는지 확인 
  hSCObject = v3;
  if ( v3 )
  {
    StartServiceA(v3, 0, 0);                    // 서비스 시작 
    CloseServiceHandle(hSCObject);
    v4 = 1;
  }
  else                                          // 기존 서비스가 없는 경우 서비스 생성 
  {
    sprintf(Buffer, "cmd.exe /c \"%s\"", a1);
    v5 = CreateServiceA(hSCManager, DisplayName, DisplayName, 0xF01FFu, 0x10u, 2u, 1u, Buffer, 0, 0, 0, 0, 0);
    v6 = v5;
    if ( v5 )
    {
      StartServiceA(v5, 0, 0);
      CloseServiceHandle(v6);
      v9 = 1;
    }
    v4 = v9;
  }
  CloseServiceHandle(hSCManager);
  return v4;
}
