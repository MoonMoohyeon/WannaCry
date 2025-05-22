// --- Metadata ---
// Function Name: IsRunningAsSystem_100012D0
// Address: 0x100012D0
// Exported At: 20250522_123540
// Signature: unknown_signature
// ---------------
BOOL IsRunningAsSystem_100012D0()
{
  int v0; // eax
  DWORD pcbBuffer; // [esp+4h] [ebp-25Ch] BYREF
  WCHAR Buffer; // [esp+8h] [ebp-258h] BYREF
  char v4[596]; // [esp+Ah] [ebp-256h] BYREF
  __int16 v5; // [esp+25Eh] [ebp-2h]

  Buffer = word_1000D918;
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  if ( GetCurrentUserSID_100011D0(&Buffer) )    // 현재 프로세스가 시스템 권한으로 실행되는지 확인 
  {
    v0 = wcsicmp(L"S-1-5-18", &Buffer);         // SID 문자열 비교 
  }
  else
  {
    pcbBuffer = 300;
    GetUserNameW(&Buffer, &pcbBuffer);          // 사용자 이름을 얻어 SYSTEM과 비교 
    v0 = wcsicmp(&Buffer, L"SYSTEM");
  }
  return v0 == 0;
}
