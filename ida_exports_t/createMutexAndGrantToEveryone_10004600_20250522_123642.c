// --- Metadata ---
// Function Name: createMutexAndGrantToEveryone_10004600
// Address: 0x10004600
// Exported At: 20250522_123642
// Signature: unknown_signature
// ---------------
int __cdecl createMutexAndGrantToEveryone_10004600(int a1)
{
  HANDLE v1; // eax
  int result; // eax
  HANDLE v3; // esi
  char Buffer[100]; // [esp+4h] [ebp-64h] BYREF

  v1 = OpenMutexA(0x100000u, 1, "Global\\MsWinZonesCacheCounterMutexW");
  if ( v1 )
  {
    CloseHandle(v1);
    result = 1;
  }
  else                                          // 기존 뮤텍스가 없는 경우 
  {
    sprintf(Buffer, "%s%d", "Global\\MsWinZonesCacheCounterMutexA", a1);
    v3 = CreateMutexA(0, 1, Buffer);
    if ( v3 && GetLastError() == 183 )
    {
      CloseHandle(v3);
      result = 1;
    }
    else                                        // 뮤텍스 생성이 성공하면 모든 권한 부여 
    {
      GrantAccessToEveryone_100013E0(v3);
      result = 0;
    }
  }
  return result;
}
