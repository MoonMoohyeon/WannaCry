// --- Metadata ---
// Function Name: waitMutex_401EFF
// Address: 0x401EFF
// Exported At: 20250516_100348
// Signature: unknown_signature
// ---------------
int __cdecl waitMutex_401EFF(int maxtry)
{
  int v1; // esi
  HANDLE v2; // eax
  char Buffer[100]; // [esp+4h] [ebp-64h] BYREF

  sprintf(Buffer, "%s%d", "Global\\MsWinZonesCacheCounterMutexA", 0);// 뮤텍스 이름
  v1 = 0;
  if ( maxtry <= 0 )
    return 0;
  while ( 1 )
  {
    v2 = OpenMutexA(1048576u, 1, Buffer);       // 중복 실행 방지 혹은 선행 작업 대기 
    if ( v2 )
      break;
    Sleep(1000u);
    if ( ++v1 >= maxtry )                       // 타임 아웃 = 조건 불충분 
      return 0;
  }
  CloseHandle(v2);
  return 1;                                     // 뮤텍스 존재 -> 실행 조건 만족 
}
