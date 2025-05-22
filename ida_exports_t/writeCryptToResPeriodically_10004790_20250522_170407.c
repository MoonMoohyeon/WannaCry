// --- Metadata ---
// Function Name: writeCryptToResPeriodically_10004790
// Address: 0x10004790
// Exported At: 20250522_170407
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn writeCryptToResPeriodically_10004790(LPVOID lpThreadParameter)
{
  int i; // esi

  while ( !dword_1000DD90 )                     // 종료 플래그 
  {
    dword_1000DCDC = time(0);
    writeCryptrandomToRes_10004730();           // 25초를 주기로 실행 
    for ( i = 0; i < 25; ++i )
    {
      if ( dword_1000DD90 )
        goto LABEL_6;
      Sleep(1000u);                             // 1초 대기 
    }
  }
LABEL_6:
  ExitThread(0);
}
