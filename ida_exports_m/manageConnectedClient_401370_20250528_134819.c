// --- Metadata ---
// Function Name: manageConnectedClient_401370
// Address: 0x401370
// Exported At: 20250528_134819
// Signature: unknown_signature
// ---------------
void __cdecl manageConnectedClient_401370(char *serverIp, u_short serverPort)
{
  __int16 *cmdEntry; // esi 레드 블랙트리를 활용한 연결된 클라이언트 관리 
  double v3; // st7
  __int16 cmdCode; // ax
  SOCKET v5; // edi
  int v6; // edi
  char v7; // [esp+10h] [ebp-2F84h] BYREF
  char v8; // [esp+11h] [ebp-2F83h]
  char v9; // [esp+12h] [ebp-2F82h] BYREF
  char v10; // [esp+13h] [ebp-2F81h]
  __int64 prevTick; // [esp+14h] [ebp-2F80h] BYREF
  int v12[2]; // [esp+1Ch] [ebp-2F78h] BYREF
  int v13[2]; // [esp+24h] [ebp-2F70h] BYREF
  double currTick; // [esp+2Ch] [ebp-2F68h]
  int v15[2]; // [esp+34h] [ebp-2F60h] BYREF
  int v16[2]; // [esp+3Ch] [ebp-2F58h] BYREF
  __int64 v17; // [esp+44h] [ebp-2F50h]
  int v18; // [esp+4Ch] [ebp-2F48h] BYREF
  int v19; // [esp+54h] [ebp-2F40h] BYREF
  double intervalMs; // [esp+5Ch] [ebp-2F38h]
  struct sockaddr name; // [esp+64h] [ebp-2F30h] BYREF
  int v22; // [esp+74h] [ebp-2F20h] BYREF
  int v23; // [esp+7Ch] [ebp-2F18h] BYREF
  char recvBuf[2048]; // [esp+84h] [ebp-2F10h] BYREF
  char buf[10000]; // [esp+884h] [ebp-2710h] BYREF

  v7 = 0;
  v8 = 8;
  v9 = 0;
  v10 = 8;
  prevTick = GetTickCount();
  currTick = prevTick;
  initSomeBigData_401D80();
  rbTreeDeleteRange(&dword_431468, &prevTick, *dword_43146C, dword_43146C);
  cmdEntry = &word_431480;
  while ( 1 )
  {
    intervalMs = *(cmdEntry + 1252) * 1000.0;
    prevTick = GetTickCount();
    v3 = intervalMs - (prevTick - currTick);
    if ( v3 > 0.0 )
      preciseSleep_401660((v3 * 1000.0));
    v17 = GetTickCount();
    cmdCode = *cmdEntry;
    currTick = v17;
    if ( cmdCode == 2 )
      break;
    if ( cmdCode == 3 )
    {
      v13[0] = *(cmdEntry + 1);
      v13[1] = 0;
      rbInsertOrFind_408390(&dword_431468, &v23, v13);
      closesocket(*(v23 + 16));
    }
    else if ( cmdCode )
    {
      if ( cmdCode == 1 )
      {
        v12[0] = *(cmdEntry + 1);
        v12[1] = 0;
        rbInsertOrFind_408390(&dword_431468, &v19, v12);
        if ( recv(*(v19 + 16), recvBuf, 2048, 0) == -1 )
          goto LABEL_24;
        if ( *(cmdEntry + 2) > 3 )
        {
          if ( !stricmp(cmdEntry + 12, String2) )
          {
            v9 = recvBuf[28];
            v10 = recvBuf[29];
          }
          if ( !stricmp(cmdEntry + 12, aUserid) )
          {
            v7 = recvBuf[32];
            v8 = recvBuf[33];
          }
        }
      }
    }
    else
    {
      memset(buf, 0, sizeof(buf));
      v6 = replacePlaceholders_401190(cmdEntry + 12, *(cmdEntry + 2), buf, &v7, &v9);
      v15[0] = *(cmdEntry + 1);
      v15[1] = 0;
      rbInsertOrFind_408390(&dword_431468, &v22, v15);
      if ( send(*(v22 + 16), buf, v6, 0) == -1 )
        goto LABEL_24;
    }
LABEL_20:
    cmdEntry += 5012;
    if ( cmdEntry >= &unk_5FFD08 )
      return;
  }
  name.sa_family = 2;
  *&name.sa_data[2] = inet_addr(serverIp);
  *name.sa_data = htons(serverPort);
  v5 = socket(2, 1, 0);
  if ( v5 == -1 )
  {
    closeAllClientSockets_401310();
    return;
  }
  if ( connect(v5, &name, 16) != -1 )
  {
    v16[0] = *(cmdEntry + 1);
    v16[1] = 0;
    rbInsertOrFind_408390(&dword_431468, &v18, v16);
    *(v18 + 16) = v5;
    goto LABEL_20;
  }
  closesocket(v5);
LABEL_24:
  closeAllClientSockets_401310();
  Sleep(0x3E8u);
}
