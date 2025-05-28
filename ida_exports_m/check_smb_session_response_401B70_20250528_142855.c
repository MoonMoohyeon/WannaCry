// --- Metadata ---
// Function Name: check_smb_session_response_401B70
// Address: 0x401B70
// Exported At: 20250528_142855
// Signature: unknown_signature
// ---------------
int __cdecl check_smb_session_response_401B70(char *cp, int a2, u_short hostshort)
{
  SOCKET v3; // eax
  SOCKET v4; // esi
  char v5; // bl
  char v7; // [esp+Fh] [ebp-411h]
  struct sockaddr name; // [esp+10h] [ebp-410h] BYREF
  char buf; // [esp+20h] [ebp-400h] BYREF
  char v10[1020]; // [esp+21h] [ebp-3FFh] BYREF
  __int16 v11; // [esp+41Dh] [ebp-3h]
  char v12; // [esp+41Fh] [ebp-1h]

  buf = 0;
  name.sa_family = 2;
  memset(v10, 0, sizeof(v10));
  v11 = 0;
  v12 = 0;
  *&name.sa_data[2] = inet_addr(cp);
  *name.sa_data = htons(hostshort);             // 지정된 IP(cp)와 포트(hostshort)에 대해 TCP 소켓을 열기 
  v3 = socket(2, 1, 0);
  v4 = v3;
  if ( v3 != -1 )
  {
    if ( connect(v3, &name, 16) != -1           // 정해진 SMB 패킷 시퀀스(byte_42E544, byte_42E5D0, byte_42E65C, byte_42E6BC)를 송수신 
      && send(v4, byte_42E544, 137, 0) != -1
      && recv(v4, &buf, 1024, 0) != -1
      && send(v4, byte_42E5D0, 140, 0) != -1
      && recv(v4, &buf, 1024, 0) != -1 )        // SMB 세션을 열고, 특정 응답을 확인 
    {
      v5 = v10[31];
      byte_42E67C = v10[31];
      v7 = v10[32];
      byte_42E67D = v10[32];
      if ( send(v4, byte_42E65C, 96, 0) != -1 && recv(v4, &buf, 1024, 0) != -1 )// SMB72 SMB73 SMB75 SMB2 순서대로 메시지 전송 
      {
        byte_42E6D8 = v10[27];
        byte_42E6D9 = v10[28];
        byte_42E6DC = v5;
        byte_42E6DD = v7;
        if ( send(v4, byte_42E6BC, 82, 0) != -1 && recv(v4, &buf, 1024, 0) != -1 && v10[33] == 81 )
        {
          if ( a2
            || (byte_42E6DE = 66,
                byte_42E6ED = 14,
                strcpy(&byte_42E6EE, "i"),
                byte_42E6F0 = 0,
                send(v4, byte_42E6BC, 82, 0) != -1)
            && recv(v4, &buf, 1024, 0) != -1 )
          {
            closesocket(v4);
            return 1;
          }
        }
      }
    }
    closesocket(v4);
  }
  return 0;
}
