// --- Metadata ---
// Function Name: isPort445Open_407480
// Address: 0x407480
// Exported At: 20250527_171653
// Signature: unknown_signature
// ---------------
int __cdecl isPort445Open_407480(int a1)
{
  SOCKET v1; // eax
  SOCKET v2; // esi
  int v4; // edi
  struct sockaddr name; // [esp+8h] [ebp-120h] BYREF
  u_long argp; // [esp+18h] [ebp-110h] BYREF
  struct timeval timeout; // [esp+1Ch] [ebp-10Ch] BYREF
  fd_set writefds; // [esp+24h] [ebp-104h] BYREF

  *&name.sa_data[6] = 0;
  *&name.sa_data[8] = 0;
  *&name.sa_data[12] = 0;
  argp = 1;
  *&name.sa_data[2] = a1;
  name.sa_family = 2;
  *name.sa_data = htons(445u);                  // 포트 445 (htons(0x1BD))로 connect() 시도 후 select()로 연결 여부 검사 
  v1 = socket(2, 1, 6);
  v2 = v1;
  if ( v1 == -1 )
    return 0;
  ioctlsocket(v1, -2147195266, &argp);
  writefds.fd_array[0] = v2;
  writefds.fd_count = 1;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  connect(v2, &name, 16);
  v4 = select(0, 0, &writefds, 0, &timeout);
  closesocket(v2);
  return v4;
}
