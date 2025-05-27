// --- Metadata ---
// Function Name: collectLocalNetworkIPRanges_409160
// Address: 0x409160
// Exported At: 20250527_190807
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
