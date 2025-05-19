// --- Metadata ---
// Function Name: ResolveSectionsFromImage_402470
// Address: 0x402470
// Exported At: 20250519_155644
// Signature: unknown_signature
// ---------------
int __cdecl ResolveSectionsFromImage_402470(int a1, unsigned int a2, int a3, int a4)
{
  size_t *i; // esi
  signed int v6; // ebx
  void *v7; // ebx
  void *v9; // [esp-Ch] [ebp-1Ch]
  int v10; // [esp+Ch] [ebp-4h]
  int baseAddr; // [esp+24h] [ebp+14h] 복호화된 바이너리 로딩, 언패킹, 또는 수동 PE 로딩 

  v10 = 0;
  baseAddr = *(a4 + 4);
  if ( !*(*a4 + 6) )                            // 섹션/블록 개수 
    return 1;
  for ( i = (*(*a4 + 20) + *a4 + 40); !*i; i += 10 )// 섹션 배열 포인터 
  {
    v6 = *(a3 + 56);
    if ( v6 > 0 )
    {
      if ( !(*(a4 + 28))(*(i - 1) + baseAddr, v6, 4096, 4, *(a4 + 48)) )// 할당 콜백 함수와 추가 콘텍스트 
        return 0;
      v9 = (*(i - 1) + baseAddr);               // RVA 계산 
      *(i - 2) = v9;                            // 로드된 위치(포인터 캐시)
      memset(v9, 0, v6);
    }
LABEL_10:
    if ( ++v10 >= *(*a4 + 6) )
      return 1;
  }
  if ( checkBoundary_402457(a2, *i + i[1]) && (*(a4 + 28))(*(i - 1) + baseAddr, *i, 4096, 4, *(a4 + 48)) )
  {
    v7 = (*(i - 1) + baseAddr);
    memcpy(v7, (a1 + i[1]), *i);
    *(i - 2) = v7;
    goto LABEL_10;
  }
  return 0;
}
