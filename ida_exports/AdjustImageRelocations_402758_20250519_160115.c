// --- Metadata ---
// Function Name: AdjustImageRelocations_402758
// Address: 0x402758
// Exported At: 20250519_160115
// Signature: unknown_signature
// ---------------
BOOL __cdecl AdjustImageRelocations_402758(_DWORD *a1, int a2)
{
  int baseAddr; // esi
  _DWORD *relocationBlockBaseAddr; // eax
  int i; // ecx
  _WORD *v6; // edx
  int v7; // ebx
  unsigned int v8; // [esp+Ch] [ebp+8h] PE 파일 등의 로딩 시 베이스 주소 변경이 생길 경우 포인터를 수정하는 로직

  baseAddr = a1[1];
  if ( !*(*a1 + 164) )                          // 재배치 테이블 개수 혹은 존재 여부 
    return a2 == 0;
  relocationBlockBaseAddr = (baseAddr + *(*a1 + 160));
  for ( i = *relocationBlockBaseAddr; *relocationBlockBaseAddr; i = *relocationBlockBaseAddr )
  {
    v8 = 0;
    v6 = relocationBlockBaseAddr + 2;
    if ( ((relocationBlockBaseAddr[1] - 8) & 0xFFFFFFFE) != 0 )
    {
      do
      {
        v7 = *v6;
        LOWORD(v7) = v7 & 0xF000;
        if ( v7 == 12288 )
          *(i + baseAddr + (*v6 & 0xFFF)) += a2;
        ++v8;
        ++v6;
      }
      while ( v8 < (relocationBlockBaseAddr[1] - 8) >> 1 );
    }
    relocationBlockBaseAddr = (relocationBlockBaseAddr + relocationBlockBaseAddr[1]);
  }
  return 1;
}
