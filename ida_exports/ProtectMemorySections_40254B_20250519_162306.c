// --- Metadata ---
// Function Name: ProtectMemorySections_40254B
// Address: 0x40254B
// Exported At: 20250519_162306
// Signature: unknown_signature
// ---------------
BOOL __cdecl sub_40254B(_DWORD *baseAddr)
{
  int v2; // esi
  int v3; // ecx
  unsigned int v4; // eax
  int v5; // esi
  int v6; // edi
  unsigned int v7; // edi
  int v8; // eax
  int v9; // ecx
  DWORD flOldProtect; // [esp+Ch] [ebp-1Ch] BYREF
  unsigned int v12; // [esp+10h] [ebp-18h]
  int v13; // [esp+14h] [ebp-14h]
  unsigned int v14; // [esp+18h] [ebp-10h]
  int v15; // [esp+1Ch] [ebp-Ch]
  int v16; // [esp+20h] [ebp-8h]
  DWORD v17; // [esp+24h] [ebp-4h]
  int baseAddra; // [esp+30h] [ebp+8h]

  v2 = *(*baseAddr + 20) + *baseAddr + 24;
  v3 = *(*(*baseAddr + 20) + *baseAddr + 32) & ~(baseAddr[14] - 1);
  flOldProtect = *(*(*baseAddr + 20) + *baseAddr + 32);
  v12 = v3;
  v13 = GetHandler_40264F(baseAddr, v2);
  v4 = *(v2 + 36);
  v15 = 0;
  v14 = v4;
  v5 = v2 + 40;
  baseAddra = 1;
  if ( *(*baseAddr + 6) <= 1u )
  {
LABEL_12:
    v15 = 1;
    return ApplyMemoryProtection_40267B(baseAddr, &flOldProtect);// 메모리 보호를 섹션 단위로 적용 
  }
  while ( 1 )                                   //  PE 파일 로딩, 코드 압축 해제, 또는 런타임 복호화 같은 기능에서 사용 
  {
    v6 = baseAddr[14] - 1;
    v17 = *(v5 + 8);
    v7 = v17 & ~v6;
    v8 = GetHandler_40264F(baseAddr, v5);
    v16 = v8;
    if ( v12 == v7 || flOldProtect + v13 > v7 )
    {
      v9 = *(v5 + 36);
      if ( (v9 & 0x2000000) != 0 && (v14 & 0x2000000) != 0 )
        v14 |= v9;
      else
        v14 = (v14 | v9) & 0xFDFFFFFF;
      v13 = v17 + v8 - flOldProtect;
      goto LABEL_11;
    }
    if ( !ApplyMemoryProtection_40267B(baseAddr, &flOldProtect) )
      return 0;
    v12 = v7;
    flOldProtect = v17;
    v13 = v16;
    v14 = *(v5 + 36);
LABEL_11:
    ++baseAddra;
    v5 += 40;
    if ( baseAddra >= *(*baseAddr + 6) )
      goto LABEL_12;
  }
}
