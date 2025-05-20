// --- Metadata ---
// Function Name: lookupPEexportTable_402924
// Address: 0x402924
// Exported At: 20250520_113658
// Signature: unknown_signature
// ---------------
int __cdecl lookupPEexportTable_402924(int a1, char *String1)
{
  int baseAddr; // ecx
  _DWORD *exportDir; // esi
  unsigned int v4; // edx
  unsigned int ordinalIndex; // eax
  _DWORD *addrNamePtr; // edi
  unsigned __int16 *addrOrdinalName; // ebx
  int v9; // [esp+Ch] [ebp-4h]
  unsigned int v10; // [esp+18h] [ebp+8h]

  baseAddr = *(a1 + 4);                         // PE 내 Export Table을 수동 파싱하여 함수 주소를 찾음 
  v9 = baseAddr;
  if ( !*(*a1 + 124) )                          // 동적으로 API 주소를 찾는 데 사용 
    goto LABEL_12;
  exportDir = (baseAddr + *(*a1 + 120));
  if ( !exportDir[6] || !exportDir[5] )
    goto LABEL_12;
  if ( HIWORD(String1) )
  {
    addrNamePtr = (baseAddr + exportDir[8]);
    addrOrdinalName = (baseAddr + exportDir[9]);
    v10 = 0;
    while ( stricmp(String1, (baseAddr + *addrNamePtr)) )
    {
      ++v10;
      ++addrNamePtr;
      ++addrOrdinalName;
      if ( v10 >= exportDir[6] )
        goto LABEL_12;
      baseAddr = v9;
    }
    ordinalIndex = *addrOrdinalName;
    baseAddr = v9;
  }
  else
  {
    v4 = exportDir[4];
    if ( String1 < v4 )
    {
LABEL_12:
      SetLastError(0x7Fu);
      return 0;
    }
    ordinalIndex = String1 - v4;
  }
  if ( ordinalIndex > exportDir[5] )
    goto LABEL_12;
  return baseAddr + *(exportDir[7] + 4 * ordinalIndex + baseAddr);// RVA 
}
