// --- Metadata ---
// Function Name: ReadPointerFromStream_405E6B
// Address: 0x405E6B
// Exported At: 20250517_205922
// Signature: unknown_signature
// ---------------
int __cdecl ReadPointerFromStream_405E6B(_BYTE *readerPointer, _DWORD *resultPointer)
{
  _BYTE *v2; // esi
  int result; // eax
  _BYTE *v4; // edi
  _BYTE *v5; // edi
  _BYTE *v6; // edi

  v2 = readerPointer;
  result = readByte_405DEF(readerPointer, &readerPointer);// 리틀 엔디안 포인터 계산 
  v4 = readerPointer;
  if ( !result )
    result = readByte_405DEF(v2, &readerPointer);
  v5 = &v4[256 * readerPointer];
  if ( !result )
    result = readByte_405DEF(v2, &readerPointer);
  v6 = &v5[0x10000 * readerPointer];
  if ( result || (result = readByte_405DEF(v2, &readerPointer)) != 0 )// 읽은 4바이트를 리틀엔디안 포맷으로 주소 계산 
    *resultPointer = 0;
  else
    *resultPointer = &v6[0x1000000 * readerPointer];
  return result;                                // result = base + (byte0) + (byte1 << 8) + (byte2 << 16) + (byte3 << 24)
}
