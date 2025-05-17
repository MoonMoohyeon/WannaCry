// --- Metadata ---
// Function Name: readByte_405DEF
// Address: 0x405DEF
// Exported At: 20250517_204406
// Signature: unknown_signature
// ---------------
int __cdecl readByte_405DEF(_BYTE *a1, _DWORD *a2)
{
  int v2; // ecx
  unsigned __int8 Buffer; // [esp+1h] [ebp-1h] BYREF

  Buffer = HIBYTE(v2);
  if ( readFromReader_405D8A(&Buffer, 1, 1, a1) != 1 )// Reader에서 1바이트씩 읽기
    return -isReaderValid_405CC7(a1);
  *a2 = Buffer;
  return 0;
}
