// --- Metadata ---
// Function Name: readLE16_405E27
// Address: 0x405E27
// Exported At: 20250517_210149
// Signature: unknown_signature
// ---------------
int __cdecl readLE16_405E27(_BYTE *inputStream, _DWORD *resultPointer)
{
  int result; // eax
  int v3; // esi
  int v4; // [esp+4h] [ebp-4h] BYREF

  result = readByte_405DEF(inputStream, &v4);   // 리틀 엔디안 2바이트 디코딩 
  v3 = v4;
  if ( result || (result = readByte_405DEF(inputStream, &v4)) != 0 )
    *resultPointer = 0;
  else
    *resultPointer = v3 + (v4 << 8);
  return result;
}
