// --- Metadata ---
// Function Name: writeCryptrandomToRes_10004730
// Address: 0x10004730
// Exported At: 20250522_170357
// Signature: unknown_signature
// ---------------
int writeCryptrandomToRes_10004730()
{
  HANDLE v0; // esi
  DWORD NumberOfBytesWritten; // [esp+4h] [ebp-4h] BYREF

  v0 = CreateFileA(resFile, 0x40000000u, 1u, 0, 4u, 0x80u, 0);// res 파일에 랜덤으로 cryptRandomGen으로 생성된 136바이트를 씀 
  if ( v0 == (HANDLE)-1 )
    return 0;
  NumberOfBytesWritten = 0;
  WriteFile(v0, &cryptRandom, 0x88u, &NumberOfBytesWritten, 0);
  CloseHandle(v0);
  return 136;
}
