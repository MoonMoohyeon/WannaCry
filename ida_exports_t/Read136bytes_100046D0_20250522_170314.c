// --- Metadata ---
// Function Name: Read136bytes_100046D0
// Address: 0x100046D0
// Exported At: 20250522_170314
// Signature: unknown_signature
// ---------------
int Read136bytes_100046D0()
{
  HANDLE v0; // esi
  DWORD NumberOfBytesRead; // [esp+4h] [ebp-4h] BYREF

  v0 = CreateFileA(resFile, 0x80000000, 1u, 0, 3u, 0, 0);// 버퍼는 파일 경로 
  if ( v0 == (HANDLE)-1 )
    return 0;
  NumberOfBytesRead = 0;
  ReadFile(v0, &cryptRandom, 136u, &NumberOfBytesRead, 0);// 어떤 파일에서 136바이트를 읽음 
  CloseHandle(v0);
  return 136;
}
