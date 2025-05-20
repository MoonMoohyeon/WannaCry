// --- Metadata ---
// Function Name: FindZipEOCDoffset_405EDF
// Address: 0x405EDF
// Exported At: 20250520_125854
// Signature: unknown_signature
// ---------------
int __cdecl FindZipEOCDoffset_405EDF(int stream)
{
  DWORD fileSize; // ecx
  int readSize; // edi
  void *readBuffer; // ebx
  int offsetIncrement; // eax
  unsigned int v6; // eax
  int sigSearchIndex; // eax
  int v8; // ecx
  DWORD v9; // [esp+8h] [ebp-10h]
  int eocdOffset; // [esp+Ch] [ebp-Ch]
  unsigned int v11; // [esp+10h] [ebp-8h]
  unsigned int v12; // [esp+14h] [ebp-4h]

  if ( SeekStreamOffset_405D0E(stream, 0, 2) )  // ZIP 파일의 끝에서 역방향으로 EOCD 시그니처를 탐색하여 오프셋을 반환 
    return -1;
  fileSize = GetStreamOffset_405CDD(stream);    // ZIP 파일 내 중앙 디렉터리 파싱의 진입점 확보 
  v9 = fileSize;
  v12 = 0xFFFF;
  if ( fileSize < 0xFFFF )
    v12 = fileSize;
  readSize = 1028;
  readBuffer = malloc(0x404u);
  if ( !readBuffer )
    return -1;
  eocdOffset = -1;
  offsetIncrement = 4;
  if ( v12 > 4 )
  {
    while ( 1 )
    {
      v6 = offsetIncrement + 1024;
      v11 = v12;
      if ( v6 <= v12 )
        v11 = v6;
      if ( v11 <= 0x404 )
        readSize = v11;
      if ( SeekStreamOffset_405D0E(stream, v9 - v11, 0) || readFromReader_405D8A(readBuffer, readSize, 1, stream) != 1 )
        break;
      sigSearchIndex = readSize - 3;
      while ( 1 )
      {
        v8 = sigSearchIndex--;
        if ( v8 < 0 )
          break;
        if ( *(readBuffer + sigSearchIndex) == 0x50
          && *(readBuffer + sigSearchIndex + 1) == 0x4B
          && *(readBuffer + sigSearchIndex + 2) == 5
          && *(readBuffer + sigSearchIndex + 3) == 6 )
        {
          eocdOffset = v9 - v11 + sigSearchIndex;
          break;
        }
      }
      if ( eocdOffset || v11 >= v12 )
        break;
      offsetIncrement = v11;
      readSize = 1028;
    }
  }
  free(readBuffer);
  return eocdOffset;
}
