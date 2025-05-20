// --- Metadata ---
// Function Name: FindZipEOCDoffset_405EDF
// Address: 0x405EDF
// Exported At: 20250520_125654
// Signature: unknown_signature
// ---------------
int __cdecl FindZipEOCDoffset_405EDF(int stream)
{
  DWORD v1; // ecx
  int v2; // edi
  void *v3; // ebx
  int v5; // eax
  unsigned int v6; // eax
  int v7; // eax
  int v8; // ecx
  DWORD v9; // [esp+8h] [ebp-10h]
  int v10; // [esp+Ch] [ebp-Ch]
  unsigned int v11; // [esp+10h] [ebp-8h]
  unsigned int v12; // [esp+14h] [ebp-4h]

  if ( SeekStreamOffset_405D0E(stream, 0, 2) )  // ZIP 파일의 끝에서 역방향으로 EOCD 시그니처를 탐색하여 오프셋을 반환 
    return -1;
  v1 = GetStreamOffset_405CDD(stream);          // ZIP 파일 내 중앙 디렉터리 파싱의 진입점 확보 
  v9 = v1;
  v12 = 0xFFFF;
  if ( v1 < 0xFFFF )
    v12 = v1;
  v2 = 1028;
  v3 = malloc(0x404u);
  if ( !v3 )
    return -1;
  v10 = -1;
  v5 = 4;
  if ( v12 > 4 )
  {
    while ( 1 )
    {
      v6 = v5 + 1024;
      v11 = v12;
      if ( v6 <= v12 )
        v11 = v6;
      if ( v11 <= 0x404 )
        v2 = v11;
      if ( SeekStreamOffset_405D0E(stream, v9 - v11, 0) || readFromReader_405D8A(v3, v2, 1, stream) != 1 )
        break;
      v7 = v2 - 3;
      while ( 1 )
      {
        v8 = v7--;
        if ( v8 < 0 )
          break;
        if ( *(v3 + v7) == 0x50 && *(v3 + v7 + 1) == 0x4B && *(v3 + v7 + 2) == 5 && *(v3 + v7 + 3) == 6 )
        {
          v10 = v9 - v11 + v7;
          break;
        }
      }
      if ( v10 || v11 >= v12 )
        break;
      v5 = v11;
      v2 = 1028;
    }
  }
  free(v3);
  return v10;
}
