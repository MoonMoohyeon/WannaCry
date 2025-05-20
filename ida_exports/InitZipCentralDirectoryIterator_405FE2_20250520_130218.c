// --- Metadata ---
// Function Name: InitZipCentralDirectoryIterator_405FE2
// Address: 0x405FE2
// Exported At: 20250520_130218
// Signature: unknown_signature
// ---------------
int *__cdecl InitZipCentralDirectoryIterator_405FE2(void *stream)
{
  LONG eocdOffset; // eax
  int v3; // edi
  int v4; // eax
  int v6; // eax
  int *v7; // ebx
  int v8[32]; // [esp+Ch] [ebp-90h] BYREF
  int v9; // [esp+8Ch] [ebp-10h] BYREF
  int v10; // [esp+90h] [ebp-Ch] BYREF
  int v11; // [esp+94h] [ebp-8h] BYREF
  int v12; // [esp+98h] [ebp-4h] BYREF
  int streama; // [esp+A4h] [ebp+8h]

  if ( !stream )
    return 0;
  streama = 0;
  eocdOffset = FindZipEOCDoffset_405EDF(stream);// EOCD를 찾아 ZIP 중앙 디렉터리 구조를 초기화 
  v3 = eocdOffset;
  if ( eocdOffset == -1 )
    streama = -1;
  if ( SeekStreamOffset_405D0E(stream, eocdOffset, 0) )
    streama = -1;
  if ( ReadPointerFromStream_405E6B(stream, &v9) )
    streama = -1;
  if ( readLE16_405E27(stream, &v12) )
    streama = -1;
  if ( readLE16_405E27(stream, &v10) )
    streama = -1;
  if ( readLE16_405E27(stream, &v8[1]) )
    streama = -1;
  if ( readLE16_405E27(stream, &v11) )
    streama = -1;
  if ( v11 != v8[1] || v10 || v12 )
    streama = -103;
  if ( ReadPointerFromStream_405E6B(stream, &v8[8]) )
    streama = -1;
  if ( ReadPointerFromStream_405E6B(stream, &v8[9]) )
    streama = -1;
  if ( readLE16_405E27(stream, &v8[2]) )
    streama = -1;
  v4 = *(stream + 3);
  if ( v4 + v3 < (v8[9] + v8[8]) )
  {
    if ( streama )
    {
LABEL_30:
      FreeZipEntryStream_405C9F(stream);
      return 0;
    }
    streama = -103;
  }
  if ( streama )
    goto LABEL_30;
  v8[0] = stream;
  v8[7] = v3;
  v8[31] = 0;
  v6 = v3 + v4 - v8[8] - v8[9];
  *(stream + 3) = 0;
  v8[3] = v6;
  v7 = malloc(0x80u);
  qmemcpy(v7, v8, 0x80u);
  initCentralZipIterator_4064E2(v7);
  return v7;
}
