// --- Metadata ---
// Function Name: ZipArchive_ExtractEntry_407136
// Address: 0x407136
// Exported At: 20250519_105922
// Signature: unknown_signature
// ---------------
int __thiscall ZipArchive_ExtractEntry_407136(_DWORD **zipArc, HANDLE hFile, char *Source, int output_size, int mode)
{
  int v5; // ebx
  int result; // eax ZIP 아카이브에서 하나의 파일을 추출해서 읽기 스트림 연결 
  _DWORD *v8; // eax
  _DWORD *v9; // edi
  _DWORD *v10; // eax
  int v11; // edi
  _DWORD *v12; // eax
  HANDLE v13; // edi
  char v14; // al
  void *v15; // eax
  char *v16; // edi
  char *v17; // ebx
  char *v18; // ecx
  char i; // al
  signed int v20; // eax
  signed int v21; // edi
  CHAR FileName[260]; // [esp+Ch] [ebp-338h] BYREF
  char Src[264]; // [esp+110h] [ebp-234h] BYREF
  DWORD dwFlagsAndAttributes; // [esp+218h] [ebp-12Ch]
  FILETIME LastAccessTime; // [esp+21Ch] [ebp-128h] BYREF
  FILETIME CreationTime; // [esp+224h] [ebp-120h] BYREF
  FILETIME LastWriteTime; // [esp+22Ch] [ebp-118h] BYREF
  char Destination[260]; // [esp+23Ch] [ebp-108h] BYREF
  DWORD NumberOfBytesWritten; // [esp+340h] [ebp-4h] BYREF

  v5 = mode;
  if ( mode != 3 )                              // 읽기 스트림 연결 
  {
    if ( mode == 2 || mode == 1 )               // 파일 추출 
    {
      if ( zipArc[1] != -1 )
        closeSession_406A97(*zipArc);
      v12 = *zipArc;
      v13 = hFile;
      zipArc[1] = -1;
      if ( v13 < v12[1] )
      {
        if ( v13 < v12[4] )
          initCentralZipIterator_4064E2(v12);
        while ( (*zipArc)[4] < v13 )
          MoveToNextZipEntry_406520(*zipArc);
        LoadZipEntryMetadata_406C40(zipArc, v13, Src);
        if ( (dwFlagsAndAttributes & 0x10) != 0 )
        {
          if ( v5 != 1 )
          {
            v14 = *Source;
            if ( *Source == 47 || v14 == 92 || v14 && Source[1] == 58 )
              mkdirRecursive_407070(0, Source);
            else
              mkdirRecursive_407070(zipArc + 320, Source);
          }
          return 0;
        }
        if ( v5 == 1 )
        {
          v15 = Source;
          goto LABEL_48;
        }
        v16 = Source;
        v17 = Source;
        v18 = Source;
        for ( i = *Source; i; i = *++v18 )
        {
          if ( i == 47 || i == 92 )
            v17 = v18 + 1;
        }
        strcpy(Destination, Source);
        if ( v17 == v16 )
        {
          Destination[0] = 0;
        }
        else
        {
          Destination[v17 - v16] = 0;
          if ( Destination[0] == 47 || Destination[0] == 92 || Destination[0] && Destination[1] == 58 )
          {
            wsprintfA(FileName, "%s%s", Destination, v17);
            mkdirRecursive_407070(0, Destination);
            goto LABEL_47;
          }
        }
        wsprintfA(FileName, "%s%s%s", zipArc + 320, Destination, v17);
        mkdirRecursive_407070(zipArc + 320, Destination);
LABEL_47:
        v15 = CreateFileA(FileName, 0x40000000u, 0, 0, 2u, dwFlagsAndAttributes, 0);
LABEL_48:
        hFile = v15;
        if ( v15 == -1 )
          return 512;
        initZipFileStream_40671D(*zipArc, zipArc[78]);
        if ( !zipArc[79] )
          zipArc[79] = operator new(0x4000u);
        output_size = 0;
        while ( 1 )
        {
          v20 = ReadFromZipStream_406880(*zipArc, zipArc[79], 0x4000u, &Source + 3);
          v21 = v20;
          if ( v20 == -106 )
          {
            output_size = 4096;
            goto LABEL_69;
          }
          if ( v20 < 0 )
          {
LABEL_66:
            output_size = 83886080;
            goto LABEL_69;
          }
          if ( v20 > 0 && !WriteFile(hFile, zipArc[79], v20, &NumberOfBytesWritten, 0) )
          {
            output_size = 1024;
            goto LABEL_69;
          }
          if ( HIBYTE(Source) )
            break;
          if ( !v21 )
            goto LABEL_66;
        }
        SetFileTime(hFile, &CreationTime, &LastAccessTime, &LastWriteTime);
LABEL_69:
        if ( mode != 1 )
          CloseHandle(hFile);
        closeSession_406A97(*zipArc);
        return output_size;
      }
    }
    return 0x10000;
  }
  v8 = zipArc[1];
  v9 = hFile;
  if ( hFile != v8 )
  {
    if ( v8 != -1 )
      closeSession_406A97(*zipArc);
    v10 = *zipArc;
    zipArc[1] = -1;
    if ( v9 >= v10[1] )
      return 0x10000;
    if ( v9 < v10[4] )
      initCentralZipIterator_4064E2(v10);
    while ( (*zipArc)[4] < v9 )
      MoveToNextZipEntry_406520(*zipArc);
    initZipFileStream_40671D(*zipArc, zipArc[78]);
    zipArc[1] = v9;
  }
  v11 = ReadFromZipStream_406880(*zipArc, Source, output_size, &hFile + 3);
  if ( v11 <= 0 )
  {
    closeSession_406A97(*zipArc);
    zipArc[1] = -1;
  }
  if ( HIBYTE(hFile) )
    return 0;
  if ( v11 <= 0 )
    result = v11 != -106 ? 83886080 : 4096;
  else
    result = 1536;
  return result;
}
