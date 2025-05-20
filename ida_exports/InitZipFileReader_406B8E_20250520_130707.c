// --- Metadata ---
// Function Name: InitZipFileReader_406B8E
// Address: 0x406B8E
// Exported At: 20250520_130707
// Signature: unknown_signature
// ---------------
int __thiscall InitZipFileReader_406B8E(void *zipContext, HANDLE hFile, int a3, int fileAccessType)
{
  char lastChar; // al
  _BYTE *v7; // eax
  int *zipIterator; // eax
  int resultCode; // eax
  int v10; // [esp+4h] [ebp-4h] BYREF

  if ( *zipContext || *(zipContext + 1) != -1 ) // 이미 초기화된 객체인지 검사 
    return 0x1000000;
  GetCurrentDirectoryA(0x104u, zipContext + 320);
  lastChar = *(zipContext + strlen(zipContext + 320) + 319);// 작업 디렉터리 경로 설정 
  if ( lastChar != '\\' && lastChar != '/' )
    strcat(zipContext + 320, "\\");
  if ( fileAccessType == 1 && SetFilePointer(hFile, 0, 0, 1u) == -1 )
    return 0x2000000;
  v7 = CreateFileReaderContext_405BAE(hFile, a3, fileAccessType, &v10);
  if ( !v7 )
    return v10;
  zipIterator = InitZipCentralDirectoryIterator_405FE2(v7);// ZIP 중앙 디렉터리 반복자 초기화 
  *zipContext = zipIterator;
  resultCode = -(zipIterator != 0);
  LOWORD(resultCode) = resultCode & 0xFE00;
  return resultCode + 512;
}
