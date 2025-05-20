// --- Metadata ---
// Function Name: OpenZipArchive_4074A4
// Address: 0x4074A4
// Exported At: 20250520_131527
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl OpenZipArchive_4074A4(HANDLE hFile, int a2, int a3, char *Str)
{
  _DWORD *rawContext; // ecx
  _DWORD *zipContext; // esi
  _DWORD *result; // eax

  rawContext = operator new(0x244u);
  if ( rawContext )
    zipContext = InitWithString_407527(rawContext, Str);// zip 컨텍스트와 리더를 생성한 후 핸들 반환 
  else
    zipContext = 0;
  dword_40F938 = InitZipFileReader_406B8E(zipContext, hFile, a2, a3);
  if ( dword_40F938 )
  {
    if ( zipContext )
    {
      ZipHandle_FreeBuffers_407572(zipContext);
      operator delete(zipContext);
    }
    result = 0;
  }
  else
  {
    result = operator new(8u);
    *result = 1;
    result[1] = zipContext;
  }
  return result;
}
