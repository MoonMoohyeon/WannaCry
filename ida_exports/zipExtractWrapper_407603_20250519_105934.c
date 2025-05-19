// --- Metadata ---
// Function Name: zipExtractWrapper_407603
// Address: 0x407603
// Exported At: 20250519_105934
// Signature: unknown_signature
// ---------------
int __cdecl zipExtractWrapper_407603(int a1, HANDLE hFile, char *Source, int a4, int a5)
{
  int result; // eax

  if ( a1 )
  {
    if ( *a1 == 1 )
      result = ZipArchive_ExtractEntry_407136(*(a1 + 4), hFile, Source, a4, a5);
    else
      result = 0x80000;
  }
  else
  {
    result = 0x10000;
  }
  dword_40F938 = result;
  return result;
}
