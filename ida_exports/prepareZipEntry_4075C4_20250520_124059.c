// --- Metadata ---
// Function Name: prepareZipEntry_4075C4
// Address: 0x4075C4
// Exported At: 20250520_124059
// Signature: unknown_signature
// ---------------
int __cdecl prepareZipEntry_4075C4(int struct_dropperReturnValue, int a2, void *Src)
{
  int result; // eax

  *Src = 0;                                     // 메타데이터를 특정 조건에 따라 구조체(Src)에 채워 넣는 기능
  *(Src + 4) = 0;
  *(Src + 74) = 0;
  if ( struct_dropperReturnValue )
  {
    if ( *struct_dropperReturnValue == 1 )
      result = LoadZipEntryMetadata_406C40(*(struct_dropperReturnValue + 4), a2, Src);
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
