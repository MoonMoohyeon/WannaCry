// --- Metadata ---
// Function Name: FreeZipArchive_406162
// Address: 0x406162
// Exported At: 20250519_143723
// Signature: unknown_signature
// ---------------
int __cdecl FreeZipArchive_406162(void *archive)
{
  if ( !archive )                               // ZIP 세션이 살아 있으면 닫고, ZIP 엔트리 스트림도 정리한 후 Block 자체 해제.
    return -102;
  if ( *(archive + 31) )
    closeSession_406A97(archive);
  FreeZipEntryStream_405C9F(*archive);
  free(archive);
  return 0;
}
