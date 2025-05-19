// --- Metadata ---
// Function Name: FreeZipEntryStream_405C9F
// Address: 0x405C9F
// Exported At: 20250519_143712
// Signature: unknown_signature
// ---------------
int __cdecl FreeZipEntryStream_405C9F(void *entryStream)
{
  if ( !entryStream )                           // 객체 메모리 정리 
    return -1;
  if ( *(entryStream + 16) )
    CloseHandle(*(entryStream + 1));
  operator delete(entryStream);
  return 0;
}
