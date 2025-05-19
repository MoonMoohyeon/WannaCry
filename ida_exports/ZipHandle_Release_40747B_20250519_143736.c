// --- Metadata ---
// Function Name: ZipHandle_Release_40747B
// Address: 0x40747B
// Exported At: 20250519_143736
// Signature: unknown_signature
// ---------------
int __thiscall ZipHandle_Release_40747B(int *zipHandle)
{
  void *v2; // eax

  if ( zipHandle[1] != -1 )                     // ZIP 세션을 종료하고, 내부 구조체도 정리
    closeSession_406A97(*zipHandle);
  v2 = *zipHandle;
  zipHandle[1] = -1;
  if ( v2 )
    FreeZipArchive_406162(v2);
  *zipHandle = 0;
  return 0;
}
