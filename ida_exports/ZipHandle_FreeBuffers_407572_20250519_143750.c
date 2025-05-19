// --- Metadata ---
// Function Name: ZipHandle_FreeBuffers_407572
// Address: 0x407572
// Exported At: 20250519_143750
// Signature: unknown_signature
// ---------------
void __thiscall ZipHandle_FreeBuffers_407572(void **zipHandle)
{
  void **v2; // esi

  v2 = zipHandle + 78;                          // ZIP 처리 중 사용한 버퍼 메모리 2개를 정리
  if ( zipHandle[78] )
    operator delete(zipHandle[78]);
  *v2 = 0;
  if ( zipHandle[79] )
    operator delete(zipHandle[79]);
  zipHandle[79] = 0;
}
