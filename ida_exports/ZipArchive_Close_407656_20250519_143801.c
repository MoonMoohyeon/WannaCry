// --- Metadata ---
// Function Name: ZipArchive_Close_407656
// Address: 0x407656
// Exported At: 20250519_143801
// Signature: unknown_signature
// ---------------
int __cdecl ZipArchive_Close_407656(void *zipHandle)
{
  int result; // eax
  int *v2; // esi

  if ( !zipHandle )                             // ZIP 핸들을 안전하게 닫고 메모리 해제하는 최종 해제 함수 
  {
    result = 0x10000;
LABEL_5:
    dword_40F938 = result;
    return result;
  }
  if ( *zipHandle != 1 )
  {
    result = 0x80000;
    goto LABEL_5;
  }
  v2 = *(zipHandle + 1);
  dword_40F938 = ZipHandle_Release_40747B(v2);
  if ( v2 )
  {
    ZipHandle_FreeBuffers_407572(v2);
    operator delete(v2);
  }
  operator delete(zipHandle);
  return dword_40F938;
}
