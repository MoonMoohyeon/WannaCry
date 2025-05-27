// --- Metadata ---
// Function Name: freeRedBlackTree_4089D0
// Address: 0x4089D0
// Exported At: 20250527_175324
// Signature: unknown_signature
// ---------------
int __stdcall freeRedBlackTree_4089D0(void *Block)
{
  int result; // eax
  void *v2; // edi
  void **v3; // esi

  result = *&FileName[280];
  v2 = Block;
  v3 = Block;
  if ( Block != *&FileName[280] )               // 레드블랙 트리 삭제 
  {
    do
    {
      freeRedBlackTree_4089D0(v3[2]);
      v3 = *v3;
      freeBlock_4097FE(v2);
      result = *&FileName[280];
      v2 = v3;
    }
    while ( v3 != *&FileName[280] );
  }
  return result;
}
