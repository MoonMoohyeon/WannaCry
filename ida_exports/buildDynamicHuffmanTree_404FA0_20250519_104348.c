// --- Metadata ---
// Function Name: buildDynamicHuffmanTree_404FA0
// Address: 0x404FA0
// Exported At: 20250519_104348
// Signature: unknown_signature
// ---------------
int __cdecl buildDynamicHuffmanTree_404FA0(int *a1, unsigned int *a2, _DWORD *a3, int a4, int a5)
{
  unsigned int *v5; // eax
  int v7; // eax
  int v8; // ebx
  unsigned int v9; // [esp+4h] [ebp-4h] BYREF

  v9 = 0;
  v5 = (*(a5 + 32))(*(a5 + 40), 19, 4);         // 메모리 할당 
  if ( !v5 )
    return -4;
  v7 = BuildHuffmanDecodingTable_404C19(a1, 0x13u, 0x13u, 0, 0, a3, a2, a4, &v9, v5);
  v8 = v7;
  if ( v7 == -3 )                               // 동적 허프만 트리 생성 
  {
    *(a5 + 24) = "oversubscribed dynamic bit lengths tree";
  }
  else if ( v7 == -5 || !*a2 )
  {
    *(a5 + 24) = "incomplete dynamic bit lengths tree";
    v8 = -3;
  }
  (*(a5 + 36))(*(a5 + 40));
  return v8;
}
