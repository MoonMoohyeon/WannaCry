// --- Metadata ---
// Function Name: findMinNode_408D30
// Address: 0x408D30
// Exported At: 20250527_175300
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl findMinTreeNode_408D30(_DWORD **a1)
{
  _DWORD *result; // eax
  _DWORD *i; // ecx

  result = a1;
  for ( i = *a1; i != *&FileName[280]; i = *i ) // 최소 노드 찾기 
    result = i;
  return result;
}
