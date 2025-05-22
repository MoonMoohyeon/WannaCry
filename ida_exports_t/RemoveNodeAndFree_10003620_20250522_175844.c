// --- Metadata ---
// Function Name: RemoveNodeAndFree_10003620
// Address: 0x10003620
// Exported At: 20250522_175844
// Signature: unknown_signature
// ---------------
int __thiscall RemoveNodeAndFree_10003620(_DWORD *this, int a2, void *deleteNodePtr)
{
  int v4; // ebp
  int v5; // eax
  char v6; // cl
  int result; // eax

  v4 = *(_DWORD *)deleteNodePtr;                // 연결리스트 노드 삭제 
  **((_DWORD **)deleteNodePtr + 1) = *(_DWORD *)deleteNodePtr;
  *(_DWORD *)(*(_DWORD *)deleteNodePtr + 4) = *((_DWORD *)deleteNodePtr + 1);
  v5 = *((_DWORD *)deleteNodePtr + 3);
  if ( v5 )
  {
    v6 = *(_BYTE *)(v5 - 1);
    if ( !v6 || v6 == -1 )
      operator delete((void *)(v5 - 2));
    else
      *(_BYTE *)(v5 - 1) = v6 - 1;
  }
  *((_DWORD *)deleteNodePtr + 3) = 0;
  *((_DWORD *)deleteNodePtr + 4) = 0;
  *((_DWORD *)deleteNodePtr + 5) = 0;
  operator delete(deleteNodePtr);
  --this[2];
  result = a2;
  *(_DWORD *)a2 = v4;
  return result;
}
