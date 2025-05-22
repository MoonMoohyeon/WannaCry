// --- Metadata ---
// Function Name: DeleteNodeRangeDeep_100036A0
// Address: 0x100036A0
// Exported At: 20250522_175628
// Signature: unknown_signature
// ---------------
int __thiscall DeleteNodeRangeDeep_100036A0(_DWORD *this, int lastNodePtr, void *startNode, int endNode)
{
  _DWORD *curNode; // edi
  _DWORD **nodeToDelete; // esi
  _DWORD *attachedData; // ecx
  char refCount; // al
  int result; // eax

  curNode = startNode;
  if ( startNode == (void *)endNode )           // 범위 내 노드 삭제 
  {
    result = lastNodePtr;
    *(_DWORD *)lastNodePtr = startNode;
  }
  else
  {
    do
    {
      nodeToDelete = (_DWORD **)curNode;
      curNode = (_DWORD *)*curNode;
      *nodeToDelete[1] = *nodeToDelete;
      (*nodeToDelete)[1] = nodeToDelete[1];
      attachedData = nodeToDelete[3];
      if ( attachedData )
      {
        refCount = *((_BYTE *)attachedData - 1);
        if ( !refCount || refCount == -1 )
          operator delete((char *)attachedData - 2);
        else
          *((_BYTE *)attachedData - 1) = refCount - 1;
      }
      nodeToDelete[3] = 0;
      nodeToDelete[4] = 0;
      nodeToDelete[5] = 0;
      operator delete(nodeToDelete);
      --this[2];
    }
    while ( curNode != (_DWORD *)endNode );
    result = lastNodePtr;
    *(_DWORD *)lastNodePtr = curNode;
  }
  return result;
}
