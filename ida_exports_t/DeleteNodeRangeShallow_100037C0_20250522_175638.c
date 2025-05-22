// --- Metadata ---
// Function Name: DeleteNodeRangeShallow_100037C0
// Address: 0x100037C0
// Exported At: 20250522_175638
// Signature: unknown_signature
// ---------------
int __thiscall DeleteNodeRangeShallow_100037C0(_DWORD *this, int lastNodePtr, void *startNode, int endNode)
{
  _DWORD *curNode; // esi
  _DWORD **nodeToDelete; // eax
  int result; // eax

  curNode = startNode;
  if ( startNode != (void *)endNode )           // 범위 내 노드 제거(얕은)
  {
    do
    {
      nodeToDelete = (_DWORD **)curNode;
      curNode = (_DWORD *)*curNode;
      *nodeToDelete[1] = *nodeToDelete;
      (*nodeToDelete)[1] = nodeToDelete[1];
      operator delete(nodeToDelete);
      --this[2];
    }
    while ( curNode != (_DWORD *)endNode );
  }
  result = lastNodePtr;
  *(_DWORD *)lastNodePtr = curNode;
  return result;
}
