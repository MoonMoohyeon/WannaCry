// --- Metadata ---
// Function Name: CreateLinkedNode_10003730
// Address: 0x10003730
// Exported At: 20250522_175614
// Signature: unknown_signature
// ---------------
_DWORD *__stdcall CreateLinkedNode_10003730(_DWORD *prevNode, int a2)
{
  _DWORD *newNode; // eax
  _DWORD *linkedPrev; // ecx

  newNode = operator new(0x18u);                // 연결리스트 노드 생성 
  linkedPrev = prevNode;
  if ( !prevNode )
    linkedPrev = newNode;
  *newNode = linkedPrev;
  if ( a2 )
    newNode[1] = a2;
  else
    newNode[1] = newNode;
  return newNode;
}
