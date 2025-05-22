// --- Metadata ---
// Function Name: InsertNodeAfterCopyData_10003760
// Address: 0x10003760
// Exported At: 20250522_175742
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall InsertNodeAfterCopyData_10003760(_DWORD *this, _DWORD *outNewNode, _DWORD *currentNode, const void *dataToCopy)
{
  _DWORD *nextNode; // edi
  _DWORD *newNode; // eax
  _DWORD *v7; // ecx
  _DWORD *v8; // ecx

  nextNode = (_DWORD *)currentNode[1];          // 새 노드를 삽입하고, 새 노드에 데이터를 복사 
  newNode = operator new(0x4ECu);
  v7 = currentNode;
  if ( !currentNode )
    v7 = newNode;
  *newNode = v7;
  v8 = nextNode;
  if ( !nextNode )
    v8 = newNode;
  newNode[1] = v8;
  currentNode[1] = newNode;
  *(_DWORD *)newNode[1] = newNode;
  if ( newNode != (_DWORD *)-8 )
    qmemcpy(newNode + 2, dataToCopy, 0x4E4u);
  ++this[2];
  *outNewNode = newNode;
  return outNewNode;
}
