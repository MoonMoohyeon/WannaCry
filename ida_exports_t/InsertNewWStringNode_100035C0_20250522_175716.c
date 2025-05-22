// --- Metadata ---
// Function Name: InsertNewWStringNode_100035C0
// Address: 0x100035C0
// Exported At: 20250522_175716
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall InsertNewWStringNode_100035C0(_DWORD *this, _DWORD *NewNodePtr, _DWORD *currentNode, int newStringSource)
{
  _DWORD *nextNode; // ebp
  _DWORD *newNode; // esi
  _DWORD *v7; // eax
  _DWORD *v8; // eax
  _DWORD *result; // eax

  nextNode = (_DWORD *)currentNode[1];          // 이중 연결 리스트에 wstring을 담은 새 노드를 생성 및 삽입 
  newNode = operator new(0x18u);
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
  WStringAssign_10003810((int)(newNode + 2), (char *)newStringSource);
  ++this[2];
  result = NewNodePtr;
  *NewNodePtr = newNode;
  return result;
}
