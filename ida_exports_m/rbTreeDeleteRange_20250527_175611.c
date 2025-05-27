// --- Metadata ---
// Function Name: rbTreeDeleteRange
// Address: 0x4082C0
// Exported At: 20250527_175611
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbTreeDeleteRange(_DWORD *this, _DWORD *a2, _DWORD *a3, _DWORD *a4)
{
  _DWORD *v4; // ebp
  _DWORD *v5; // esi
  _DWORD *v7; // eax
  void **v8; // ebx
  int v9; // eax
  void **j; // esi
  _DWORD *v11; // eax
  _DWORD *result; // eax
  _DWORD *v13; // ebx
  _DWORD *i; // eax

  v4 = a4;
  v5 = a3;
  if ( !this[3] || (v7 = this[1], a3 != *v7) || a4 != v7 )// 레드블랙트리의 특정 구간 노드 삭제 
  {
    if ( a3 == a4 )
    {
LABEL_15:
      result = a2;
      *a2 = v5;
      return result;
    }
    while ( 1 )
    {
      v13 = v5;
      if ( v5[2] == *&FileName[280] )
      {
        for ( i = v5[1]; v5 == i[2]; i = i[1] )
          v5 = i;
        if ( v5[2] == i )
          goto LABEL_14;
      }
      else
      {
        i = findMinNode_408D30(v5[2]);
      }
      v5 = i;
LABEL_14:
      rbTreeDelete_4085D0(this, &a4, v13);
      if ( v5 == v4 )
        goto LABEL_15;
    }
  }
  v8 = v7[1];
  v9 = *&FileName[280];
  for ( j = v8; j != *&FileName[280]; v8 = j )
  {
    freeRedBlackTree_4089D0(j[2]);
    j = *j;
    freeBlock_4097FE(v8);
    v9 = *&FileName[280];
  }
  *(this[1] + 4) = v9;
  v11 = this[1];
  this[3] = 0;
  *v11 = v11;
  *(this[1] + 8) = this[1];
  result = a2;
  *a2 = *this[1];
  return result;
}
