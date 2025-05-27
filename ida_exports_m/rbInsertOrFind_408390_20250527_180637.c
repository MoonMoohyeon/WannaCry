// --- Metadata ---
// Function Name: rbInsertOrFind_408390
// Address: 0x408390
// Exported At: 20250527_180637
// Signature: unknown_signature
// ---------------
int __thiscall rbInsertOrFind_408390(int this, int a2, _DWORD *a3)
{
  _DWORD *v4; // ebx
  bool v5; // al
  _DWORD *v6; // ecx
  _DWORD *v7; // esi
  _DWORD *v8; // ebp
  _DWORD *v9; // eax
  _DWORD *v10; // eax
  _DWORD *v11; // ebp
  int v12; // eax
  _DWORD *v13; // ecx
  _DWORD *v14; // eax
  _DWORD *v15; // esi
  _DWORD *v16; // eax
  _DWORD *v17; // edx
  _DWORD *v18; // ecx
  int v19; // ecx
  int result; // eax
  int v21; // edx
  int v22; // edx
  int v23; // edx
  _DWORD *v24; // [esp+10h] [ebp-4h] BYREF

  v4 = a3;
  v5 = 1;
  v6 = *(this + 4);
  v7 = v6;
  v8 = v6[1];
  while ( v8 != *&FileName[280] )
  {
    v7 = v8;
    v5 = *a3 < v8[3];
    if ( *a3 >= v8[3] )
      v8 = v8[2];
    else
      v8 = *v8;
  }
  if ( *(this + 8) )
  {
    v9 = createRbNode_408DB0(v7, 0);
    a3 = v9;
    *v9 = *&FileName[280];
    v9[2] = *&FileName[280];
    copyNodeData_408E30(v9 + 3, v4);
    v10 = *(this + 4);
    ++*(this + 12);
    if ( v7 == v10 || v8 != *&FileName[280] || *v4 < v7[3] )
    {
      v13 = a3;
      *v7 = a3;
      v14 = *(this + 4);
      if ( v7 == v14 )
      {
        v14[1] = v13;
        *(*(this + 4) + 8) = v13;
      }
      else if ( v7 == *v14 )
      {
        *v14 = a3;
      }
      v11 = a3;
    }
    else
    {
      v11 = a3;
      v7[2] = a3;
      v12 = *(this + 4);
      if ( v7 == *(v12 + 8) )
        *(v12 + 8) = v11;
    }
    v15 = v11;
    while ( v15 != *(*(this + 4) + 4) )
    {
      v16 = v15[1];
      if ( v16[5] )
        break;
      v17 = v16[1];
      v18 = *v17;
      if ( v16 == *v17 )
      {
        v19 = v17[2];
        if ( *(v19 + 20) )
        {
          if ( v15 == v16[2] )
          {
            v15 = v15[1];
            RBrotateLeft_408CD0(v16);
          }
          *(v15[1] + 20) = 1;
          *(*(v15[1] + 4) + 20) = 0;
          RBrotateRight_408D50(*(v15[1] + 4));
        }
        else
        {
          v16[5] = 1;
          *(v19 + 20) = 1;
          *(*(v15[1] + 4) + 20) = 0;
          v15 = *(v15[1] + 4);
        }
      }
      else if ( v18[5] )
      {
        if ( v15 == *v16 )
        {
          v15 = v15[1];
          RBrotateRight_408D50(v16);
        }
        *(v15[1] + 20) = 1;
        *(*(v15[1] + 4) + 20) = 0;
        RBrotateLeft_408CD0(*(v15[1] + 4));
      }
      else
      {
        v16[5] = 1;
        v18[5] = 1;
        *(*(v15[1] + 4) + 20) = 0;
        v15 = *(v15[1] + 4);
      }
    }
    *(*(*(this + 4) + 4) + 20) = 1;
    result = a2;
    *a2 = v11;
    *(a2 + 4) = 1;
  }
  else
  {
    v21 = v7;
    v24 = v7;
    if ( v5 )
    {
      if ( v7 == *v6 )
      {
        v22 = *rbInsert_408A60(&a3, v8, v7, a3);
        result = a2;
        *a2 = v22;
        *(a2 + 4) = 1;
        return result;
      }
      rbNextInorder_408DD0(&v24);
      v21 = v24;
    }
    if ( *(v21 + 12) >= *v4 )
    {
      result = a2;
      *a2 = v21;
      *(a2 + 4) = 0;
    }
    else
    {
      v23 = *rbInsert_408A60(&a3, v8, v7, v4);
      result = a2;
      *a2 = v23;
      *(a2 + 4) = 1;
    }
  }
  return result;
}
