// --- Metadata ---
// Function Name: rbInsert_408A60
// Address: 0x408A60
// Exported At: 20250527_180426
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbInsert_408A60(_DWORD *this, _DWORD *a2, int a3, _DWORD *a4, _DWORD *a5)
{
  _DWORD *v6; // ebp
  _DWORD *v7; // eax
  int v8; // eax
  _DWORD *v9; // eax
  _DWORD *v10; // eax
  _DWORD *v11; // ecx
  _DWORD *v12; // esi
  _DWORD *v13; // edx
  int v14; // edx
  _DWORD *v15; // ecx
  int v16; // edx
  _DWORD *v17; // edx
  _DWORD *v18; // ecx
  _DWORD *v19; // edx
  int v20; // esi
  int v21; // esi
  _DWORD *v22; // esi
  _DWORD *v23; // ecx
  int v24; // edx
  int v25; // edx
  _DWORD *v26; // edx
  int v27; // esi
  _DWORD *v28; // esi
  _DWORD *result; // eax

  v6 = operator new(0x18u);
  v6[1] = a4;
  v6[5] = 0;
  *v6 = *&FileName[280];
  v6[2] = *&FileName[280];
  copyNodeData_408E30(v6 + 3, a5);
  v7 = this[1];
  ++this[3];
  if ( a4 == v7 || a3 != *&FileName[280] || *a5 < a4[3] )
  {
    *a4 = v6;
    v9 = this[1];
    if ( a4 == v9 )
    {
      v9[1] = v6;
      *(this[1] + 8) = v6;
    }
    else if ( a4 == *v9 )
    {
      *v9 = v6;
    }
  }
  else
  {
    a4[2] = v6;
    v8 = this[1];
    if ( a4 == *(v8 + 8) )
      *(v8 + 8) = v6;
  }
  v10 = v6;
  while ( v10 != *(this[1] + 4) )
  {
    v11 = v10[1];
    if ( v11[5] )
      break;
    v12 = v11[1];
    v13 = *v12;
    if ( v11 == *v12 )
    {
      v14 = v12[2];
      if ( *(v14 + 20) )
      {
        if ( v10 == v11[2] )
        {
          v10 = v10[1];
          v15 = v11[2];
          v10[2] = *v15;
          if ( *v15 != *&FileName[280] )
            *(*v15 + 4) = v10;
          v15[1] = v10[1];
          v16 = this[1];
          if ( v10 == *(v16 + 4) )
          {
            *(v16 + 4) = v15;
          }
          else
          {
            v17 = v10[1];
            if ( v10 == *v17 )
              *v17 = v15;
            else
              v17[2] = v15;
          }
          *v15 = v10;
          v10[1] = v15;
        }
        *(v10[1] + 20) = 1;
        *(*(v10[1] + 4) + 20) = 0;
        v18 = *(v10[1] + 4);
        v19 = *v18;
        *v18 = *(*v18 + 8);
        v20 = v19[2];
        if ( v20 != *&FileName[280] )
          *(v20 + 4) = v18;
        v19[1] = v18[1];
        v21 = this[1];
        if ( v18 == *(v21 + 4) )
        {
          *(v21 + 4) = v19;
          v19[2] = v18;
        }
        else
        {
          v22 = v18[1];
          if ( v18 == v22[2] )
            v22[2] = v19;
          else
            *v22 = v19;
          v19[2] = v18;
        }
LABEL_51:
        v18[1] = v19;
        continue;
      }
      v11[5] = 1;
      *(v14 + 20) = 1;
      *(*(v10[1] + 4) + 20) = 0;
      v10 = *(v10[1] + 4);
    }
    else
    {
      if ( v13[5] )
      {
        if ( v10 == *v11 )
        {
          v10 = v10[1];
          v23 = *v11;
          *v10 = v23[2];
          v24 = v23[2];
          if ( v24 != *&FileName[280] )
            *(v24 + 4) = v10;
          v23[1] = v10[1];
          v25 = this[1];
          if ( v10 == *(v25 + 4) )
          {
            *(v25 + 4) = v23;
          }
          else
          {
            v26 = v10[1];
            if ( v10 == v26[2] )
              v26[2] = v23;
            else
              *v26 = v23;
          }
          v23[2] = v10;
          v10[1] = v23;
        }
        *(v10[1] + 20) = 1;
        *(*(v10[1] + 4) + 20) = 0;
        v18 = *(v10[1] + 4);
        v19 = v18[2];
        v18[2] = *v19;
        if ( *v19 != *&FileName[280] )
          *(*v19 + 4) = v18;
        v19[1] = v18[1];
        v27 = this[1];
        if ( v18 == *(v27 + 4) )
        {
          *(v27 + 4) = v19;
        }
        else
        {
          v28 = v18[1];
          if ( v18 == *v28 )
            *v28 = v19;
          else
            v28[2] = v19;
        }
        *v19 = v18;
        goto LABEL_51;
      }
      v11[5] = 1;
      v13[5] = 1;
      *(*(v10[1] + 4) + 20) = 0;
      v10 = *(v10[1] + 4);
    }
  }
  *(*(this[1] + 4) + 20) = 1;
  result = a2;
  *a2 = v6;
  return result;
}
