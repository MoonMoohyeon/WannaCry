// --- Metadata ---
// Function Name: rbTreeDelete_4085D0
// Address: 0x4085D0
// Exported At: 20250527_175313
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbTreeDelete_4085D0(_DWORD *this, _DWORD *a2, _DWORD *a3)
{
  _DWORD *v3; // edi
  _DWORD *v4; // esi
  _DWORD *v5; // ebx
  _DWORD *v6; // ebp
  _DWORD *v7; // eax
  _DWORD *i; // ecx
  _DWORD *v9; // edx
  _DWORD *v10; // ebp
  int v11; // eax
  _DWORD *v12; // eax
  int v13; // eax
  _DWORD *v14; // ecx
  int v15; // eax
  _DWORD *v16; // eax
  _DWORD *v17; // eax
  _DWORD *v18; // ecx
  _DWORD *v19; // eax
  int v20; // ebp
  _DWORD *j; // ecx
  _DWORD *v22; // eax
  int v23; // ecx
  _DWORD *v24; // eax
  int v25; // eax
  _DWORD *v26; // ecx
  int v27; // edx
  _DWORD *v28; // edx
  _DWORD *v29; // eax
  int v30; // ecx
  int v31; // edx
  int v32; // edx
  _DWORD *v33; // edx
  int v34; // ecx
  int v35; // edx
  int v36; // edx
  _DWORD *v37; // edx
  _DWORD *v38; // eax
  _DWORD *v39; // ecx
  int v40; // edx
  _DWORD *v41; // edx
  _DWORD *v42; // ecx
  int v43; // edx
  _DWORD *v44; // edx
  int v45; // edx
  int v46; // edx
  _DWORD *v47; // edx
  _DWORD *v48; // ecx
  _DWORD *result; // eax
  _DWORD *Block; // [esp+14h] [ebp-Ch]
  _DWORD *v52; // [esp+18h] [ebp-8h]
  char v53[4]; // [esp+1Ch] [ebp-4h] BYREF

  v3 = a3;
  rbTreeNextInOrder_408A10(&a3);
  v4 = *v3;
  v5 = v3 + 2;
  Block = v3;
  v6 = v3 + 2;
  if ( *v3 == *&FileName[280] )                 // 레드 블랙 트리의 삭제와 리밸런싱 
  {
    v4 = *v5;
  }
  else
  {
    v7 = *v5;
    if ( *v5 != *&FileName[280] )
    {
      for ( i = *v7; i != *&FileName[280]; i = *i )
        v7 = i;
      v4 = v7[2];
      v6 = v7 + 2;
      Block = v7;
    }
  }
  std::_Lockit::_Lockit(v53);
  v9 = Block;
  if ( Block == v3 )
  {
    v14 = this;
    v4[1] = Block[1];
    v15 = this[1];
    if ( *(v15 + 4) == v3 )
    {
      *(v15 + 4) = v4;
    }
    else
    {
      v16 = v3[1];
      if ( *v16 == v3 )
        *v16 = v4;
      else
        v16[2] = v4;
    }
    v17 = this[1];
    v52 = v17;
    if ( *v17 == v3 )
    {
      if ( *v5 == *&FileName[280] )
      {
        *v17 = v3[1];
      }
      else
      {
        v18 = v4;
        if ( *v4 != *&FileName[280] )
        {
          v19 = *v4;
          do
          {
            v18 = v19;
            v19 = *v19;
          }
          while ( v19 != *&FileName[280] );
          v17 = v52;
        }
        *v17 = v18;
        v14 = this;
      }
    }
    v20 = v14[1];
    if ( *(v20 + 8) == v3 )
    {
      if ( *v3 == *&FileName[280] )
      {
        j = v3[1];
      }
      else
      {
        v22 = v4[2];
        for ( j = v4; v22 != *&FileName[280]; v22 = v22[2] )
          j = v22;
      }
      *(v20 + 8) = j;
    }
    v10 = this;
  }
  else
  {
    *(*v3 + 4) = Block;
    *Block = *v3;
    if ( Block == *v5 )
    {
      v4[1] = Block;
    }
    else
    {
      v4[1] = Block[1];
      *Block[1] = v4;
      *v6 = *v5;
      *(*v5 + 4) = Block;
    }
    v10 = this;
    v11 = this[1];
    if ( *(v11 + 4) == v3 )
    {
      *(v11 + 4) = Block;
    }
    else
    {
      v12 = v3[1];
      if ( *v12 == v3 )
        *v12 = Block;
      else
        v12[2] = Block;
    }
    Block = v3;
    v9[1] = v3[1];
    v13 = v9[5];
    v9[5] = v3[5];
    v3[5] = v13;
    v9 = v3;
  }
  if ( v9[5] == 1 )
  {
    for ( ; v4 != *(v10[1] + 4); v4 = v4[1] )
    {
      if ( v4[5] != 1 )
        break;
      v23 = v4[1];
      v24 = *v23;
      if ( v4 == *v23 )
      {
        v24 = *(v23 + 8);
        if ( !v24[5] )
        {
          v24[5] = 1;
          *(v4[1] + 20) = 0;
          v25 = v4[1];
          v26 = *(v25 + 8);
          *(v25 + 8) = *v26;
          if ( *v26 != *&FileName[280] )
            *(*v26 + 4) = v25;
          v26[1] = *(v25 + 4);
          v27 = v10[1];
          if ( v25 == *(v27 + 4) )
          {
            *(v27 + 4) = v26;
          }
          else
          {
            v28 = *(v25 + 4);
            if ( v25 == *v28 )
              *v28 = v26;
            else
              v28[2] = v26;
          }
          *v26 = v25;
          *(v25 + 4) = v26;
          v24 = *(v4[1] + 8);
        }
        if ( *(*v24 + 20) != 1 || *(v24[2] + 20) != 1 )
        {
          if ( *(v24[2] + 20) == 1 )
          {
            *(*v24 + 20) = 1;
            v34 = *v24;
            v24[5] = 0;
            *v24 = *(v34 + 8);
            v35 = *(v34 + 8);
            if ( v35 != *&FileName[280] )
              *(v35 + 4) = v24;
            *(v34 + 4) = v24[1];
            v36 = v10[1];
            if ( v24 == *(v36 + 4) )
            {
              *(v36 + 4) = v34;
            }
            else
            {
              v37 = v24[1];
              if ( v24 == v37[2] )
                v37[2] = v34;
              else
                *v37 = v34;
            }
            *(v34 + 8) = v24;
            v24[1] = v34;
            v24 = *(v4[1] + 8);
          }
          v24[5] = *(v4[1] + 20);
          *(v4[1] + 20) = 1;
          *(v24[2] + 20) = 1;
          v38 = v4[1];
          v39 = v38[2];
          v38[2] = *v39;
          if ( *v39 != *&FileName[280] )
            *(*v39 + 4) = v38;
          v39[1] = v38[1];
          v40 = v10[1];
          if ( v38 == *(v40 + 4) )
          {
            *(v40 + 4) = v39;
            *v39 = v38;
          }
          else
          {
            v41 = v38[1];
            if ( v38 == *v41 )
              *v41 = v39;
            else
              v41[2] = v39;
            *v39 = v38;
          }
LABEL_100:
          v38[1] = v39;
          break;
        }
      }
      else
      {
        if ( !v24[5] )
        {
          v24[5] = 1;
          *(v4[1] + 20) = 0;
          v29 = v4[1];
          v30 = *v29;
          *v29 = *(*v29 + 8);
          v31 = *(v30 + 8);
          if ( v31 != *&FileName[280] )
            *(v31 + 4) = v29;
          *(v30 + 4) = v29[1];
          v32 = v10[1];
          if ( v29 == *(v32 + 4) )
          {
            *(v32 + 4) = v30;
          }
          else
          {
            v33 = v29[1];
            if ( v29 == v33[2] )
              v33[2] = v30;
            else
              *v33 = v30;
          }
          *(v30 + 8) = v29;
          v29[1] = v30;
          v24 = *v4[1];
        }
        if ( *(v24[2] + 20) != 1 || *(*v24 + 20) != 1 )
        {
          if ( *(*v24 + 20) == 1 )
          {
            *(v24[2] + 20) = 1;
            v42 = v24[2];
            v24[5] = 0;
            v24[2] = *v42;
            if ( *v42 != *&FileName[280] )
              *(*v42 + 4) = v24;
            v42[1] = v24[1];
            v43 = v10[1];
            if ( v24 == *(v43 + 4) )
            {
              *(v43 + 4) = v42;
            }
            else
            {
              v44 = v24[1];
              if ( v24 == *v44 )
                *v44 = v42;
              else
                v44[2] = v42;
            }
            *v42 = v24;
            v24[1] = v42;
            v24 = *v4[1];
          }
          v24[5] = *(v4[1] + 20);
          *(v4[1] + 20) = 1;
          *(*v24 + 20) = 1;
          v38 = v4[1];
          v39 = *v38;
          *v38 = *(*v38 + 8);
          v45 = v39[2];
          if ( v45 != *&FileName[280] )
            *(v45 + 4) = v38;
          v39[1] = v38[1];
          v46 = v10[1];
          if ( v38 == *(v46 + 4) )
          {
            *(v46 + 4) = v39;
          }
          else
          {
            v47 = v38[1];
            if ( v38 == v47[2] )
              v47[2] = v39;
            else
              *v47 = v39;
          }
          v39[2] = v38;
          goto LABEL_100;
        }
      }
      v24[5] = 0;
    }
    v4[5] = 1;
  }
  std::_Lockit::~_Lockit(v53);
  freeBlock_4097FE(Block);
  v48 = a3;
  --v10[3];
  result = a2;
  *a2 = v48;
  return result;
}
