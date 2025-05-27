// --- Metadata ---
// Function Name: insertValueIntoArray_409470
// Address: 0x409470
// Exported At: 20250527_190702
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall insertValueIntoArray_409470(int this, _DWORD *a2, unsigned int a3, _DWORD *a4)
{
  int v5; // edi
  _DWORD *result; // eax
  int v7; // edx
  unsigned int v8; // ecx
  int v9; // eax
  int v10; // eax
  _DWORD *v11; // ecx
  _DWORD *m; // eax
  _DWORD *v13; // eax
  unsigned int v14; // edx
  _DWORD *v15; // edi
  _DWORD *v16; // edx
  _DWORD *v17; // eax
  int v18; // ecx
  int v19; // eax
  unsigned int v20; // ebx
  _DWORD *v21; // esi
  _DWORD *v22; // ecx
  _DWORD *v23; // eax
  unsigned int k; // ebp
  _DWORD *v25; // ecx
  _DWORD *l; // eax
  unsigned int v27; // ebp
  _DWORD *v28; // esi
  _DWORD *i; // ecx
  _DWORD *v30; // ecx
  _DWORD *j; // eax
  int v32; // esi
  int v34; // [esp+14h] [ebp-4h]
  _DWORD *v35; // [esp+20h] [ebp+8h]

  v5 = this;
  result = *(this + 8);                         // 동적 배열(버퍼)에 지정된 위치에 값을 삽입하는 함수 
  if ( (*(this + 12) - result) >> 2 >= a3 )
  {
    if ( result - a2 >= a3 )
    {
      if ( a3 )
      {
        v27 = 4 * a3;
        v28 = *(this + 8);
        for ( i = &result[-a3]; i != result; ++v28 )
        {
          if ( v28 )
            *v28 = *i;
          ++i;
        }
        v30 = *(v5 + 8);
        for ( j = &v30[v27 / 0xFFFFFFFC]; j != a2; *v30 = v32 )
        {
          v32 = *--j;
          --v30;
        }
        for ( result = a2; result != &a2[v27 / 4]; ++result )
          *result = *a4;
        *(v5 + 8) += v27;
      }
    }
    else
    {
      v20 = 4 * a3;
      v21 = &a2[a3];
      if ( a2 != result )
      {
        v22 = &v21[v20 / 0xFFFFFFFC];
        do
        {
          if ( v21 )
          {
            *v21 = *v22;
            v5 = this;
          }
          ++v22;
          ++v21;
        }
        while ( v22 != result );
      }
      v23 = *(v5 + 8);
      for ( k = a3 - (v23 - a2); k; --k )
      {
        if ( v23 )
          *v23 = *a4;
        ++v23;
      }
      v25 = *(v5 + 8);
      for ( l = a2; l != v25; ++l )
        *l = *a4;
      result = (v20 + *(v5 + 8));
      *(v5 + 8) = result;
    }
  }
  else
  {
    v7 = *(this + 4);
    if ( !v7 || (v8 = (result - v7) >> 2, a3 >= v8) )
      v8 = a3;
    if ( v7 )
      v9 = (result - v7) >> 2;
    else
      v9 = 0;
    v10 = v8 + v9;
    v34 = v10;
    if ( v10 < 0 )
      v10 = 0;
    v35 = operator new(4 * v10);
    v11 = v35;
    for ( m = *(v5 + 4); m != a2; ++v11 )
    {
      if ( v11 )
        *v11 = *m;
      ++m;
    }
    v13 = v11;
    if ( a3 )
    {
      v14 = a3;
      do
      {
        if ( v13 )
        {
          *v13 = *a4;
          v5 = this;
        }
        ++v13;
        --v14;
      }
      while ( v14 );
    }
    v15 = *(v5 + 8);
    v16 = &v11[a3];
    if ( a2 != v15 )
    {
      v17 = a2;
      do
      {
        if ( v16 )
          *v16 = *v17;
        ++v17;
        ++v16;
      }
      while ( v17 != v15 );
    }
    freeBlock_4097FE(*(this + 4));
    *(this + 12) = &v35[v34];
    v18 = *(this + 4);
    if ( v18 )
    {
      v19 = *(this + 8);
      *(this + 4) = v35;
      result = &v35[a3 + ((v19 - v18) >> 2)];
    }
    else
    {
      *(this + 4) = v35;
      result = &v35[a3];
    }
    *(this + 8) = result;
  }
  return result;
}
