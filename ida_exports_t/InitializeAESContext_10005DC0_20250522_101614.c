// --- Metadata ---
// Function Name: InitializeAESContext_10005DC0
// Address: 0x10005DC0
// Exported At: 20250522_101614
// Signature: unknown_signature
// ---------------
int __thiscall InitializeAESContext_10005DC0(int this, int IVPtr, int keyPtr, int keyLen, int IVLen)
{
  int v6; // ecx
  const void *v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // eax
  int v11; // edx
  int v12; // eax
  int wordsPerKey; // ecx
  char *v14; // esi
  int v15; // edx
  char *v16; // esi
  int v17; // esi
  __int64 v18; // rax
  int v19; // edi
  int v20; // ebp
  unsigned __int8 *v21; // eax
  int v22; // ebp
  _BYTE *v23; // eax
  unsigned __int16 v24; // dx
  int v25; // esi
  int v26; // eax
  int v27; // edx
  int v28; // eax
  int v29; // ecx
  _DWORD *v30; // eax
  int v31; // ecx
  _DWORD *v32; // eax
  int v33; // ecx
  int v34; // ecx
  _DWORD *v35; // eax
  int *v36; // edi
  int v37; // ebp
  int v38; // ecx
  int v39; // edx
  int v40; // eax
  bool v41; // cc
  int v42; // edx
  int result; // eax
  int v44; // ebp
  int *v45; // esi
  int v46; // edi
  int v47; // edx
  int v48; // [esp+4h] [ebp-10h]
  char pExceptionObject[12]; // [esp+8h] [ebp-Ch] BYREF

  if ( !IVPtr )                                 // AES 암호화의 키 확장과 상태 초기화 루틴 
  {
    IVPtr = (int)&unk_1000D8D8;
    exception::exception((exception *)pExceptionObject, (const char *const *)&IVPtr);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  if ( keyLen != 16 && keyLen != 24 && keyLen != 32 )
  {
    IVPtr = (int)&unk_1000D8D8;
    exception::exception((exception *)pExceptionObject, (const char *const *)&IVPtr);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  v6 = IVLen;
  if ( IVLen != 16 && IVLen != 24 && IVLen != 32 )
  {
    IVPtr = (int)&unk_1000D8D8;
    exception::exception((exception *)pExceptionObject, (const char *const *)&IVPtr);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  *(_DWORD *)(this + 968) = keyLen;
  v7 = (const void *)keyPtr;
  *(_DWORD *)(this + 972) = v6;
  qmemcpy((void *)(this + 976), v7, v6);
  qmemcpy((void *)(this + 1008), v7, *(_DWORD *)(this + 972));
  v8 = *(_DWORD *)(this + 968);
  if ( v8 == 16 )
  {
    v9 = *(_DWORD *)(this + 972);
    if ( v9 == 16 )
      v10 = 10;
    else
      v10 = v9 != 24 ? 14 : 12;
    *(_DWORD *)(this + 1040) = v10;
  }
  else if ( v8 == 24 )
  {
    *(_DWORD *)(this + 1040) = *(_DWORD *)(this + 972) != 32 ? 12 : 14;
  }
  else
  {
    *(_DWORD *)(this + 1040) = 14;
  }
  v11 = 0;
  v12 = *(_DWORD *)(this + 1040);
  wordsPerKey = *(_DWORD *)(this + 972) / 4;
  keyLen = wordsPerKey;
  if ( v12 >= 0 )
  {
    v14 = (char *)(this + 8);
    do
    {
      if ( wordsPerKey > 0 )
      {
        memset(v14, 0, 4 * wordsPerKey);
        wordsPerKey = keyLen;
      }
      ++v11;
      v14 += 32;
    }
    while ( v11 <= *(_DWORD *)(this + 1040) );
  }
  v15 = 0;
  if ( *(int *)(this + 1040) >= 0 )
  {
    v16 = (char *)(this + 488);
    do
    {
      if ( wordsPerKey > 0 )
      {
        memset(v16, 0, 4 * wordsPerKey);
        wordsPerKey = keyLen;
      }
      ++v15;
      v16 += 32;
    }
    while ( v15 <= *(_DWORD *)(this + 1040) );
  }
  v17 = this + 1044;
  v18 = *(int *)(this + 968);
  v19 = wordsPerKey * (*(_DWORD *)(this + 1040) + 1);
  IVLen = v19;
  v20 = (BYTE4(v18) & 3) + v18;
  v21 = (unsigned __int8 *)IVPtr;
  v22 = v20 >> 2;
  v48 = v22;
  if ( v22 > 0 )
  {
    IVPtr = v22;
    do
    {
      v17 += 4;
      *(_DWORD *)(v17 - 4) = *v21 << 24;
      v23 = v21 + 1;
      *(_DWORD *)(v17 - 4) |= (unsigned __int8)*v23++ << 16;
      LOBYTE(v24) = 0;
      HIBYTE(v24) = *v23;
      *(_DWORD *)(v17 - 4) |= v24;
      *(_DWORD *)(v17 - 4) |= (unsigned __int8)*++v23;
      v21 = v23 + 1;
      --IVPtr;
    }
    while ( IVPtr );
  }
  v25 = 0;
  if ( v22 <= 0 )
  {
LABEL_36:
    if ( v25 < v19 )
    {
      keyPtr = (int)&unk_1000AC3C;
      while ( 1 )
      {
        IVPtr = *(_DWORD *)(this + 4 * v22 + 1040);
        v29 = keyPtr + 1;
        *(_DWORD *)(this + 1044) ^= (unsigned __int8)byte_10007A3C[HIBYTE(IVPtr)] ^ (((unsigned __int8)byte_10007A3C[(unsigned __int8)IVPtr] ^ (((unsigned __int8)byte_10007A3C[BYTE1(IVPtr)] ^ ((*(char *)keyPtr ^ byte_10007A3C[BYTE2(IVPtr)]) << 8)) << 8)) << 8);
        keyPtr = v29;
        if ( v22 == 8 )
        {
          v32 = (_DWORD *)(this + 1048);
          v33 = 3;
          do
          {
            *v32 ^= *(v32 - 1);
            ++v32;
            --v33;
          }
          while ( v33 );
          IVPtr = *(_DWORD *)(this + 1056);
          v34 = 3;
          *(_DWORD *)(this + 1060) ^= (unsigned __int8)byte_10007A3C[(unsigned __int8)IVPtr] ^ (((unsigned __int8)byte_10007A3C[BYTE1(IVPtr)] ^ (((unsigned __int8)byte_10007A3C[BYTE2(IVPtr)] ^ (byte_10007A3C[HIBYTE(IVPtr)] << 8)) << 8)) << 8);
          v35 = (_DWORD *)(this + 1064);
          do
          {
            *v35 ^= *(v35 - 1);
            ++v35;
            --v34;
          }
          while ( v34 );
        }
        else if ( v22 > 1 )
        {
          v30 = (_DWORD *)(this + 1048);
          v31 = v22 - 1;
          do
          {
            *v30 ^= *(v30 - 1);
            ++v30;
            --v31;
          }
          while ( v31 );
        }
        IVPtr = 0;
        if ( v22 > 0 )
          break;
LABEL_51:
        wordsPerKey = keyLen;
        if ( v25 >= IVLen )
          goto LABEL_52;
      }
      v36 = (int *)(this + 1044);
      while ( 1 )
      {
        wordsPerKey = keyLen;
        if ( v25 >= IVLen )
          break;
        v37 = *v36++;
        v38 = v25 / keyLen;
        v39 = v25 % keyLen;
        *(_DWORD *)(this + 4 * (v25 % keyLen + 8 * v38) + 8) = v37;
        v22 = v48;
        v40 = IVPtr + 1;
        ++v25;
        v41 = IVPtr + 1 < v48;
        *(_DWORD *)(this + 4 * (v39 + 8 * (*(_DWORD *)(this + 1040) - v38)) + 488) = *(v36 - 1);
        IVPtr = v40;
        if ( !v41 )
          goto LABEL_51;
      }
    }
  }
  else
  {
    IVPtr = this + 1044;
    while ( v25 < v19 )
    {
      keyPtr = v25 % wordsPerKey;
      *(_DWORD *)(this + 4 * (v25 % wordsPerKey + 8 * (v25 / wordsPerKey)) + 8) = *(_DWORD *)IVPtr;
      v26 = *(_DWORD *)(this + 1040) - v25 / wordsPerKey;
      ++v25;
      v27 = keyPtr + 8 * v26;
      v28 = IVPtr + 4;
      *(_DWORD *)(this + 4 * v27 + 488) = *(_DWORD *)IVPtr;
      v19 = IVLen;
      IVPtr = v28;
      if ( v25 >= v22 )
        goto LABEL_36;
    }
  }
LABEL_52:
  v42 = *(_DWORD *)(this + 1040);
  result = 1;
  IVLen = 1;
  if ( v42 > 1 )
  {
    v44 = this + 520;
    do
    {
      if ( wordsPerKey > 0 )
      {
        v45 = (int *)v44;
        v46 = wordsPerKey;
        do
        {
          IVPtr = *v45++;
          --v46;
          *(v45 - 1) = dword_1000A83C[(unsigned __int8)IVPtr] ^ dword_1000A43C[BYTE1(IVPtr)] ^ dword_1000A03C[BYTE2(IVPtr)] ^ dword_10009C3C[HIBYTE(IVPtr)];
        }
        while ( v46 );
        wordsPerKey = keyLen;
      }
      v47 = *(_DWORD *)(this + 1040);
      result = IVLen + 1;
      v44 += 32;
      ++IVLen;
    }
    while ( IVLen < v47 );
  }
  *(_BYTE *)(this + 4) = 1;
  return result;
}
