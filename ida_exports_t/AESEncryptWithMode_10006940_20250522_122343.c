// --- Metadata ---
// Function Name: AESEncryptWithMode_10006940
// Address: 0x10006940
// Exported At: 20250522_122343
// Signature: unknown_signature
// ---------------
unsigned int __thiscall AESEncryptWithMode_10006940(int this, int a2, char *a3, unsigned int a4, int a5)
{
  unsigned int v6; // ecx
  unsigned int result; // eax
  char *v9; // ebp
  _BYTE *v10; // eax
  int v11; // edi
  char *v12; // ebp
  char *v13; // eax
  int i; // esi
  unsigned int v15; // ecx
  unsigned __int8 *v16; // esi
  char *v17; // ebp
  unsigned int v18; // ecx
  char pExceptionObject[12]; // [esp+10h] [ebp-Ch] BYREF
  unsigned int v20; // [esp+2Ch] [ebp+10h]
  unsigned int v21; // [esp+2Ch] [ebp+10h]

  if ( !*(_BYTE *)(this + 4) )                  // 모드에 따른 AES 분기 처리, CBC, CFB, ECB
  {
    exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  if ( !a4 || (v6 = *(_DWORD *)(this + 972), a4 % v6) )
  {
    exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8D0);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  if ( a5 == 1 )
  {
    result = a4 / v6;
    v20 = 0;
    if ( a4 / v6 )
    {
      v9 = (char *)(this + 1008);
      do
      {
        v10 = (_BYTE *)(this + 1008);
        if ( !*(_BYTE *)(this + 4) )
        {
          exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
          CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
        }
        v11 = 0;
        if ( (int)v6 > 0 )
        {
          do
          {
            *v10 ^= v10[a2 - (_DWORD)v9];
            ++v10;
            ++v11;
          }
          while ( v11 < *(_DWORD *)(this + 972) );
        }
        AESGenericEncryptBlock_10006640(this, (unsigned __int8 *)(this + 1008), a3);
        qmemcpy(v9, a3, *(_DWORD *)(this + 972));
        v6 = *(_DWORD *)(this + 972);
        a2 += v6;
        a3 += v6;
        result = a4 / v6;
        ++v20;
      }
      while ( v20 < a4 / v6 );
    }
  }
  else
  {
    v21 = 0;
    if ( a5 == 2 )
    {
      result = a4 / v6;
      v12 = a3;
      if ( a4 / v6 )
      {
        do
        {
          AESGenericEncryptBlock_10006640(this, (unsigned __int8 *)(this + 1008), v12);
          v13 = v12;
          if ( !*(_BYTE *)(this + 4) )
          {
            exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
            CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
          }
          for ( i = 0; i < *(_DWORD *)(this + 972); ++i )
            *v13++ ^= *(_BYTE *)(i + a2);
          qmemcpy((void *)(this + 1008), v12, *(_DWORD *)(this + 972));
          v15 = *(_DWORD *)(this + 972);
          result = a4 / v15;
          v12 += v15;
          a2 += v15;
          ++v21;
        }
        while ( v21 < a4 / v15 );
      }
    }
    else
    {
      result = a4 / v6;
      v16 = (unsigned __int8 *)a2;
      v17 = a3;
      if ( a4 / v6 )
      {
        do
        {
          AESGenericEncryptBlock_10006640(this, v16, v17);
          v18 = *(_DWORD *)(this + 972);
          v16 += v18;
          v17 += v18;
          ++v21;
          result = a4 / v18;
        }
        while ( v21 < a4 / v18 );
      }
    }
  }
  return result;
}
