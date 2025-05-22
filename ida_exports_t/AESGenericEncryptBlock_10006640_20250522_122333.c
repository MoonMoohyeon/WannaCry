// --- Metadata ---
// Function Name: AESGenericEncryptBlock_10006640
// Address: 0x10006640
// Exported At: 20250522_122333
// Signature: unknown_signature
// ---------------
int __thiscall AESGenericEncryptBlock_10006640(int this, unsigned __int8 *a2, _BYTE *a3)
{
  int result; // eax
  int v5; // kr00_4
  int v6; // ebx
  int v7; // eax
  int v8; // eax
  int v9; // edx
  int v10; // ecx
  int *v11; // eax
  unsigned __int8 *v12; // esi
  unsigned __int8 *v13; // esi
  int v14; // edi
  unsigned __int16 v15; // cx
  int *v16; // edi
  bool v17; // zf
  int v18; // esi
  int v19; // eax
  int v20; // ecx
  int v21; // edi
  int v22; // ecx
  bool v23; // cc
  _BYTE *v24; // esi
  int v25; // edi
  int v26; // ecx
  _BYTE *v27; // esi
  _DWORD *v28; // [esp+10h] [ebp-30h]
  int v29; // [esp+10h] [ebp-30h]
  int v30; // [esp+14h] [ebp-2Ch]
  int v31; // [esp+18h] [ebp-28h]
  _DWORD *v32; // [esp+18h] [ebp-28h]
  int v33; // [esp+1Ch] [ebp-24h]
  int v34; // [esp+20h] [ebp-20h]
  int v35; // [esp+28h] [ebp-18h]
  int v36; // [esp+2Ch] [ebp-14h]
  int v37; // [esp+30h] [ebp-10h]
  int v38; // [esp+30h] [ebp-10h]
  char pExceptionObject[12]; // [esp+34h] [ebp-Ch] BYREF
  int v40; // [esp+44h] [ebp+4h]
  int v41; // [esp+44h] [ebp+4h]
  int v42; // [esp+48h] [ebp+8h]

  if ( !*(_BYTE *)(this + 4) )                  // 블록 크기에 따른 복호화 분기 처리 
  {
    exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  if ( *(_DWORD *)(this + 972) == 16 )
    return (int)AESEncryptBlock_10006280(this, a2, a3);
  v5 = *(_DWORD *)(this + 972);
  v6 = v5 / 4;
  if ( v5 / 4 == 4 )
    v7 = 0;
  else
    v7 = (v6 != 6) + 1;
  v8 = 8 * v7;
  v9 = dword_1000AC64[v8];
  v10 = dword_1000AC6C[v8];
  v37 = v9;
  v34 = dword_1000AC74[v8];
  v30 = v10;
  v11 = (int *)(this + 1108);
  if ( v6 > 0 )
  {
    v12 = a2;
    v28 = (_DWORD *)(this + 8);
    v31 = v5 / 4;
    do
    {
      *v11 = *v12 << 24;
      v13 = v12 + 1;
      v14 = (*v13++ << 16) | *v11;
      LOBYTE(v15) = 0;
      *v11 = v14;
      HIBYTE(v15) = *v13++;
      *v11 = v15 | v14;
      v16 = v11;
      *v11 |= *v13;
      v12 = v13 + 1;
      ++v11;
      *v16 ^= *v28;
      v17 = v31 == 1;
      ++v28;
      --v31;
    }
    while ( !v17 );
    v10 = v30;
  }
  result = 1;
  v33 = 1;
  if ( *(int *)(this + 1040) > 1 )
  {
    v40 = this + 40;
    do
    {
      if ( v6 > 0 )
      {
        v18 = v9;
        v32 = (_DWORD *)v40;
        v19 = v10 - v9;
        v20 = v34 - v9;
        v21 = this + 1076;
        v35 = v19;
        v29 = v5 / 4;
        while ( 1 )
        {
          v21 += 4;
          v22 = *v32++ ^ dword_10007C3C[*(unsigned __int8 *)(v21 + 31)] ^ dword_1000803C[*(unsigned __int8 *)(this + 4 * (v18 % v6) + 1110)] ^ dword_1000883C[(unsigned __int8)*(_DWORD *)(this + 4 * ((v20 + v18) % v6) + 1108)] ^ dword_1000843C[*(unsigned __int8 *)(this + 4 * ((v18 + v19) % v6) + 1109)];
          *(_DWORD *)(v21 - 4) = v22;
          ++v18;
          if ( !--v29 )
            break;
          v20 = v34 - v9;
          v19 = v35;
        }
        v9 = v37;
      }
      qmemcpy((void *)(this + 1108), (const void *)(this + 1076), 4 * v6);
      result = v33 + 1;
      v23 = v33 + 1 < *(_DWORD *)(this + 1040);
      v10 = v30;
      ++v33;
      v40 += 32;
    }
    while ( v23 );
  }
  v41 = 0;
  if ( v6 > 0 )
  {
    v24 = a3;
    v42 = this + 1108;
    v25 = v10;
    v38 = v9 - v10;
    v36 = v34 - v10;
    do
    {
      v26 = *(_DWORD *)(this + 4 * (v41 + 8 * *(_DWORD *)(this + 1040)) + 8);
      *v24 = HIBYTE(v26) ^ byte_10007A3C[*(unsigned __int8 *)(v42 + 3)];
      v27 = v24 + 1;
      *v27++ = BYTE2(v26) ^ byte_10007A3C[*(unsigned __int8 *)(this + 4 * ((v38 + v25) % v6) + 1110)];
      *v27++ = BYTE1(v26) ^ byte_10007A3C[*(unsigned __int8 *)(this + 4 * (v25 % v6) + 1109)];
      *v27 = v26 ^ byte_10007A3C[(unsigned __int8)*(_DWORD *)(this + 4 * ((v36 + v25) % v6) + 1108)];
      v24 = v27 + 1;
      result = v41 + 1;
      ++v25;
      v41 = result;
      v42 += 4;
    }
    while ( result < v6 );
  }
  return result;
}
