// --- Metadata ---
// Function Name: AESDecryptBlock_10006280
// Address: 0x10006280
// Exported At: 20250522_101728
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall AESDecryptBlock_10006280(int this, unsigned __int8 *a2, _BYTE *a3)
{
  _DWORD *v3; // ebp
  int v4; // ebx
  unsigned __int16 v5; // cx
  int v6; // edx
  int v7; // ecx
  int v8; // eax
  int v9; // esi
  _DWORD *v10; // ebp
  int v11; // esi
  int v12; // edi
  int v13; // edx
  int v14; // ecx
  int v15; // ebx
  int v16; // edx
  int v17; // ebx
  bool v18; // zf
  int v19; // esi
  int v20; // edi
  _DWORD *v21; // esi
  _BYTE *result; // eax
  int v23; // [esp+4h] [ebp-24h]
  int v24; // [esp+8h] [ebp-20h]
  int v25; // [esp+Ch] [ebp-1Ch]
  __int16 v26; // [esp+12h] [ebp-16h]
  int v27; // [esp+14h] [ebp-14h]
  char pExceptionObject[12]; // [esp+1Ch] [ebp-Ch] BYREF
  int v30; // [esp+2Ch] [ebp+4h]
  unsigned int v31; // [esp+2Ch] [ebp+4h]
  unsigned int v32; // [esp+2Ch] [ebp+4h]
  int v33; // [esp+2Ch] [ebp+4h]

  v3 = (_DWORD *)this;
  if ( !*(_BYTE *)(this + 4) )                  // AES 블록 복호화
  {
    exception::exception((exception *)pExceptionObject, (const char *const *)&off_1000D8CC);
    CxxThrowException(pExceptionObject, (_ThrowInfo *)&_TI1_AVexception__);
  }
  v4 = *(_DWORD *)(this + 8);
  LOBYTE(v5) = 0;
  HIBYTE(v5) = a2[2];
  LOWORD(v6) = v4 ^ (a2[3] | v5);
  v25 = v4 ^ (a2[3] | v5 | (a2[1] << 16) | (*a2 << 24));
  LOBYTE(v5) = 0;
  HIBYTE(v5) = a2[6];
  v24 = v3[3] ^ (a2[7] | v5 | (a2[5] << 16) | (a2[4] << 24));
  LOBYTE(v4) = 0;
  BYTE1(v4) = a2[10];
  v7 = v3[4] ^ (a2[11] | (unsigned __int16)v4 | (a2[9] << 16) | (a2[8] << 24));
  v26 = HIWORD(v7);
  BYTE1(v4) = a2[14];
  LOBYTE(v4) = a2[15];
  v8 = ((a2[13] << 16) | (a2[12] << 24) | (unsigned __int16)v4) ^ v3[5];
  v9 = v3[260];
  v23 = v8;
  v27 = v9;
  if ( v9 > 1 )
  {
    v10 = v3 + 12;
    v30 = v9 - 1;
    do
    {
      v10 += 8;
      v11 = *(v10 - 9) ^ dword_1000883C[(unsigned __int8)v6] ^ dword_10007C3C[HIBYTE(v24)] ^ dword_1000803C[(unsigned __int8)v26] ^ dword_1000843C[BYTE1(v8)];
      v12 = *(v10 - 8) ^ dword_1000883C[(unsigned __int8)v24] ^ dword_1000843C[BYTE1(v6)] ^ dword_10007C3C[HIBYTE(v26)] ^ dword_1000803C[BYTE2(v23)];
      v8 = *(v10 - 7) ^ dword_1000883C[(unsigned __int8)v7] ^ dword_1000803C[BYTE2(v25)] ^ dword_1000843C[BYTE1(v24)] ^ dword_10007C3C[HIBYTE(v23)];
      v13 = BYTE1(v7);
      v14 = BYTE2(v24);
      v24 = v11;
      v15 = dword_1000803C[v14];
      v7 = (unsigned __int8)v23;
      v16 = dword_10007C3C[HIBYTE(v25)] ^ v15 ^ dword_1000843C[v13];
      v23 = v8;
      v17 = dword_1000883C[v7];
      LOWORD(v7) = v12;
      v6 = *(v10 - 10) ^ v17 ^ v16;
      v18 = v30 == 1;
      v25 = v6;
      v26 = HIWORD(v12);
      --v30;
    }
    while ( !v18 );
    v9 = v27;
    v3 = (_DWORD *)this;
  }
  v19 = 8 * v9;
  v20 = v3[v19 + 2];
  v21 = &v3[v19 + 2];
  result = a3;
  *a3 = HIBYTE(v20) ^ byte_10007A3C[HIBYTE(v25)];
  a3[1] = BYTE2(v20) ^ byte_10007A3C[BYTE2(v24)];
  a3[2] = BYTE1(v20) ^ byte_10007A3C[BYTE1(v7)];
  a3[3] = v20 ^ byte_10007A3C[(unsigned __int8)v23];
  v31 = v21[1];
  a3[4] = HIBYTE(v31) ^ byte_10007A3C[HIBYTE(v24)];
  a3[5] = ((unsigned __int16)(v31 >> 8) >> 8) ^ byte_10007A3C[(unsigned __int8)v26];
  a3[6] = BYTE1(v31) ^ byte_10007A3C[BYTE1(v23)];
  a3[7] = v31 ^ byte_10007A3C[(unsigned __int8)v25];
  v32 = v21[2];
  a3[8] = HIBYTE(v32) ^ byte_10007A3C[HIBYTE(v26)];
  a3[9] = ((unsigned __int16)(v32 >> 8) >> 8) ^ byte_10007A3C[BYTE2(v23)];
  a3[10] = BYTE1(v32) ^ byte_10007A3C[BYTE1(v25)];
  a3[11] = v32 ^ byte_10007A3C[(unsigned __int8)v24];
  v33 = v21[3];
  a3[12] = HIBYTE(v33) ^ byte_10007A3C[HIBYTE(v23)];
  a3[13] = BYTE2(v33) ^ byte_10007A3C[BYTE2(v25)];
  a3[14] = BYTE1(v33) ^ byte_10007A3C[BYTE1(v24)];
  a3[15] = v33 ^ byte_10007A3C[(unsigned __int8)v7];
  return result;
}
