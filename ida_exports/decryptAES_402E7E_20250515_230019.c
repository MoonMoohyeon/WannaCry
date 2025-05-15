// --- Metadata ---
// Function Name: decryptAES_402E7E
// Address: 0x402E7E
// Exported At: 20250515_230019
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall decryptAES_402E7E(_BYTE *this, unsigned __int8 *a2, _BYTE *a3)
{
  _DWORD *v3; // edi
  unsigned __int16 v4; // bx
  unsigned __int16 v5; // cx
  int v6; // edx
  int v7; // ecx
  int v8; // esi
  int v9; // esi
  int v10; // esi
  int v11; // ecx
  int v12; // ecx
  int v13; // ebx
  int v14; // esi
  int v15; // esi
  int v16; // eax
  int v17; // edi
  int v18; // eax
  _DWORD *v19; // edx
  int v20; // eax
  int v21; // edx
  int v22; // ecx
  int v23; // eax
  int v24; // edx
  int v25; // edx
  int v26; // edx
  bool v27; // zf
  int v28; // eax
  int v29; // edx
  _DWORD *v30; // edi
  _BYTE *result; // eax
  int v32; // ebx
  int v33; // edx
  int v34; // ebx
  int v35; // edx
  int v36; // edi
  char pExceptionObject[12]; // [esp+4h] [ebp-28h] BYREF
  _BYTE *v38; // [esp+10h] [ebp-1Ch]
  int v39; // [esp+14h] [ebp-18h]
  int v40; // [esp+18h] [ebp-14h]
  int v41; // [esp+1Ch] [ebp-10h]
  int v42; // [esp+20h] [ebp-Ch]
  int v43; // [esp+24h] [ebp-8h]
  int v44; // [esp+28h] [ebp-4h]
  _DWORD *v45; // [esp+34h] [ebp+8h]

  v3 = this;
  v38 = this;
  if ( !this[4] )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  LOBYTE(v4) = 0;
  LOBYTE(v5) = 0;
  HIBYTE(v5) = a2[2];
  v6 = v3[2] ^ (a2[3] | v5 | (a2[1] << 16) | (*a2 << 24));
  v7 = a2[5];
  v8 = a2[4] << 24;
  v41 = v6;
  v9 = (v7 << 16) | v8;
  LOBYTE(v7) = 0;
  BYTE1(v7) = a2[6];
  v10 = v3[3] ^ (a2[7] | v7 | v9);
  v11 = a2[8] << 24;
  v42 = v10;
  HIBYTE(v4) = a2[10];
  v12 = v3[4] ^ (a2[11] | v4 | (a2[9] << 16) | v11);
  v13 = a2[13];
  v14 = a2[12] << 24;
  v40 = v12;
  v15 = (v13 << 16) | v14;
  BYTE1(v13) = a2[14];
  LOBYTE(v13) = a2[15];
  v16 = v3[260];
  v39 = v16;
  v43 = v3[5] ^ (v15 | v13);
  if ( v16 > 1 )
  {
    v45 = v3 + 12;
    v44 = v16 - 1;
    do
    {
      v17 = *(v45 - 1) ^ dword_4097FC[v6] ^ dword_408BFC[HIBYTE(v42)] ^ dword_408FFC[BYTE2(v40)] ^ dword_4093FC[BYTE1(v43)];
      v18 = dword_4097FC[v42] ^ dword_4093FC[BYTE1(v6)] ^ dword_408BFC[HIBYTE(v40)] ^ dword_408FFC[BYTE2(v43)];
      v19 = v45;
      v45 += 8;
      v40 = *v19 ^ v18;
      v20 = dword_4097FC[v12] ^ dword_408FFC[BYTE2(v41)] ^ dword_4093FC[BYTE1(v42)] ^ dword_408BFC[HIBYTE(v43)];
      v21 = BYTE1(v12);
      v22 = BYTE2(v42);
      v23 = *(v45 - 7) ^ v20;
      v24 = dword_4093FC[v21];
      v42 = v17;
      v25 = dword_408BFC[HIBYTE(v41)] ^ dword_408FFC[v22] ^ v24;
      v12 = v43;
      v43 = v23;
      v26 = dword_4097FC[v12] ^ v25;
      LOWORD(v12) = v40;
      v6 = *(v45 - 10) ^ v26;
      v27 = v44-- == 1;
      v41 = v6;
    }
    while ( !v27 );
    v16 = v39;
    v3 = v38;
  }
  v28 = 8 * v16;
  v29 = v3[v28 + 2];
  v30 = &v3[v28 + 2];
  v44 = v29;
  result = a3;
  *a3 = HIBYTE(v29) ^ byte_4089FC[HIBYTE(v41)];
  a3[1] = BYTE2(v29) ^ byte_4089FC[BYTE2(v42)];
  a3[2] = BYTE1(v44) ^ byte_4089FC[BYTE1(v12)];
  v32 = HIBYTE(v42);
  a3[3] = v44 ^ byte_4089FC[v43];
  LOBYTE(v32) = byte_4089FC[v32];
  v44 = v30[1];
  v33 = BYTE2(v40);
  a3[4] = HIBYTE(v44) ^ v32;
  BYTE1(v32) = BYTE1(v44);
  a3[5] = BYTE2(v44) ^ byte_4089FC[v33];
  a3[6] = BYTE1(v32) ^ byte_4089FC[BYTE1(v43)];
  v34 = HIBYTE(v40);
  a3[7] = v44 ^ byte_4089FC[v41];
  LOBYTE(v34) = byte_4089FC[v34];
  v44 = v30[2];
  v35 = BYTE2(v43);
  a3[8] = HIBYTE(v44) ^ v34;
  BYTE1(v34) = BYTE1(v44);
  a3[9] = BYTE2(v44) ^ byte_4089FC[v35];
  a3[10] = BYTE1(v34) ^ byte_4089FC[BYTE1(v41)];
  a3[11] = v44 ^ byte_4089FC[v42];
  v36 = v30[3];
  v44 = v36;
  a3[12] = HIBYTE(v36) ^ byte_4089FC[HIBYTE(v43)];
  a3[13] = BYTE2(v36) ^ byte_4089FC[BYTE2(v41)];
  a3[14] = BYTE1(v36) ^ byte_4089FC[BYTE1(v42)];
  a3[15] = v44 ^ byte_4089FC[v12];
  return result;
}
