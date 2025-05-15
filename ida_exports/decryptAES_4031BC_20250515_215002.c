// --- Metadata ---
// Function Name: decryptAES_4031BC
// Address: 0x4031BC
// Exported At: 20250515_215002
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall sub_4031BC(int this, unsigned __int8 *inputBlock, _BYTE *outputBlock)
{
  _DWORD *v3; // edi
  unsigned __int16 v4; // dx
  int v5; // ecx
  int v6; // edx
  int v7; // esi
  int v8; // esi
  int v9; // esi
  int v10; // edx
  int v11; // esi
  int v12; // esi
  int v13; // edx
  int v14; // esi
  int v15; // eax
  _DWORD *v16; // edx
  int v17; // edi
  int v18; // eax
  int v19; // edx
  int v20; // ecx
  int v21; // ecx
  int v22; // ecx
  int v23; // edx
  bool v24; // zf
  int v25; // eax
  int v26; // edx
  _DWORD *v27; // edi
  _BYTE *result; // eax
  char v29; // bl
  int v30; // edx
  int v31; // ebx
  int v32; // edx
  int v33; // ebx
  int v34; // edx
  int v35; // edi
  char pExceptionObject[12]; // [esp+4h] [ebp-2Ch] BYREF
  int v37; // [esp+10h] [ebp-20h]
  _DWORD *v38; // [esp+14h] [ebp-1Ch]
  int v39; // [esp+18h] [ebp-18h]
  int v40; // [esp+1Ch] [ebp-14h]
  int v41; // [esp+20h] [ebp-10h]
  int v42; // [esp+24h] [ebp-Ch]
  int v43; // [esp+28h] [ebp-8h]
  int v44; // [esp+2Ch] [ebp-4h]
  _DWORD *inputBlocka; // [esp+38h] [ebp+8h]

  v3 = this;
  v38 = this;
  if ( !*(this + 4) )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  LOBYTE(v4) = 0;
  HIBYTE(v4) = inputBlock[2];
  v5 = *(this + 488) ^ (inputBlock[3] | v4 | (inputBlock[1] << 16) | (*inputBlock << 24));
  v6 = inputBlock[5];
  v7 = inputBlock[4] << 24;
  v40 = v5;
  v8 = (v6 << 16) | v7;
  LOBYTE(v6) = 0;
  BYTE1(v6) = inputBlock[6];
  v9 = v3[123] ^ (inputBlock[7] | v6 | v8);
  v10 = inputBlock[9];
  v41 = v9;
  v11 = (v10 << 16) | (inputBlock[8] << 24);
  LOBYTE(v10) = 0;
  BYTE1(v10) = inputBlock[10];
  v12 = v3[124] ^ (inputBlock[11] | v10 | v11);
  v13 = inputBlock[13];
  v42 = v12;
  v14 = (v13 << 16) | (inputBlock[12] << 24);
  BYTE1(v13) = inputBlock[14];
  LOBYTE(v13) = inputBlock[15];
  v15 = v3[260];
  v37 = v15;
  v43 = v3[125] ^ (v14 | v13);
  if ( v15 > 1 )
  {
    v16 = v3 + 132;
    inputBlocka = v3 + 132;
    v44 = v15 - 1;
    do
    {
      v17 = *(v16 - 1) ^ dword_40A7FC[v42] ^ dword_409FFC[BYTE2(v40)] ^ dword_409BFC[HIBYTE(v41)] ^ dword_40A3FC[BYTE1(v43)];
      v18 = *v16 ^ dword_40A7FC[v43] ^ dword_40A3FC[BYTE1(v5)] ^ dword_409FFC[BYTE2(v41)] ^ dword_409BFC[HIBYTE(v42)];
      v39 = inputBlocka[1] ^ dword_40A7FC[v5] ^ dword_40A3FC[BYTE1(v41)] ^ dword_409FFC[BYTE2(v42)] ^ dword_409BFC[HIBYTE(v43)];
      v19 = BYTE1(v42);
      v20 = dword_409FFC[BYTE2(v43)];
      v42 = v18;
      v21 = dword_40A3FC[v19] ^ v20;
      v43 = v39;
      v22 = dword_409BFC[HIBYTE(v40)] ^ v21;
      v23 = v41;
      v41 = v17;
      v5 = *(inputBlocka - 2) ^ dword_40A7FC[v23] ^ v22;
      v16 = inputBlocka + 8;
      v24 = v44-- == 1;
      inputBlocka += 8;
      v40 = v5;
    }
    while ( !v24 );
    v3 = v38;
    v15 = v37;
  }
  v25 = 8 * v15;
  v26 = v3[v25 + 122];
  v27 = &v3[v25 + 122];
  v44 = v26;
  result = outputBlock;
  *outputBlock = HIBYTE(v26) ^ byte_408AFC[HIBYTE(v40)];
  v29 = BYTE2(v26) ^ byte_408AFC[BYTE2(v43)];
  v30 = BYTE1(v42);
  outputBlock[1] = v29;
  outputBlock[2] = BYTE1(v44) ^ byte_408AFC[v30];
  v31 = HIBYTE(v41);
  outputBlock[3] = v44 ^ byte_408AFC[v41];
  LOBYTE(v31) = byte_408AFC[v31];
  v44 = v27[1];
  v32 = BYTE2(v40);
  outputBlock[4] = HIBYTE(v44) ^ v31;
  BYTE1(v31) = BYTE1(v44);
  outputBlock[5] = BYTE2(v44) ^ byte_408AFC[v32];
  outputBlock[6] = BYTE1(v31) ^ byte_408AFC[BYTE1(v43)];
  v33 = HIBYTE(v42);
  outputBlock[7] = v44 ^ byte_408AFC[v42];
  LOBYTE(v33) = byte_408AFC[v33];
  v44 = v27[2];
  v34 = BYTE2(v41);
  outputBlock[8] = HIBYTE(v44) ^ v33;
  BYTE1(v33) = BYTE1(v44);
  outputBlock[9] = BYTE2(v44) ^ byte_408AFC[v34];
  outputBlock[10] = BYTE1(v33) ^ byte_408AFC[BYTE1(v5)];
  outputBlock[11] = v44 ^ byte_408AFC[v43];
  v35 = v27[3];
  v44 = v35;
  outputBlock[12] = HIBYTE(v35) ^ byte_408AFC[HIBYTE(v43)];
  outputBlock[13] = BYTE2(v35) ^ byte_408AFC[BYTE2(v42)];
  outputBlock[14] = BYTE1(v35) ^ byte_408AFC[BYTE1(v41)];
  outputBlock[15] = v44 ^ byte_408AFC[v5];
  return result;
}
