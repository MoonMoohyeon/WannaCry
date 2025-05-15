// --- Metadata ---
// Function Name: AES_BlockTransform_encrypt_403797
// Address: 0x403797
// Exported At: 20250515_225946
// Signature: unknown_signature
// ---------------
unsigned __int8 __thiscall AES_BlockTransform_encrypt_403797(int this, unsigned __int8 *inputBlock, _BYTE *outputBlock)
{
  int keylength; // eax
  unsigned __int8 result; // al
  int v6; // edi
  int v7; // eax
  int v8; // ecx
  int v9; // eax
  int *v10; // eax
  unsigned __int8 *v11; // ecx
  int v12; // edx
  _BYTE *v13; // ecx
  int *v14; // edx
  _DWORD *v15; // ebx
  bool v16; // cc
  int v17; // ecx
  int v18; // ebx
  _DWORD *v19; // eax
  _BYTE *v20; // ecx
  int v21; // ebx
  int v22; // edx
  _BYTE *v23; // ecx
  char pExceptionObject[12]; // [esp+Ch] [ebp-34h] BYREF
  int v25; // [esp+18h] [ebp-28h]
  int v26; // [esp+1Ch] [ebp-24h]
  int v27; // [esp+20h] [ebp-20h]
  int v28; // [esp+24h] [ebp-1Ch]
  int v29; // [esp+28h] [ebp-18h]
  int v30; // [esp+2Ch] [ebp-14h]
  int v31; // [esp+30h] [ebp-10h]
  int v32; // [esp+34h] [ebp-Ch]
  _DWORD *v33; // [esp+38h] [ebp-8h]
  _DWORD *v34; // [esp+3Ch] [ebp-4h]
  int inputBlocka; // [esp+48h] [ebp+8h]
  int inputBlockb; // [esp+48h] [ebp+8h]
  int outputBlocka; // [esp+4Ch] [ebp+Ch]

  if ( !*(this + 4) )                           // 초기화 
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  keylength = *(this + 972);
  if ( keylength == 16 )
    return encryptAES_4031BC(this, inputBlock, outputBlock);
  v6 = keylength / 4;
  v7 = 8 * (keylength / 4 != 4 ? (keylength / 4 != 6) + 1 : 0);
  v29 = dword_40BC28[v7];
  v8 = dword_40BC30[v7];
  v9 = dword_40BC38[v7];
  v30 = v8;
  v28 = v9;
  v10 = (this + 1108);
  if ( v6 > 0 )
  {
    v32 = v6;
    v34 = (this + 488);
    v11 = inputBlock;
    do
    {
      v12 = *v11 << 24;
      v13 = v11 + 1;
      *v10 = v12;
      *v10 |= *v13++ << 16;
      LOBYTE(v12) = 0;
      BYTE1(v12) = *v13;
      *v10 |= v12;
      ++v13;
      v14 = v10;
      *v10 |= *v13;
      v15 = v34++;
      v11 = v13 + 1;
      ++v10;
      *v14 ^= *v15;
      --v32;
    }
    while ( v32 );
  }
  result = 1;
  v16 = *(this + 1040) <= 1;
  v32 = 1;
  if ( !v16 )
  {
    v33 = (this + 520);
    do
    {
      if ( v6 > 0 )
      {
        v34 = v33;
        inputBlocka = v29;
        v27 = v30 - v29;
        v17 = this + 1076;
        v26 = v28 - v29;
        v31 = v6;
        do
        {
          v25 = *(this + 4 * ((inputBlocka + v27) % v6) + 1109);
          v18 = dword_409BFC[*(v17 + 35)] ^ dword_409FFC[*(this + 4 * (inputBlocka % v6) + 1110)] ^ dword_40A7FC[*(this + 4 * ((inputBlocka + v26) % v6) + 1108)] ^ dword_40A3FC[v25];
          v19 = v34++;
          *v17 = *v19 ^ v18;
          v17 += 4;
          ++inputBlocka;
          --v31;
        }
        while ( v31 );
      }
      memcpy((this + 1108), (this + 1076), 4 * v6);
      v33 += 8;
      result = ++v32;
    }
    while ( v32 < *(this + 1040) );
  }
  v34 = 0;
  if ( v6 > 0 )
  {
    v20 = outputBlock;
    v21 = v30;
    outputBlocka = this + 1108;
    v25 = v29 - v30;
    v26 = v28 - v30;
    do
    {
      v22 = outputBlocka;
      outputBlocka += 4;
      inputBlockb = *(this + 4 * &v34[2 * *(this + 1040)] + 488);
      *v20 = HIBYTE(inputBlockb) ^ byte_408AFC[*(v22 + 3)];
      v23 = v20 + 1;
      *v23++ = BYTE2(inputBlockb) ^ byte_408AFC[*(this + 4 * ((v21 + v25) % v6) + 1110)];
      *v23++ = BYTE1(inputBlockb) ^ byte_408AFC[*(this + 4 * (v21 % v6) + 1109)];
      result = inputBlockb ^ byte_408AFC[*(this + 4 * ((v21 + v26) % v6) + 1108)];
      *v23 = result;
      v20 = v23 + 1;
      v34 = (v34 + 1);
      ++v21;
    }
    while ( v34 < v6 );
  }
  return result;
}
