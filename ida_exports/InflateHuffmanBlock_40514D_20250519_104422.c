// --- Metadata ---
// Function Name: InflateHuffmanBlock_40514D
// Address: 0x40514D
// Exported At: 20250519_104422
// Signature: unknown_signature
// ---------------
int __cdecl InflateHuffmanBlock_40514D(int a1, int a2, int a3, int a4, _DWORD *a5, _DWORD *a6)
{
  _DWORD *v6; // esi zlib 또는 DEFLATE 알고리즘에서의 inflate 단계 
  _BYTE *v8; // ecx 동적 허프만 블록을 해석하여 실제 데이터를 복원하는 로직 
  unsigned int j; // edx
  unsigned int v10; // eax
  int v11; // eax
  unsigned __int8 *v12; // eax
  bool i; // zf
  unsigned __int8 v14; // cl
  int v15; // esi
  unsigned int v16; // edx
  int v17; // ebx
  int v18; // eax
  int v19; // ecx
  int v20; // ecx
  unsigned int v21; // ebx
  int v22; // esi
  _BYTE *v23; // ecx
  _BYTE *v24; // eax
  unsigned int v25; // esi
  int v26; // esi
  _BYTE *v27; // esi
  _BYTE *v28; // eax
  _BYTE *v29; // eax
  _BYTE *v30; // ecx
  unsigned int v31; // ecx
  int result; // eax
  unsigned __int8 *v33; // edx
  int v34; // [esp-4h] [ebp-28h]
  int v35; // [esp+Ch] [ebp-18h]
  int v36; // [esp+10h] [ebp-14h]
  unsigned int v37; // [esp+14h] [ebp-10h]
  _BYTE *v38; // [esp+18h] [ebp-Ch]
  unsigned __int8 *v39; // [esp+1Ch] [ebp-8h]
  unsigned __int8 *v40; // [esp+1Ch] [ebp-8h]
  unsigned int v41; // [esp+20h] [ebp-4h]
  int v42; // [esp+2Ch] [ebp+8h]
  unsigned int v43; // [esp+2Ch] [ebp+8h]
  int v44; // [esp+2Ch] [ebp+8h]
  unsigned int v45; // [esp+2Ch] [ebp+8h]
  unsigned int v46; // [esp+2Ch] [ebp+8h]
  int v47; // [esp+30h] [ebp+Ch]
  unsigned int v48; // [esp+40h] [ebp+1Ch]
  unsigned int v49; // [esp+40h] [ebp+1Ch]

  v6 = a5;
  v8 = a5[13];
  j = a5[7];
  v38 = v8;
  v39 = *a6;
  v41 = a6[1];
  v48 = a5[8];
  v10 = a5[12];
  if ( v8 >= v10 )
    v11 = a5[11] - v8;
  else
    v11 = v10 - v8 - 1;
  v37 = v11;
  v36 = dword_40BCA8[a1];
  v47 = dword_40BCA8[a2];
LABEL_5:
  while ( j < 0x14 )
  {
    --v41;
    v48 |= *v39++ << j;
    j += 8;
  }
  v12 = (a3 + 8 * (v48 & v36));
  v42 = *v12;
  for ( i = v42 == 0; ; i = v42 == 0 )
  {
    v14 = v12[1];
    if ( i )
    {
      v48 >>= v14;
      j -= v12[1];
      v30 = v38++;
      --v37;
      *v30 = v12[4];
LABEL_38:
      if ( v37 < 0x102 || v41 < 0xA )
      {
        v31 = a6[1] - v41;
        if ( j >> 3 < v31 )
          v31 = j >> 3;
        result = 0;
        goto LABEL_55;
      }
      goto LABEL_5;
    }
    v48 >>= v14;
    j -= v12[1];
    if ( (v42 & 0x10) != 0 )
      break;
    if ( (v42 & 0x40) != 0 )
    {
      if ( (v42 & 0x20) != 0 )
      {
        v31 = a6[1] - v41;
        if ( j >> 3 < v31 )
          v31 = j >> 3;
        v34 = 1;
      }
      else
      {
        v31 = a6[1] - v41;
        a6[6] = "invalid literal/length code";
        if ( j >> 3 < v31 )
          v31 = j >> 3;
        v34 = -3;
      }
      result = v34;
      goto LABEL_55;
    }
    v12 += 8 * *(v12 + 1) + 8 * (v48 & dword_40BCA8[v42]);
    v42 = *v12;
  }
  v15 = v48 & dword_40BCA8[v42 & 0xF];
  v49 = v48 >> (v42 & 0xF);
  v16 = j - (v42 & 0xF);
  v43 = *(v12 + 1) + v15;
  while ( v16 < 0xF )
  {
    --v41;
    v49 |= *v39++ << v16;
    v16 += 8;
  }
  v17 = *(a4 + 8 * (v49 & v47));
  v18 = a4 + 8 * (v49 & v47);
  v48 = v49 >> *(v18 + 1);
  for ( j = v16 - *(v18 + 1); ; j -= v20 )
  {
    if ( (v17 & 0x10) != 0 )
    {
      v21 = v17 & 0xF;
      while ( j < v21 )
      {
        --v41;
        v48 |= *v39++ << j;
        j += 8;
      }
      v22 = v48 & dword_40BCA8[v21];
      j -= v21;
      v48 >>= v21;
      v23 = v38;
      v37 -= v43;
      v24 = &v38[-*(v18 + 4) - v22];
      v25 = a5[10];
      if ( v24 >= v25 )
      {
        *v38 = *v24;
        v38[1] = v24[1];
        v23 = v38 + 2;
        v29 = v24 + 2;
        v46 = v43 - 2;
        do
        {
          *v23++ = *v29++;
          --v46;
        }
        while ( v46 );
      }
      else
      {
        v35 = a5[11];
        do
          v24 += v35 - v25;
        while ( v24 < v25 );
        v26 = v35 - v24;
        if ( v43 <= v35 - v24 )
        {
          *v38 = *v24;
          v38[1] = v24[1];
          v23 = v38 + 2;
          v28 = v24 + 2;
          v45 = v43 - 2;
          do
          {
            *v23++ = *v28++;
            --v45;
          }
          while ( v45 );
        }
        else
        {
          v44 = v43 - v26;
          do
          {
            *v23++ = *v24++;
            --v26;
          }
          while ( v26 );
          v27 = a5[10];
          do
          {
            *v23++ = *v27++;
            --v44;
          }
          while ( v44 );
        }
      }
      v6 = a5;
      v38 = v23;
      goto LABEL_38;
    }
    if ( (v17 & 0x40) != 0 )
      break;
    v19 = *(v18 + 4) + (v48 & dword_40BCA8[v17]);
    v17 = *(v18 + 8 * v19);
    v18 += 8 * v19;
    v20 = *(v18 + 1);
    v48 >>= v20;
  }
  v31 = a6[1] - v41;
  a6[6] = "invalid distance code";
  if ( j >> 3 < v31 )
    v31 = j >> 3;
  v6 = a5;
  result = -3;
LABEL_55:
  v40 = &v39[-v31];
  v6[8] = v48;
  v6[7] = j - 8 * v31;
  a6[1] = v41 + v31;
  v33 = &v40[-*a6];
  *a6 = v40;
  a6[2] += v33;
  v6[13] = v38;
  return result;
}
