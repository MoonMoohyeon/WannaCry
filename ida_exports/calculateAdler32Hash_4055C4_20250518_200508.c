// --- Metadata ---
// Function Name: calculateAdler32Hash_4055C4
// Address: 0x4055C4
// Exported At: 20250518_200508
// Signature: unknown_signature
// ---------------
unsigned int __cdecl calculateAdler32Hash_4055C4(unsigned int adler, unsigned __int8 *data, unsigned int len)
{
  unsigned __int8 *v3; // ecx
  unsigned int v4; // esi
  unsigned int v5; // edi
  unsigned int v7; // edx
  unsigned int v8; // eax
  int v9; // esi
  int v10; // edi
  int v11; // esi
  int v12; // edi
  int v13; // esi
  int v14; // edi
  int v15; // esi
  int v16; // edi
  int v17; // esi
  int v18; // edi
  int v19; // esi
  int v20; // edi
  int v21; // esi
  int v22; // edi
  int v23; // esi
  int v24; // edi
  int v25; // esi
  int v26; // edi
  int v27; // esi
  int v28; // edi
  int v29; // esi
  int v30; // edi
  int v31; // esi
  int v32; // edi
  int v33; // esi
  int v34; // edi
  int v35; // esi
  int v36; // edi
  int v37; // esi
  int v38; // edi

  v3 = data;
  v4 = adler;
  v5 = HIWORD(adler);
  if ( !data )
    return 1;
  for ( ; len; v5 %= 0xFFF1u )                  // Adler32 해시를 계산 - 널리 쓰이는 zlib 압축 라이브러리의 일부
  {
    v7 = 5552;
    if ( len < 0x15B0 )
      v7 = len;
    len -= v7;
    if ( v7 >= 16 )
    {
      v8 = v7 >> 4;
      v7 += -16 * (v7 >> 4);
      do
      {
        v9 = *v3 + v4;
        v10 = v9 + v5;
        v11 = v3[1] + v9;
        v12 = v11 + v10;
        v13 = v3[2] + v11;
        v14 = v13 + v12;
        v15 = v3[3] + v13;
        v16 = v15 + v14;
        v17 = v3[4] + v15;
        v18 = v17 + v16;
        v19 = v3[5] + v17;
        v20 = v19 + v18;
        v21 = v3[6] + v19;
        v22 = v21 + v20;
        v23 = v3[7] + v21;
        v24 = v23 + v22;
        v25 = v3[8] + v23;
        v26 = v25 + v24;
        v27 = v3[9] + v25;
        v28 = v27 + v26;
        v29 = v3[10] + v27;
        v30 = v29 + v28;
        v31 = v3[11] + v29;
        v32 = v31 + v30;
        v33 = v3[12] + v31;
        v34 = v33 + v32;
        v35 = v3[13] + v33;
        v36 = v35 + v34;
        v37 = v3[14] + v35;
        v38 = v37 + v36;
        v4 = v3[15] + v37;
        v5 = v4 + v38;
        v3 += 16;
        --v8;
      }
      while ( v8 );
    }
    for ( ; v7; --v7 )
    {
      v4 += *v3++;
      v5 += v4;
    }
    v4 %= 0xFFF1u;
  }
  return v4 | (v5 << 16);
}
