// --- Metadata ---
// Function Name: BuildHuffmanDecodingTable_404C19
// Address: 0x404C19
// Exported At: 20250519_104337
// Signature: unknown_signature
// ---------------
int __cdecl BuildHuffmanDecodingTable_404C19(int *symbol_len, unsigned int symbol_num, unsigned int literal_num, int literal_ptr, int len_ptr, _DWORD *output_ptr, unsigned int *maxBit, int decodingTable_ptr, unsigned int *tableSize_counter, unsigned int *output_symbol_order)
{
  int *v10; // ecx
  unsigned int v11; // esi zlib/DEFLATE의 압축 해제를 위한 동적 허프만 트리 테이블을 구성 
  int v12; // eax
  int *v15; // eax
  unsigned int v16; // esi
  unsigned int v17; // ecx
  int *v18; // esi
  unsigned int v19; // eax
  int v20; // ebx
  int *v21; // esi
  int v22; // ebx
  int v23; // esi
  int v24; // edi
  int v25; // ebx
  int v26; // ecx
  unsigned int v27; // eax
  int v28; // edi
  int *v29; // ebx
  unsigned int v30; // edi
  int v31; // eax
  int v32; // ecx
  int v33; // eax
  int v34; // ebx
  int v35; // edi
  bool v36; // zf
  int v37; // eax
  unsigned int v38; // ecx
  unsigned int v39; // eax
  int *v40; // esi
  unsigned int v41; // eax
  unsigned int v42; // edx
  unsigned int v43; // eax
  unsigned int v44; // esi
  int *v45; // edx
  unsigned int v46; // esi
  unsigned int v47; // edi
  unsigned int v48; // eax
  int v49; // ecx
  unsigned int v50; // eax
  unsigned int v51; // eax
  int v52; // esi
  unsigned int v53; // eax
  _DWORD *v54; // ecx
  unsigned int v55; // eax
  unsigned int v56; // ecx
  int *i; // eax
  int v60[15]; // [esp+Ch] [ebp-F0h] BYREF
  int v61; // [esp+48h] [ebp-B4h] BYREF
  int v62[15]; // [esp+4Ch] [ebp-B0h]
  int v63; // [esp+88h] [ebp-74h] BYREF
  int code_len_count[14]; // [esp+8Ch] [ebp-70h] BYREF
  int v65; // [esp+C4h] [ebp-38h] BYREF
  int v66; // [esp+C8h] [ebp-34h]
  int v67; // [esp+CCh] [ebp-30h]
  int v68; // [esp+D0h] [ebp-2Ch]
  int v69; // [esp+D4h] [ebp-28h]
  int v70; // [esp+D8h] [ebp-24h]
  int *v71; // [esp+DCh] [ebp-20h]
  unsigned int v72; // [esp+E0h] [ebp-1Ch]
  int v73; // [esp+E4h] [ebp-18h]
  int v74; // [esp+E8h] [ebp-14h]
  unsigned int *v75; // [esp+ECh] [ebp-10h]
  unsigned int v76; // [esp+F0h] [ebp-Ch]
  int v77; // [esp+F4h] [ebp-8h]
  int v78; // [esp+F8h] [ebp-4h]
  unsigned int symbol_lena; // [esp+104h] [ebp+8h]
  unsigned int symbol_lenb; // [esp+104h] [ebp+8h]
  int symbol_numa; // [esp+108h] [ebp+Ch]
  unsigned int maxBita; // [esp+11Ch] [ebp+20h]

  v10 = symbol_len;
  v63 = 0;
  code_len_count[0] = 0;
  code_len_count[1] = 0;
  code_len_count[2] = 0;
  code_len_count[3] = 0;
  code_len_count[4] = 0;
  code_len_count[5] = 0;
  code_len_count[6] = 0;
  code_len_count[7] = 0;
  code_len_count[8] = 0;
  code_len_count[9] = 0;
  code_len_count[10] = 0;
  code_len_count[11] = 0;
  code_len_count[12] = 0;
  code_len_count[13] = 0;
  v65 = 0;
  v11 = symbol_num;
  do
  {
    v12 = *v10++;
    ++*(&v63 + v12);
    --v11;
  }
  while ( v11 );
  if ( v63 == symbol_num )
  {
    *output_ptr = 0;
    *maxBit = 0;
    return 0;
  }
  v15 = code_len_count;
  v16 = *maxBit;
  v17 = 1;
  maxBita = *maxBit;
  do
  {
    if ( *v15 )
      break;
    ++v17;
    ++v15;
  }
  while ( v17 <= 0xF );
  v78 = v17;
  if ( v16 < v17 )
    maxBita = v17;
  v18 = &v65;
  v19 = 15;
  do
  {
    if ( *v18 )
      break;
    --v19;
    --v18;
  }
  while ( v19 );
  v73 = v19;
  if ( maxBita > v19 )
    maxBita = v19;
  v20 = 1 << v17;
  *maxBit = maxBita;
  if ( v17 < v19 )
  {
    v21 = &v63 + v17;
    do
    {
      v22 = v20 - *v21;
      if ( v22 < 0 )
        return -3;
      ++v17;
      ++v21;
      v20 = 2 * v22;
    }
    while ( v17 < v19 );
  }
  v23 = 4 * v19;
  v24 = *(&v63 + v19);
  v25 = v20 - v24;
  v67 = v25;
  if ( v25 < 0 )
    return -3;
  v62[0] = 0;
  *(&v63 + v19) = v25 + v24;
  v26 = 0;
  v27 = v19 - 1;
  if ( v27 )
  {
    v28 = 0;
    do
    {
      v26 += code_len_count[v28++];
      --v27;
      v62[v28] = v26;
    }
    while ( v27 );
  }
  v29 = symbol_len;
  v30 = 0;
  do
  {
    v31 = *v29++;
    if ( v31 )
    {
      v32 = *(&v61 + v31);
      output_symbol_order[v32] = v30;
      *(&v61 + v31) = v32 + 1;
    }
    ++v30;
  }
  while ( v30 < symbol_num );
  v33 = *(&v61 + v23);
  v77 = -1;
  symbol_numa = v33;
  v76 = 0;
  v75 = output_symbol_order;
  v34 = -maxBita;
  v61 = 0;
  v60[0] = 0;
  v72 = 0;
  symbol_lena = 0;
  if ( v78 <= v73 )
  {
    v35 = v70;
    v68 = v78 - 1;
    v71 = &v63 + v78;
    while ( 1 )
    {
      v36 = *v71 == 0;
      v74 = *v71 - 1;
      if ( !v36 )
        break;
LABEL_61:
      ++v78;
      ++v71;
      ++v68;
      if ( v78 > v73 )
        goto LABEL_62;
    }
    while ( 1 )
    {
      v37 = v34 + maxBita;
      if ( v78 > (v34 + maxBita) )
        break;
LABEL_45:
      BYTE1(v69) = v78 - v34;
      if ( v75 < &output_symbol_order[symbol_numa] )
      {
        v50 = *v75;
        if ( *v75 >= literal_num )
        {
          v51 = 4 * (v50 - literal_num);
          LOBYTE(v69) = *(v51 + len_ptr) + 80;
          v35 = *(v51 + literal_ptr);
        }
        else
        {
          v35 = *v75;
          LOBYTE(v69) = v50 < 0x100 ? 0 : 96;
        }
        ++v75;
      }
      else
      {
        LOBYTE(v69) = -64;
      }
      v52 = 1 << (v78 - v34);
      v53 = v76 >> v34;
      if ( v76 >> v34 < symbol_lena )
      {
        v54 = (v72 + 8 * v53);
        do
        {
          v53 += v52;
          *v54 = v69;
          v54[1] = v35;
          v54 += 2 * v52;
        }
        while ( v53 < symbol_lena );
      }
      v55 = 1 << v68;
      v56 = v76;
      while ( (v55 & v56) != 0 )
      {
        v56 ^= v55;
        v55 >>= 1;
      }
      v76 = v55 ^ v56;
      for ( i = &v61 + v77; (v76 & ((1 << v34) - 1)) != *i; --i )
      {
        --v77;
        v34 -= maxBita;
      }
      if ( !v74-- )
        goto LABEL_61;
    }
    while ( 1 )
    {
      ++v77;
      v34 += maxBita;
      v66 = maxBita + v37;
      symbol_lenb = v73 - v34;
      if ( v73 - v34 > maxBita )
        symbol_lenb = maxBita;
      v38 = v78 - v34;
      v39 = 1 << (v78 - v34);
      if ( v39 > v74 + 1 )
      {
        v40 = v71;
        v41 = -1 - v74 + v39;
        if ( v38 < symbol_lenb )
        {
          while ( ++v38 < symbol_lenb )
          {
            v42 = v40[1];
            ++v40;
            v43 = 2 * v41;
            if ( v43 <= v42 )
              break;
            v41 = v43 - v42;
          }
        }
      }
      symbol_lena = 1 << v38;
      v44 = *tableSize_counter + (1 << v38);
      if ( v44 > 0x5A0 )
        return -3;
      v72 = decodingTable_ptr + 8 * *tableSize_counter;
      v45 = &v60[v77];
      *v45 = v72;
      *tableSize_counter = v44;
      if ( v77 )
      {
        v46 = v76;
        v47 = v72;
        *(&v61 + v77) = v76;
        LOBYTE(v69) = v38;
        BYTE1(v69) = maxBita;
        v48 = v46 >> (v34 - maxBita);
        v49 = *(v45 - 1);
        v35 = ((v47 - v49) >> 3) - v48;
        *(v49 + 8 * v48) = v69;
        *(v49 + 8 * v48 + 4) = v35;
      }
      else
      {
        *output_ptr = v72;
      }
      v37 = v66;
      if ( v78 <= v66 )
        goto LABEL_45;
    }
  }
LABEL_62:
  if ( !v67 || v73 == 1 )
    return 0;
  return -5;
}
