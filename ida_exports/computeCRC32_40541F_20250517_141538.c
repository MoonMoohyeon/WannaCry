// --- Metadata ---
// Function Name: computeCRC32_40541F
// Address: 0x40541F
// Exported At: 20250517_141538
// Signature: unknown_signature
// ---------------
unsigned int __cdecl computeCRC32_40541F(int a1, unsigned __int8 *a2, unsigned int a3)
{
  unsigned __int8 *v3; // edx
  unsigned int v5; // eax
  unsigned int v6; // edi
  unsigned int v7; // eax
  unsigned __int8 *v8; // edx
  int v9; // ebx
  unsigned int v10; // esi
  int v11; // eax
  int v12; // ebx
  unsigned int v13; // eax
  int v14; // esi
  int v15; // ebx
  unsigned int v16; // esi
  int v17; // eax
  int v18; // ebx
  unsigned int v19; // eax
  int v20; // esi
  int v21; // ebx
  unsigned int v22; // esi
  unsigned int v23; // eax

  v3 = a2;
  if ( !a2 )
    return 0;
  v5 = ~a1;
  if ( a3 >= 8 )                                // 계산된 CRC-32 체크섬 반환 
  {
    v6 = a3 >> 3;
    do
    {
      a3 -= 8;
      v7 = (v5 >> 8) ^ dword_40D054[*v3 ^ v5];
      v8 = v3 + 1;
      v9 = v8[1];
      v10 = (v7 >> 8) ^ dword_40D054[*v8++ ^ v7];
      v11 = v9 ^ v10;
      v12 = v8[1];
      v13 = (v10 >> 8) ^ dword_40D054[v11];
      ++v8;
      v14 = v12 ^ v13;
      v15 = v8[1];
      v16 = (v13 >> 8) ^ dword_40D054[v14];
      ++v8;
      v17 = v15 ^ v16;
      v18 = v8[1];
      v19 = (v16 >> 8) ^ dword_40D054[v17];
      ++v8;
      v20 = v18 ^ v19;
      v21 = v8[1];
      v22 = (v19 >> 8) ^ dword_40D054[v20];
      ++v8;
      v23 = (v22 >> 8) ^ dword_40D054[v21 ^ v22];
      v5 = dword_40D054[v8[1] ^ v23] ^ (v23 >> 8);
      v3 = v8 + 2;
      --v6;
    }
    while ( v6 );
  }
  for ( ; a3; --a3 )
    v5 = dword_40D054[*v3++ ^ v5] ^ (v5 >> 8);
  return ~v5;
}
