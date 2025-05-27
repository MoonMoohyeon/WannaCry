// --- Metadata ---
// Function Name: AppendIPRangeToBuffer_408E50
// Address: 0x408E50
// Exported At: 20250527_190652
// Signature: unknown_signature
// ---------------
int __cdecl AppendIPRangeToBuffer_408E50(int a1, u_long hostlong, u_long i)
{
  u_long v3; // esi
  int result; // eax
  u_long v5; // ebp
  u_long v6; // ebx
  u_long v8; // eax
  int v9; // edx
  u_long *v10; // eax
  u_long *v11; // edi
  int v12; // edx
  unsigned int v13; // ecx
  int v14; // eax
  int v15; // eax
  _DWORD *v16; // eax
  u_long *v17; // ebp
  _DWORD *j; // ebx
  int v19; // eax
  int v20; // ecx
  int v21; // [esp+Ch] [ebp-8h]
  u_long v22; // [esp+10h] [ebp-4h]
  int v23; // [esp+18h] [ebp+4h]

  v3 = htonl(hostlong);
  result = htonl(i);
  v5 = result;
  v6 = v3;
  v22 = result;
  for ( i = v3; v6 <= v5; i = v6 )              // IP 범위를 버퍼에 저장 
  {
    result = v6;
    if ( v6 && v6 != 255 )
    {
      v8 = ntohl(v6);
      v9 = *(a1 + 12);
      hostlong = v8;
      v10 = *(a1 + 8);
      v11 = v10;
      if ( (v9 - v10) >> 2 )
      {
        copyRange_409050(v10, v10, v10 + 1);
        fillArrayWithValue_409080(*(a1 + 8), (1 - ((*(a1 + 8) - v11) >> 2)), &hostlong);
        for ( result = *(a1 + 8); v11 != result; ++v11 )
          *v11 = hostlong;
        *(a1 + 8) += 4;
      }
      else
      {
        v12 = *(a1 + 4);
        if ( !v12 || (v13 = (v10 - v12) >> 2, v13 <= 1) )
          v13 = 1;
        if ( v12 )
          v14 = (v10 - v12) >> 2;
        else
          v14 = 0;
        v15 = v13 + v14;
        v21 = v15;
        if ( v15 < 0 )
          v15 = 0;
        v16 = operator new(4 * v15);
        v17 = *(a1 + 4);
        v23 = v16;
        for ( j = v16; v17 != v11; ++j )
          copySingle_4090B0(j, v17++);
        fillArrayWithValue_409080(j, 1, &hostlong);
        copyRange_409050(v11, *(a1 + 8), j + 1);
        nullsub_2(*(a1 + 4), *(a1 + 8));
        freeBlock_4097FE(*(a1 + 4));
        v19 = *(a1 + 4);
        *(a1 + 12) = v23 + 4 * v21;
        if ( v19 )
          v20 = (*(a1 + 8) - v19) >> 2;
        else
          v20 = 0;
        v5 = v22;
        v6 = i;
        result = v23 + 4 * v20 + 4;
        *(a1 + 4) = v23;
        *(a1 + 8) = result;
      }
    }
    ++v6;
  }
  return result;
}
