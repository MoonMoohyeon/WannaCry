// --- Metadata ---
// Function Name: ReadFromZipStream_406880
// Address: 0x406880
// Exported At: 20250519_105228
// Signature: unknown_signature
// ---------------
int __cdecl sub_406880(int zipCtx, int output_size, unsigned int toread, _BYTE *output_ptr)
{
  _BYTE *v4; // ebx
  int v5; // esi
  unsigned int v6; // eax ZIP 스트림으로부터 데이터를 읽고 복호화/해제, CRC 체크섬 계산 
  unsigned int v7; // eax 암호화·압축된 페이로드를 디스크 I/O 없이 메모리상에서 처리하는 고수준 루틴 
  unsigned int v8; // edi
  _BYTE *v9; // ebx
  bool v10; // zf
  unsigned __int8 v11; // al
  unsigned int v12; // ecx
  unsigned int v13; // ecx
  unsigned int v14; // eax
  unsigned int v15; // edi
  char v16; // dl
  unsigned int v17; // edi
  unsigned int i; // eax
  unsigned int CRC32checksum2; // eax
  int v20; // ebx
  unsigned int v21; // edi
  unsigned int CRC32checksum; // eax
  int v25; // [esp+Ch] [ebp-8h]
  int v26; // [esp+10h] [ebp-4h]
  unsigned int zipCtxa; // [esp+1Ch] [ebp+8h]
  unsigned __int8 *zipCtxb; // [esp+1Ch] [ebp+8h]

  v4 = output_ptr;
  v26 = 0;
  if ( output_ptr )
    *output_ptr = 0;
  if ( !zipCtx )
    return -102;
  v5 = *(zipCtx + 124);
  if ( !v5 )
    return -102;
  if ( !*v5 )
    return -100;
  if ( !toread )
    return 0;
  *(v5 + 20) = toread;
  *(v5 + 16) = output_size;
  v6 = *(v5 + 92);
  if ( toread > v6 )
    *(v5 + 20) = v6;
  while ( *(v5 + 20) )
  {
    if ( !*(v5 + 8) )
    {
      v7 = *(v5 + 88);
      if ( v7 )
      {
        v8 = 0x4000;
        if ( v7 < 0x4000 )
          v8 = *(v5 + 88);
        if ( SeekStreamOffset_405D0E(*(v5 + 96), *(v5 + 60) + *(v5 + 104), 0)
          || readFromReader_405D8A(*v5, v8, 1, *(v5 + 96)) != 1 )
        {
          return -1;
        }
        *(v5 + 60) += v8;
        *(v5 + 88) -= v8;
        v9 = *v5;
        v10 = *(v5 + 108) == 0;
        *(v5 + 4) = *v5;
        *(v5 + 8) = v8;
        if ( !v10 )
        {
          for ( zipCtxa = 0; zipCtxa < v8; v9[v12] = v11 )
          {
            v11 = EncryptByteWithState_4055A3((v5 + 112), v9[zipCtxa]);
            v12 = zipCtxa++;
          }
        }
        v4 = output_ptr;
      }
    }
    v13 = *(v5 + 124);
    v14 = *(v5 + 8);
    if ( v13 > v14 )
      v13 = *(v5 + 8);
    if ( v13 )
    {
      v15 = *(v5 + 4) + v13;
      v16 = *(v15 - 1);
      v10 = *(v5 + 124) == v13;
      *(v5 + 124) -= v13;
      *(v5 + 8) = v14 - v13;
      *(v5 + 4) = v15;
      if ( v10 && v16 != *(v5 + 128) )
        return -106;
    }
    if ( *(v5 + 100) )
    {
      v20 = *(v5 + 24);
      zipCtxb = *(v5 + 16);
      v25 = inflateStream_40583C((v5 + 4), 2);
      v21 = *(v5 + 24) - v20;
      CRC32checksum = computeCRC32_40541F(*(v5 + 80), zipCtxb, v21);
      *(v5 + 92) -= v21;
      v26 += v21;
      *(v5 + 80) = CRC32checksum;
      if ( v25 == 1 || !*(v5 + 92) )
      {
        if ( output_ptr )
          *output_ptr = 1;
        return v26;
      }
      if ( v25 )
        return v25;
      v4 = output_ptr;
    }
    else
    {
      v17 = *(v5 + 8);
      if ( *(v5 + 20) < v17 )
        v17 = *(v5 + 20);
      for ( i = 0; i < v17; ++i )
        *(*(v5 + 16) + i) = *(*(v5 + 4) + i);
      CRC32checksum2 = computeCRC32_40541F(*(v5 + 80), *(v5 + 16), v17);
      *(v5 + 92) -= v17;
      *(v5 + 8) -= v17;
      *(v5 + 20) -= v17;
      *(v5 + 16) += v17;
      *(v5 + 4) += v17;
      *(v5 + 24) += v17;
      v26 += v17;
      *(v5 + 80) = CRC32checksum2;
      if ( !*(v5 + 92) )
      {
        if ( v4 )
          *v4 = 1;
      }
    }
  }
  return v26;
}
