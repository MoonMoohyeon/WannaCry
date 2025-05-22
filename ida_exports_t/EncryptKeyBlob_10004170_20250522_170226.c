// --- Metadata ---
// Function Name: EncryptKeyBlob_10004170
// Address: 0x10004170
// Exported At: 20250522_170226
// Signature: unknown_signature
// ---------------
BYTE *__cdecl EncryptKeyBlob_10004170(int a1, HCRYPTKEY hKey, HCRYPTKEY a3, DWORD dwBlobType, DWORD *pdwDataLen)
{
  BYTE *result; // eax
  BYTE *v6; // eax
  int v7; // ecx
  DWORD v8; // ebp
  DWORD v9; // eax
  DWORD v10; // ebx
  BYTE *v11; // eax
  int v12; // ecx
  BYTE *v13; // eax
  int v14; // edx
  BYTE *v15; // eax
  BYTE *v16; // ecx
  int v17; // edx
  BYTE *v18; // eax
  int v19; // ecx
  DWORD v20; // [esp+8h] [ebp-2028h]
  DWORD v21; // [esp+1Ch] [ebp-2014h] BYREF
  int v22; // [esp+20h] [ebp-2010h]
  BYTE *v23; // [esp+24h] [ebp-200Ch]
  HGLOBAL hMem; // [esp+28h] [ebp-2008h]
  BYTE v25[4]; // [esp+2Ch] [ebp-2004h] BYREF
  BYTE pbData[4096]; // [esp+30h] [ebp-2000h] BYREF 성공 여부와 상관없이 pbData 버퍼는 항상 0으로 초기화됨(보안)
  BYTE v27[4096]; // [esp+1030h] [ebp-1000h] BYREF

  *(_DWORD *)v25 = 0;                           // 대칭키(hKey)를 다른 키(a3)로 RSA 암호화해서 안전하게 저장할 수 있도록 블롭(blob)을 생성 
  v21 = 0;
  *pdwDataLen = 4096;
  result = (BYTE *)CryptExportKey(hKey, 0, dwBlobType, 0, pbData, pdwDataLen);// 암호화된 blob 포인터 출력 
  if ( result )
  {
    v21 = 4;
    if ( CryptGetKeyParam(a3, 8u, v25, &v21, 0) )
    {
      v8 = *(_DWORD *)v25 >> 3;
      v9 = *pdwDataLen - 1;
      v21 = (*(_DWORD *)v25 >> 3) - 11;
      v10 = v9 / v21 + 1;
      v20 = (*(_DWORD *)v25 >> 3) * v10;
      *pdwDataLen = v20;
      result = (BYTE *)GlobalAlloc(0, v20);
      hMem = result;
      if ( result )
      {
        v23 = result;
        v22 = 0;
        if ( v10 )
        {
          while ( 1 )
          {
            v13 = v27;
            v21 = v8 - 11;
            v14 = 4096;
            do
            {
              *v13++ = 0;
              --v14;
            }
            while ( v14 );
            qmemcpy(v27, &pbData[(v8 - 11) * v22], v8 - 11);
            if ( !CryptEncrypt(a3, 0, 1, 0, v27, &v21, v8) )
              break;
            v15 = v23;
            qmemcpy(v23, v27, v21);
            v23 = &v15[v21];
            if ( ++v22 >= v10 )
            {
              result = (BYTE *)hMem;
              goto LABEL_16;
            }
          }
          GlobalFree(hMem);
          v18 = pbData;
          v19 = 4096;
          do
          {
            *v18++ = 0;
            --v19;
          }
          while ( v19 );
          result = 0;
        }
        else
        {
LABEL_16:
          v16 = pbData;
          v17 = 4096;
          do
          {
            *v16++ = 0;
            --v17;
          }
          while ( v17 );
        }
      }
      else
      {
        v11 = pbData;
        v12 = 4096;
        do
        {
          *v11++ = 0;
          --v12;
        }
        while ( v12 );
        result = 0;
      }
    }
    else
    {
      v6 = pbData;
      v7 = 4096;
      do
      {
        *v6++ = 0;
        --v7;
      }
      while ( v7 );
      result = 0;
    }
  }
  return result;
}
