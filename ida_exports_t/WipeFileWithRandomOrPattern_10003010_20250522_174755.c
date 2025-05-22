// --- Metadata ---
// Function Name: WipeFileWithRandomOrPattern_10003010
// Address: 0x10003010
// Exported At: 20250522_174755
// Signature: unknown_signature
// ---------------
int __cdecl WipeFileWithRandomOrPattern_10003010(LPCWSTR filePath, int hCryptProv)
{
  DWORD v2; // eax
  int result; // eax
  HANDLE v4; // ebp
  LONG v5; // edx
  DWORD v6; // eax
  DWORD v7; // ebx
  unsigned int v8; // ecx
  LONG v9; // eax
  DWORD v10; // edx
  unsigned int v11; // esi
  LONG v12; // edi
  DWORD v13; // ebx
  DWORD v14; // kr08_4
  LARGE_INTEGER FileSize; // [esp+44h] [ebp-40014h] BYREF
  unsigned int v16; // [esp+4Ch] [ebp-4000Ch] BYREF
  LONG v17; // [esp+54h] [ebp-40004h]
  BYTE pbBuffer[4]; // [esp+58h] [ebp-40000h] BYREF

  v2 = GetFileAttributesW(filePath);            // 디스크에서 복구하기 어렵게 만드는 전형적인 파일 완전 삭제 방식 
  if ( v2 == -1 )
    return 0;
  if ( (v2 & 1) != 0 )                          // 파일의 일부 또는 전체를 난수 혹은 고정 패턴(0x55) 으로 덮어씀 
  {
    LOBYTE(v2) = v2 & 0xFE;
    SetFileAttributesW(filePath, v2);
  }
  v4 = CreateFileW_0(filePath, 0x40000000u, 3u, 0, 3u, 0, 0);
  if ( v4 != (HANDLE)-1 )
    goto LABEL_9;
  result = return0_10003000();
  if ( !result )
    return result;
  v4 = CreateFileW_0(filePath, 0x40000000u, 3u, 0, 3u, 0, 0);
  if ( v4 == (HANDLE)-1 )
    return 0;
LABEL_9:
  GetFileSizeEx(v4, &FileSize);
  v5 = FileSize.HighPart;
  if ( hCryptProv )                             // hCryptProv 인자가 있으면 암호학적 난수로, 없으면 고정값으로 데이터를 채움 
  {
    v6 = FileSize.LowPart;
    if ( FileSize.QuadPart >= 0x40000 )
    {
      v6 = 0x40000;
      v17 = 0;
    }
    else
    {
      v17 = FileSize.HighPart;
    }
    CryptGenRandomWrapper_10004420((HCRYPTPROV *)hCryptProv, pbBuffer, v6);
    v5 = FileSize.HighPart;
    v7 = FileSize.LowPart;
  }
  else                                          // 1차적으로 마지막 1KB 또는 전체 크기만큼 덮어쓰고, 이후 전체 파일을 반복적으로 덮어씀 
  {
    v7 = FileSize.LowPart;
    if ( FileSize.QuadPart >= 0x40000 )
    {
      v8 = 0x40000;
      v17 = 0;
    }
    else
    {
      v17 = FileSize.HighPart;
      v8 = FileSize.LowPart;
    }
    memset(pbBuffer, 0x55u, v8);
  }
  if ( v5 < 0 || v5 <= 0 && v7 < 0x400 )
  {
    WriteFile_0(v4, pbBuffer, v7, &v16, 0);
  }
  else
  {
    SetFilePointer(v4, -1024, 0, 2u);
    WriteFile_0(v4, pbBuffer, 0x400u, &v16, 0);
  }
  FlushFileBuffers(v4);
  SetFilePointer(v4, 0, 0, 0);
  v9 = FileSize.HighPart;
  v10 = FileSize.LowPart;
  v11 = 0;
  v12 = 0;
  if ( FileSize.QuadPart > 0 )
  {
    do
    {
      while ( 1 )
      {
        v13 = 0x40000;
        if ( (__int64)(__PAIR64__(v9, v10) - __PAIR64__(v12, v11)) < 0x40000 )
          v13 = v10 - v11;
        WriteFile_0(v4, pbBuffer, v13, &v16, 0);
        v9 = FileSize.HighPart;
        v14 = v16 + v11;
        v12 = (v16 + __PAIR64__(v12, v11)) >> 32;
        v11 += v16;
        if ( v12 >= FileSize.HighPart )
          break;
        v10 = FileSize.LowPart;
      }
      if ( v12 > FileSize.HighPart )
        break;
      v10 = FileSize.LowPart;
    }
    while ( v14 < FileSize.LowPart );
  }
  dword_1000D934(v4);
  return 1;
}
