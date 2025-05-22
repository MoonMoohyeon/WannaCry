// --- Metadata ---
// Function Name: VerifyKeyPair_10003D10
// Address: 0x10003D10
// Exported At: 20250522_123855
// Signature: unknown_signature
// ---------------
int __thiscall VerifyKeyPair_10003D10(int this, LPCSTR lpFileName, LPCSTR a3)
{
  DWORD pdwDataLen; // [esp+10h] [ebp-228h] BYREF
  char Str2[12]; // [esp+14h] [ebp-224h] BYREF
  char Str1; // [esp+20h] [ebp-218h] BYREF
  char v8[508]; // [esp+21h] [ebp-217h] BYREF
  __int16 v9; // [esp+21Dh] [ebp-1Bh]
  char v10; // [esp+21Fh] [ebp-19h]
  CPPEH_RECORD ms_exc; // [esp+220h] [ebp-18h] BYREF

  strcpy(Str2, "TESTDATA");                     // 테스트 문자열에 대해 암/복호화를 통해 키 쌍의 유효성 검증 
  Str2[9] = 0;
  Str1 = 0;
  memset(v8, 0, sizeof(v8));
  v9 = 0;
  v10 = 0;
  pdwDataLen = strlen(Str2);
  if ( !InitCryptoProvider_10003A80((char *)this) )
    return 0;
  ms_exc.registration.TryLevel = 0;
  if ( !ImportKeyFromFile_10003F00(*(_DWORD *)(this + 4), this + 8, lpFileName)
    || !ImportKeyFromFile_10003F00(*(_DWORD *)(this + 4), this + 12, a3) )
  {
    local_unwind2(&ms_exc.registration, -1);
    return 0;
  }
  strcpy(&Str1, Str2);
  if ( !CryptEncrypt(*(_DWORD *)(this + 8), 0, 1, 0, (BYTE *)&Str1, &pdwDataLen, 0x200u)
    || !CryptDecrypt(*(_DWORD *)(this + 12), 0, 1, 0, (BYTE *)&Str1, &pdwDataLen) )
  {
    local_unwind2(&ms_exc.registration, -1);
    return 0;
  }
  if ( strncmp(&Str1, Str2, strlen(Str2)) )
  {
    ms_exc.registration.TryLevel = -1;
    ReleaseCryptoResources_10003BB0((_DWORD *)this);
    return 0;
  }
  local_unwind2(&ms_exc.registration, -1);
  return 1;
}
