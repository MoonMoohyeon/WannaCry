// --- Metadata ---
// Function Name: InitCryptoProvider_10003A80
// Address: 0x10003A80
// Exported At: 20250522_123813
// Signature: unknown_signature
// ---------------
BOOL __thiscall InitCryptoProvider_10003A80(char *this)
{
  int v1; // esi
  HCRYPTPROV *v2; // edi
  BOOL result; // eax

  v1 = 0;
  v2 = (HCRYPTPROV *)(this + 4);
  while ( 1 )                                   // 암호화 서비스 공급자(CSP)를 확보 
  {
    result = CryptAcquireContextA(
               v2,
               0,
               (LPCSTR)(v1 != 0 ? (unsigned int)"Microsoft Enhanced RSA and AES Cryptographic Provider" : 0),
               0x18u,
               0xF0000000);
    if ( result )
      break;
    if ( ++v1 >= 2 )
      return result;
  }
  return 1;
}
