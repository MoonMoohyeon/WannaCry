// --- Metadata ---
// Function Name: InitializeCryptoContext_40182C
// Address: 0x40182C
// Exported At: 20250516_090646
// Signature: unknown_signature
// ---------------
BOOL __thiscall InitializeCryptoContext_40182C(char *this)
{
  int v1; // edi
  HCRYPTPROV *v2; // esi
  BOOL result; // eax

  v1 = 0;
  v2 = (this + 4);
  while ( 1 )
  {
    result = CryptAcquireContextA(              // Crypto API 컨텍스트 확보 
               v2,
               0,
               (v1 != 0 ? "Microsoft Enhanced RSA and AES Cryptographic Provider" : 0),
               0x18u,
               0xF0000000);
    if ( result )
      break;
    if ( ++v1 >= 2 )
      return result;
  }
  return 1;
}
