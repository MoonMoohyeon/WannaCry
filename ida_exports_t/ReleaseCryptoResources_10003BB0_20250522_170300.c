// --- Metadata ---
// Function Name: ReleaseCryptoResources_10003BB0
// Address: 0x10003BB0
// Exported At: 20250522_170300
// Signature: unknown_signature
// ---------------
int __thiscall ReleaseCryptoResources_10003BB0(_DWORD *this)
{
  HCRYPTPROV v2; // eax

  if ( this[2] )
  {
    CryptDestroyKey(this[2]);
    this[2] = 0;
  }
  if ( this[3] )
  {
    CryptDestroyKey(this[3]);
    this[3] = 0;
  }
  v2 = this[1];
  if ( v2 )
  {
    CryptReleaseContext(v2, 0);
    this[1] = 0;
  }
  return 1;
}
