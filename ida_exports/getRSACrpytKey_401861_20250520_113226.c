// --- Metadata ---
// Function Name: getRSACrpytKey_401861
// Address: 0x401861
// Exported At: 20250520_113226
// Signature: unknown_signature
// ---------------
int __thiscall getRSACrpytKey_401861(int *this, LPCSTR lpFileName)
{
  if ( InitializeCryptoContext_40182C(this) )   // CSP 컨텍스트 확보 
  {
    if ( lpFileName ? ImportRSAKey_4018F9(this[1], (this + 2), lpFileName) : CryptImportKey(
                                                                               this[1],
                                                                               byte_40EBF8,
                                                                               0x494u,
                                                                               0,
                                                                               0,
                                                                               this + 2) )
      return 1;
  }
  ReleaseCryptoContext_4018B9(this);
  return 0;
}
