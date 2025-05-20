// --- Metadata ---
// Function Name: AEScleanUp_NDC_40135E
// Address: 0x40135E
// Exported At: 20250520_184301
// Signature: unknown_signature
// ---------------
void *__thiscall AEScleanUp_NDC_40135E(void *this, char a2)
{
  AESKeyStruct_FinalCleanup_40137A(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}
