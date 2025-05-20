// --- Metadata ---
// Function Name: AESinitVtable_NDC_402A53
// Address: 0x402A53
// Exported At: 20250520_184233
// Signature: unknown_signature
// ---------------
void *__thiscall AESinitVtable_NDC_402A53(void *this, char a2)
{
  AESKeyStruct_initVtable_402A6F(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}
