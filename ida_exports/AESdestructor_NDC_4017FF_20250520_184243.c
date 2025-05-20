// --- Metadata ---
// Function Name: AESdestructor_NDC_4017FF
// Address: 0x4017FF
// Exported At: 20250520_184243
// Signature: unknown_signature
// ---------------
void *__thiscall AESdestructor_NDC_4017FF(void *this, char a2)
{
  AESKeyStruct_Destructor_40181B(this);
  if ( (a2 & 1) != 0 )
    operator delete(this);
  return this;
}
