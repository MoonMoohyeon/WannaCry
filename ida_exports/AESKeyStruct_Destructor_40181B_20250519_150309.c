// --- Metadata ---
// Function Name: AESKeyStruct_Destructor_40181B
// Address: 0x40181B
// Exported At: 20250519_150309
// Signature: unknown_signature
// ---------------
void __thiscall AESKeyStruct_Destructor_40181B(char *this)
{
  *this = &off_4081EC;
  DeleteCriticalSection((this + 16));
}
