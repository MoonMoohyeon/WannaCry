// --- Metadata ---
// Function Name: XOR_Block_403A28
// Address: 0x403A28
// Exported At: 20250515_230038
// Signature: unknown_signature
// ---------------
void __thiscall XOR_Block_403A28(int this, _BYTE *a2, _BYTE *a3)
{
  int i; // esi
  char pExceptionObject[12]; // [esp+4h] [ebp-Ch] BYREF

  if ( !*(this + 4) )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  for ( i = 0; i < *(this + 972); ++i )
    *a2++ ^= *a3++;
}
