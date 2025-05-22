// --- Metadata ---
// Function Name: SetKey_10003C00
// Address: 0x10003C00
// Exported At: 20250522_124158
// Signature: unknown_signature
// ---------------
int __thiscall SetKey_10003C00(int *this, LPCSTR lpFileName)
{
  int *v3; // esi

  v3 = this + 2;
  if ( this[2] )
  {
    CryptDestroyKey(this[2]);
    *v3 = 0;
  }
  return ImportKeyFromFile_10003F00(this[1], (int)v3, lpFileName);
}
