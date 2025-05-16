// --- Metadata ---
// Function Name: AESKey_constructor_401437
// Address: 0x401437
// Exported At: 20250516_091149
// Signature: unknown_signature
// ---------------
int __thiscall AESKey_constructor_401437(_DWORD *this, LPCSTR lpFileName, int a3, int a4)
{
  HGLOBAL v5; // eax
  HGLOBAL v6; // eax

  if ( !loadCrpytKey_401861(this + 1, lpFileName) )
    return 0;
  if ( lpFileName )
    loadCrpytKey_401861(this + 11, 0);
  v5 = GlobalAlloc(0, 0x100000u);
  this[306] = v5;
  if ( !v5 )
    return 0;
  v6 = GlobalAlloc(0, 0x100000u);
  this[307] = v6;
  if ( !v6 )
    return 0;
  this[309] = a3;
  this[308] = a4;
  return 1;
}
