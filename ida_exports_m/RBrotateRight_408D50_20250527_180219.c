// --- Metadata ---
// Function Name: RBrotateRight_408D50
// Address: 0x408D50
// Exported At: 20250527_180219
// Signature: unknown_signature
// ---------------
int __thiscall RBrotateRight_408D50(_DWORD *this, _DWORD *a2)
{
  int result; // eax
  int v3; // esi
  int v4; // ecx
  _DWORD *v5; // ecx

  result = *a2;
  *a2 = *(*a2 + 8);
  v3 = *(result + 8);
  if ( v3 != *&FileName[280] )
    *(v3 + 4) = a2;
  *(result + 4) = a2[1];
  v4 = this[1];
  if ( a2 == *(v4 + 4) )
  {
    *(v4 + 4) = result;
    *(result + 8) = a2;
    a2[1] = result;
  }
  else
  {
    v5 = a2[1];
    if ( a2 == v5[2] )
      v5[2] = result;
    else
      *v5 = result;
    *(result + 8) = a2;
    a2[1] = result;
  }
  return result;
}
