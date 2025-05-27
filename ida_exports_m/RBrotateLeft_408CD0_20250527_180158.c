// --- Metadata ---
// Function Name: RBrotateLeft_408CD0
// Address: 0x408CD0
// Exported At: 20250527_180158
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall RBrotateLeft_408CD0(_DWORD *this, int a2)
{
  _DWORD *result; // eax
  int v3; // ecx
  _DWORD *v4; // ecx

  result = *(a2 + 8);
  *(a2 + 8) = *result;
  if ( *result != *&FileName[280] )
    *(*result + 4) = a2;
  result[1] = *(a2 + 4);
  v3 = this[1];
  if ( a2 == *(v3 + 4) )
  {
    *(v3 + 4) = result;
    *result = a2;
    *(a2 + 4) = result;
  }
  else
  {
    v4 = *(a2 + 4);
    if ( a2 == *v4 )
      *v4 = result;
    else
      v4[2] = result;
    *result = a2;
    *(a2 + 4) = result;
  }
  return result;
}
