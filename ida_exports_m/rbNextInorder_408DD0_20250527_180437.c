// --- Metadata ---
// Function Name: rbNextInorder_408DD0
// Address: 0x408DD0
// Exported At: 20250527_180437
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall rbNextInorder_408DD0(void *this)
{
  _DWORD *v1; // eax
  _DWORD *result; // eax
  _DWORD *v3; // edx

  v1 = *this;
  if ( *(*this + 20) || *(v1[1] + 4) != v1 )
  {
    v3 = *v1;
    if ( *v1 == *&FileName[280] )
    {
      for ( result = v1[1]; *this == *result; result = result[1] )
        *this = result;
      *this = result;
    }
    else
    {
      for ( result = v3[2]; result != *&FileName[280]; result = result[2] )
        v3 = result;
      *this = v3;
    }
  }
  else
  {
    result = v1[2];
    *this = result;
  }
  return result;
}
