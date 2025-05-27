// --- Metadata ---
// Function Name: copyNodeData_408E30
// Address: 0x408E30
// Exported At: 20250527_180107
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl copyNodeData_408E30(_DWORD *a1, _DWORD *a2)
{
  _DWORD *result; // eax

  result = a1;
  if ( a1 )
  {
    *a1 = *a2;
    a1[1] = a2[1];
  }
  return result;
}
