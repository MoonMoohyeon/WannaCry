// --- Metadata ---
// Function Name: initCentralZipIterator_4064E2
// Address: 0x4064E2
// Exported At: 20250518_111321
// Signature: unknown_signature
// ---------------
int __cdecl initCentralZipIterator_4064E2(_DWORD *a1)
{
  int result; // eax

  if ( !a1 )
    return -102;
  a1[5] = a1[9];
  a1[4] = 0;
  result = parseCentralZipEntry_4061E0(a1, (a1 + 10), (a1 + 30), 0, 0, 0, 0, 0, 0);
  a1[6] = result == 0;
  return result;
}
