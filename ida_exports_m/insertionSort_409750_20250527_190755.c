// --- Metadata ---
// Function Name: insertionSort_409750
// Address: 0x409750
// Exported At: 20250527_190755
// Signature: unknown_signature
// ---------------
void __cdecl insertionSort_409750(unsigned int *a1, unsigned int *a2)
{
  unsigned int *i; // edi
  unsigned int v3; // esi
  unsigned int v4; // ecx
  unsigned int *v5; // eax
  unsigned int *k; // edx
  unsigned int *j; // eax
  unsigned int v8; // ecx

  if ( a1 != a2 )
  {
    for ( i = a1 + 1; i != a2; ++i )
    {
      v3 = *i;
      if ( *i < *a1 )
      {
        for ( j = i; j != a1; j[1] = v8 )
          v8 = *--j;
        *a1 = v3;
      }
      else
      {
        v4 = *(i - 1);
        v5 = i - 1;
        for ( k = i; v3 < v4; --v5 )
        {
          *k = v4;
          v4 = *(v5 - 1);
          k = v5;
        }
        *k = v3;
      }
    }
  }
}
