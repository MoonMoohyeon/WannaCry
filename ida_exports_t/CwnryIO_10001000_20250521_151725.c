// --- Metadata ---
// Function Name: CwnryIO_10001000
// Address: 0x10001000
// Exported At: 20250521_151725
// Signature: unknown_signature
// ---------------
int __cdecl CwnryIO_10001000(void *Buffer, int a2)
{
  FILE *v2; // eax
  FILE *v3; // esi
  size_t v4; // eax

  if ( a2 )
    v2 = fopen("c.wnry", "rb");
  else
    v2 = fopen("c.wnry", "wb");
  v3 = v2;
  if ( !v2 )
    return 0;
  if ( a2 )
    v4 = fread(Buffer, 0x30Cu, 1u, v2);
  else
    v4 = fwrite(Buffer, 0x30Cu, 1u, v2);
  if ( !v4 )
  {
    fclose(v3);
    return 0;
  }
  fclose(v3);
  return 1;
}
