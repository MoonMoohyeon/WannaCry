// --- Metadata ---
// Function Name: c.wnryIO_401000
// Address: 0x401000
// Exported At: 20250515_224712
// Signature: unknown_signature
// ---------------
int __cdecl c_wnryIO_401000(void *Buffer, int a2)
{
  int v2; // esi
  FILE *v3; // eax
  FILE *v4; // edi
  size_t v6; // eax

  v2 = 0;
  if ( a2 )
    v3 = fopen("c.wnry", "rb");
  else
    v3 = fopen("c.wnry", "wb");
  v4 = v3;
  if ( !v3 )
    return 0;
  if ( a2 )
    v6 = fread(Buffer, 780u, 1u, v3);
  else
    v6 = fwrite(Buffer, 780u, 1u, v3);
  if ( v6 )
    v2 = 1;
  fclose(v4);
  return v2;
}
