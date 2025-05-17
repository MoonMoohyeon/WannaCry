// --- Metadata ---
// Function Name: mkdirRecursive_407070
// Address: 0x407070
// Exported At: 20250517_141227
// Signature: unknown_signature
// ---------------
char __cdecl mkdirRecursive_407070(LPCSTR lpFileName, void *Src)
{
  DWORD v2; // eax
  _BYTE *v3; // esi
  char *v4; // ecx
  size_t v5; // esi
  char v7[260]; // [esp+8h] [ebp-208h] BYREF
  char Destination[260]; // [esp+10Ch] [ebp-104h] BYREF

  if ( lpFileName && GetFileAttributesA(lpFileName) == -1 )
    CreateDirectoryA(lpFileName, 0);
  LOBYTE(v2) = *Src;
  if ( *Src )
  {
    v3 = Src;
    v4 = Src;
    do
    {
      if ( v2 == 47 || v2 == 92 )
        v3 = v4;
      LOBYTE(v2) = *++v4;
    }
    while ( v2 );
    if ( v3 != Src )
    {
      v5 = v3 - Src;
      memcpy(v7, Src, v5);
      v7[v5] = 0;
      mkdirRecursive_407070(lpFileName, v7);    // 디렉토리 경로를 재귀적으로 생성 
    }
    Destination[0] = 0;
    if ( lpFileName )
      strcpy(Destination, lpFileName);
    strcat(Destination, Src);
    v2 = GetFileAttributesA(Destination);
    if ( v2 == -1 )
      LOBYTE(v2) = CreateDirectoryA(Destination, 0);
  }
  return v2;
}
