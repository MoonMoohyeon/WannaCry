// --- Metadata ---
// Function Name: createDirAndHide_401AF6
// Address: 0x401AF6
// Exported At: 20250515_232610
// Signature: unknown_signature
// ---------------
int __cdecl createDirAndHide_401AF6(LPCWSTR lpPathName, LPCWSTR lpFileName, wchar_t *Buffer)
{
  DWORD v4; // eax

  CreateDirectoryW(lpPathName, 0);
  if ( !SetCurrentDirectoryW(lpPathName) )
    return 0;
  CreateDirectoryW(lpFileName, 0);
  if ( !SetCurrentDirectoryW(lpFileName) )
    return 0;
  v4 = GetFileAttributesW(lpFileName);
  LOBYTE(v4) = v4 | 6;
  SetFileAttributesW(lpFileName, v4);
  if ( Buffer )
    swprintf(Buffer, L"%s\\%s", lpPathName, lpFileName);
  return 1;
}
