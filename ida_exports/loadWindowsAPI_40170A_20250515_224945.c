// --- Metadata ---
// Function Name: loadWindowsAPI_40170A
// Address: 0x40170A
// Exported At: 20250515_224945
// Signature: unknown_signature
// ---------------
int loadWindowsAPI_40170A()
{
  HMODULE v0; // eax
  HMODULE v1; // edi
  BOOL (__stdcall *CloseHandle)(HANDLE); // eax
  int result; // eax

  if ( !sub_401A45() )
    goto LABEL_12;
  if ( *CreateFileW )
    goto LABEL_11;
  v0 = LoadLibraryA("kernel32.dll");
  v1 = v0;
  if ( !v0 )
    goto LABEL_12;
  *CreateFileW = GetProcAddress(v0, "CreateFileW");
  *WriteFile_0 = GetProcAddress(v1, "WriteFile");
  *ReadFile_0 = GetProcAddress(v1, "ReadFile");
  *MoveFileW = GetProcAddress(v1, "MoveFileW");
  *MoveFileExW = GetProcAddress(v1, "MoveFileExW");
  *DeleteFileW = GetProcAddress(v1, "DeleteFileW");
  CloseHandle = GetProcAddress(v1, "CloseHandle");
  dword_40F890 = CloseHandle;
  if ( !*CreateFileW )
    goto LABEL_12;
  if ( *WriteFile_0 && *ReadFile_0 && *MoveFileW && *MoveFileExW && *DeleteFileW && CloseHandle )
LABEL_11:
    result = 1;
  else
LABEL_12:
    result = 0;
  return result;
}
