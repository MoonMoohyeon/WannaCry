// --- Metadata ---
// Function Name: LoadFileIOAPI_10003410
// Address: 0x10003410
// Exported At: 20250522_123601
// Signature: unknown_signature
// ---------------
int LoadFileIOAPI_10003410()
{
  int result; // eax
  HMODULE v1; // eax
  HMODULE v2; // esi
  BOOL (__stdcall *CloseHandle)(HANDLE); // eax

  if ( !LoadCryptographicAPI_10004440() )       // 런타임 시 환경에서 필요한 API가 존재하는지를 확인
    goto LABEL_13;
  if ( CreateFileW_0 )
    return 1;
  v1 = LoadLibraryA("kernel32.dll");            // Windows 파일 I/O API를 런타임에서 동적으로 로드 
  v2 = v1;
  if ( !v1 )
    goto LABEL_13;                              // 백신 우회나 이식성을 고려한 악성코드 
  CreateFileW_0 = (HANDLE (__stdcall *)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))GetProcAddress(v1, "CreateFileW");
  WriteFile_0 = (BOOL (__stdcall *)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(v2, "WriteFile");
  ReadFile_0 = (BOOL (__stdcall *)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(v2, "ReadFile");
  MoveFileW = (BOOL (__stdcall *)(LPCWSTR, LPCWSTR))GetProcAddress(v2, "MoveFileW");
  MoveFileExW_0 = (BOOL (__stdcall *)(LPCWSTR, LPCWSTR, DWORD))GetProcAddress(v2, "MoveFileExW");
  DeleteFileW_0 = (BOOL (__stdcall *)(LPCWSTR))GetProcAddress(v2, "DeleteFileW");
  CloseHandle = (BOOL (__stdcall *)(HANDLE))GetProcAddress(v2, "CloseHandle");
  dword_1000D934 = (int (__stdcall *)(_DWORD))CloseHandle;
  if ( !CreateFileW_0 )
    goto LABEL_13;
  if ( WriteFile_0 && ReadFile_0 && MoveFileW && MoveFileExW_0 && DeleteFileW_0 && CloseHandle )
    result = 1;
  else
LABEL_13:
    result = 0;
  return result;
}
