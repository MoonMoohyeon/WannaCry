// --- Metadata ---
// Function Name: ExecuteProcessWithTimeout
// Address: 0x401064
// Exported At: 20250515_223156
// Signature: unknown_signature
// ---------------
int __cdecl ExecuteProcessWithTimeout(LPSTR lpCommandLine, DWORD dwMilliseconds, LPDWORD lpExitCode)
{
  struct _STARTUPINFOA StartupInfo; // [esp+8h] [ebp-54h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+4Ch] [ebp-10h] BYREF

  StartupInfo.cb = 68;
  memset(&StartupInfo.lpReserved, 0, 0x40u);
  ProcessInformation.hProcess = 0;
  ProcessInformation.hThread = 0;
  ProcessInformation.dwProcessId = 0;
  ProcessInformation.dwThreadId = 0;
  StartupInfo.wShowWindow = 0;
  StartupInfo.dwFlags = 1;
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
