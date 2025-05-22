// --- Metadata ---
// Function Name: decryptDrive_10005680
// Address: 0x10005680
// Exported At: 20250522_104847
// Signature: unknown_signature
// ---------------
DWORD __stdcall decryptDrive_10005680(LPVOID lpThreadParameter)
{
  _DWORD mainObject[585]; // [esp+0h] [ebp-930h] BYREF
  int v3; // [esp+92Ch] [ebp-4h]

  initMainObject_10001590(mainObject);
  v3 = 0;
  if ( initCryptoSession_10001830(              // 암호화 세션을 초기화하고, 지정된 드라이브에서 복호화를 시도하는 스레드 작업 
         mainObject,
         pky_1000DD24,
         (int)LogMessageAndAccumulateSize_10005340,
         (int)&isImportKeySuccess_1000DD8C) )
  {
    CheckDriveAndDecryptFiles_10005540((int)mainObject, (LONG)lpThreadParameter, 0);
    WriteMarkerAndFillDisk_10005190((int)lpThreadParameter);
    CleanupCryptoObject_10001760((int)mainObject);
    ExitThread(0);
  }
  v3 = -1;
  CryptoObject_Destructor_10001680((char *)mainObject);
  return 0;
}
