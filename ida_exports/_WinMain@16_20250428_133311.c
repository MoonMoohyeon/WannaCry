int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  char ***v4; // eax
  void *v5; // eax
  int v6; // eax
  void (__stdcall *v7)(_DWORD, _DWORD); // eax
  int v9[310]; // [esp+10h] [ebp-6E4h] BYREF
  CHAR Filename; // [esp+4E8h] [ebp-20Ch] BYREF
  char v11[516]; // [esp+4E9h] [ebp-20Bh] BYREF
  __int16 v12; // [esp+6EDh] [ebp-7h]
  char v13; // [esp+6EFh] [ebp-5h]
  int v14; // [esp+6F0h] [ebp-4h] BYREF

  Filename = byte_40F910;
  memset(v11, 0, sizeof(v11));
  v12 = 0;
  v13 = 0;
  GetModuleFileNameA(0, &Filename, 0x208u);
  sub_401225(DisplayName);
  if ( *_p___argc() != 2
    || (v4 = _p___argv(), strcmp((*v4)[1], aI))
    || !sub_401B5F(0)
    || (CopyFileA(&Filename, FileName, 0), GetFileAttributesA(FileName) == -1)
    || !sub_401F5D() )
  {
    if ( strrchr(&Filename, 92) )
      *strrchr(&Filename, 92) = 0;
    SetCurrentDirectoryA(&Filename);            // aaaaaaaaa
    test_4010FD(1);
    testtest_401DAB(0, Str);                    // bbbbbbbbbbbb
    sub_401E9E();
    sub_401064(CommandLine, 0, 0);
    sub_401064(aIcaclsGrantEve, 0, 0);
    if ( sub_40170A() )
    {
      sub_4012FD(v9);
      if ( sub_401437(0, 0, 0) )
      {
        v14 = 0;
        v5 = (void *)sub_4014A6(aTWnry, (int)&v14);
        if ( v5 )
        {
          v6 = sub_4021BD(v5, v14);
          if ( v6 )
          {
            v7 = (void (__stdcall *)(_DWORD, _DWORD))sub_402924(v6, String1);
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
