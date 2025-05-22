// --- Metadata ---
// Function Name: IsCriticalSystemFolder_100032C0
// Address: 0x100032C0
// Exported At: 20250522_175704
// Signature: unknown_signature
// ---------------
BOOL __stdcall IsCriticalSystemFolder_100032C0(wchar_t *path, wchar_t *folderName)
{
  wchar_t *posAfterPrefix; // eax
  const wchar_t *subPath; // esi

  if ( wcsnicmp(path, L"\\\\", 2u) )            // 시스템을 망가뜨리지 않도록 시스템 주요 폴더를 체크 
    posAfterPrefix = path + 1;
  else
    posAfterPrefix = wcsstr(path, L"$\\");
  if ( !posAfterPrefix )
    goto LABEL_26;
  subPath = posAfterPrefix + 1;
  if ( !wcsicmp(posAfterPrefix + 1, L"\\Intel") )
    return 1;
  if ( !wcsicmp(subPath, L"\\ProgramData") )
    return 1;
  if ( !wcsicmp(subPath, L"\\WINDOWS") )
    return 1;
  if ( !wcsicmp(subPath, L"\\Program Files") )
    return 1;
  if ( !wcsicmp(subPath, L"\\Program Files (x86)") )
    return 1;
  if ( wcsstr(subPath, L"\\AppData\\Local\\Temp") )
    return 1;
  if ( wcsstr(subPath, L"\\Local Settings\\Temp") )
    return 1;
LABEL_26:
  if ( !wcsicmp(folderName, L" This folder protects against ransomware. Modifying it will reduce protection") )
    return 1;
  if ( wcsicmp(folderName, L"Temporary Internet Files") )
    return wcsicmp(folderName, L"Content.IE5") == 0;
  return 1;
}
