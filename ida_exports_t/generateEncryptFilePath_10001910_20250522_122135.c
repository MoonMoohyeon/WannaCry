// --- Metadata ---
// Function Name: generateEncryptFilePath_10001910
// Address: 0x10001910
// Exported At: 20250522_122135
// Signature: unknown_signature
// ---------------
int __thiscall generateEncryptFilePath_10001910(wchar_t *mainObject, wchar_t *Source)
{
  wchar_t *v2; // esi
  const wchar_t *outputDir; // edi
  int fileIndex; // eax

  v2 = mainObject;
  outputDir = mainObject + 642;
  wcscpy(mainObject + 642, Source);
  fileIndex = *((_DWORD *)v2 + 581);
  v2 += 902;
  *((_DWORD *)v2 + 130) = fileIndex + 1;        // "디렉토리\번호.WNCRYT" 형식의 문자열을 생성해 저장 
  return swprintf(v2, (const size_t)L"%s\\%d%s", outputDir, fileIndex, L".WNCRYT");
}
