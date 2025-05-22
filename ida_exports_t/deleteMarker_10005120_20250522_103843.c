// --- Metadata ---
// Function Name: deleteMarker_10005120
// Address: 0x10005120
// Exported At: 20250522_103843
// Signature: unknown_signature
// ---------------
wchar_t *__cdecl deleteMarker_10005120(int a1, wchar_t *Buffer)
{
  wchar_t Format; // [esp+8h] [ebp-208h] BYREF
  char v4[516]; // [esp+Ah] [ebp-206h] BYREF
  __int16 v5; // [esp+20Eh] [ebp-2h]

  Format = 0;
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  runAttribInRecyclePath_10005060(a1, &Format);
  swprintf(Buffer, (const size_t)L"%s\\hibsys%s", &Format, L".WNCRYT");// 해당 확장자를 가진 파일을 지움 
  DeleteFileW(Buffer);
  return Buffer;
}
