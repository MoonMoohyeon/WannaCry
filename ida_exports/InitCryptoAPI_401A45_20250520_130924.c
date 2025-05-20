// --- Metadata ---
// Function Name: InitCryptoAPI_401A45
// Address: 0x401A45
// Exported At: 20250520_130924
// Signature: unknown_signature
// ---------------
int InitCryptoAPI_401A45()
{
  HMODULE v0; // eax
  HMODULE v1; // edi
  BOOL (__stdcall *CryptGenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *); // eax
  int result; // eax

  if ( CryptAcquireContextA )                   // Windows Crypto API 함수 포인터들을 동적으로 로드
    goto LABEL_9;
  v0 = LoadLibraryA("advapi32.dll");
  v1 = v0;
  if ( !v0 )
    goto LABEL_10;
  CryptAcquireContextA = GetProcAddress(v0, "CryptAcquireContextA");
  CryptImportKey = GetProcAddress(v1, "CryptImportKey");
  CryptDestroyKey = GetProcAddress(v1, "CryptDestroyKey");
  *CryptEncrypt = GetProcAddress(v1, "CryptEncrypt");
  CryptDecrypt = GetProcAddress(v1, "CryptDecrypt");
  CryptGenKey = GetProcAddress(v1, "CryptGenKey");
  dword_40F8A8 = CryptGenKey;
  if ( CryptAcquireContextA && CryptImportKey && CryptDestroyKey && *CryptEncrypt && CryptDecrypt && CryptGenKey )
LABEL_9:
    result = 1;
  else
LABEL_10:
    result = 0;
  return result;
}
