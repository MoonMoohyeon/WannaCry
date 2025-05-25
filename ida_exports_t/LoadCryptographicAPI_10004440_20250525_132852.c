// --- Metadata ---
// Function Name: LoadCryptographicAPI_10004440
// Address: 0x10004440
// Exported At: 20250525_132852
// Signature: unknown_signature
// ---------------
int LoadCryptographicAPI_10004440()
{
  int result; // eax
  HMODULE v1; // eax
  HMODULE v2; // esi
  BOOL (__stdcall *CryptGenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *); // eax

  if ( CryptAcquireContextA )                   // Cryptography 관련 API를 동적으로 로드
    return 1;
  v1 = LoadLibraryA("advapi32.dll");
  v2 = v1;
  result = 0;
  if ( v1 )
  {
    CryptAcquireContextA = (BOOL (__stdcall *)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD))GetProcAddress(
                                                                                             v1,
                                                                                             "CryptAcquireContextA");
    CryptImportKey = (BOOL (__stdcall *)(HCRYPTPROV, const BYTE *, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY *))GetProcAddress(v2, "CryptImportKey");
    CryptDestroyKey = (BOOL (__stdcall *)(HCRYPTKEY))GetProcAddress(v2, "CryptDestroyKey");
    *(_DWORD *)CryptEncrypt = GetProcAddress(v2, "CryptEncrypt");
    *(_DWORD *)CryptDecrypt = GetProcAddress(v2, "CryptDecrypt");
    CryptGenKey = (BOOL (__stdcall *)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *))GetProcAddress(v2, "CryptGenKey");
    dword_1000D950 = (int (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD))CryptGenKey;
    if ( CryptAcquireContextA )
    {
      if ( CryptImportKey && CryptDestroyKey && *(_DWORD *)CryptEncrypt && *(_DWORD *)CryptDecrypt && CryptGenKey )
        result = 1;
    }
  }
  return result;
}
