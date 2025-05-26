// --- Metadata ---
// Function Name: initializeCryptoContext_407620
// Address: 0x407620
// Exported At: 20250526_150824
// Signature: unknown_signature
// ---------------
void initializeCryptoContext_407620()
{
  int i; // esi

  for ( i = 0; i < 2; ++i )
  {
    if ( CryptAcquireContextA(                  // 암호화 컨텍스트 얻기 
           (HCRYPTPROV *)&FileName[272],
           0,
           (LPCSTR)(i != 0 ? (unsigned int)aMicrosoftBaseC : 0),
           1u,
           0xF0000000) )
    {
      break;
    }
  }
  InitializeCriticalSection(&CriticalSection);
}
