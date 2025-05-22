// --- Metadata ---
// Function Name: initCryptoSession_10001830
// Address: 0x10001830
// Exported At: 20250522_173249
// Signature: unknown_signature
// ---------------
int __thiscall initCryptoSession_10001830(LPVOID pSession, LPCSTR keyFilePath, int a3, int a4)
{
  int result; // eax
  unsigned int v6; // eax

  result = SetupCryptoSessionKey_10003AC0((_DWORD *)pSession + 1, keyFilePath, 0);// 키 1 
  if ( result )
  {
    if ( keyFilePath )
      SetupCryptoSessionKey_10003AC0((_DWORD *)pSession + 11, 0, 0);// 키 2 
    result = (int)GlobalAlloc(0, 0x100000u);    // 1mb 버퍼 2개 할당 
    *((_DWORD *)pSession + 306) = result;
    if ( result )
    {
      result = (int)GlobalAlloc(0, 0x100000u);  // 더블 버퍼링 구조 = 파일 I/O, 네트워크, 암복호화 등에 사용 
      *((_DWORD *)pSession + 307) = result;
      if ( result )
      {
        InitializeCriticalSection((LPCRITICAL_SECTION)((char *)pSession + 1260));
        *((_DWORD *)pSession + 310) = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartAddress, pSession, 0, 0);
        *((_DWORD *)pSession + 309) = a3;
        *((_DWORD *)pSession + 308) = a4;
        v6 = GetTickCount();
        srand(v6);
        result = 1;
      }
    }
  }
  return result;
}
