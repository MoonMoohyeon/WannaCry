// --- Metadata ---
// Function Name: CreateAndRunTempBatchFile_10001140
// Address: 0x10001140
// Exported At: 20250522_105217
// Signature: unknown_signature
// ---------------
FILE *__cdecl CreateAndRunTempBatchFile_10001140(const char *a1)
{
  unsigned int v1; // eax
  int v2; // eax
  FILE *result; // eax
  FILE *v4; // esi
  __time32_t v5; // [esp-4h] [ebp-10Ch]
  char Buffer[260]; // [esp+4h] [ebp-104h] BYREF

  v1 = GetTickCount();
  srand(v1);
  v5 = time(0);
  v2 = rand();
  sprintf(Buffer, "%d%d.bat", v2, v5);          // 임시 .bat 파일을 생성, 실행 후 삭제 
  result = fopen(Buffer, "wt");
  v4 = result;
  if ( result )
  {
    fprintf(result, "%s\ndel /a %%0\n", a1);
    fclose(v4);
    result = (FILE *)RunProcessWithTimeout_10001080(Buffer, 0, 0);
  }
  return result;
}
