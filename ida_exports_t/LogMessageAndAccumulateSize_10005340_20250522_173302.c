// --- Metadata ---
// Function Name: LogMessageAndAccumulateSize_10005340
// Address: 0x10005340
// Exported At: 20250522_173302
// Signature: unknown_signature
// ---------------
int __stdcall LogMessageAndAccumulateSize_10005340(int a1, LPCWCH lpWideCharStr, int a3, int a4, int a5, int a6)
{
  FILE *v6; // esi
  CHAR MultiByteStr[620]; // [esp+4h] [ebp-26Ch] BYREF

  ++count_1000DCE4;                             // 호출 카운트 및 누적 값을 추적 
  sizeSum_1000DCE8 += __PAIR64__(a3, a4);
  if ( a6 )
  {
    v6 = fopen("f.wnry", "at");                 // WideChar 문자열 로그를 "f.wnry"라는 파일에 기록 
    if ( v6 )
    {
      WideCharToMultiByte(0, 0, lpWideCharStr, -1, MultiByteStr, 619, 0, 0);
      fprintf(v6, "%s\n", MultiByteStr);
      fclose(v6);
    }
  }
  return 1;
}
