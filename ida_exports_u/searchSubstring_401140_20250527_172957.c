// --- Metadata ---
// Function Name: searchSubstring_401140
// Address: 0x401140
// Exported At: 20250527_172957
// Signature: unknown_signature
// ---------------
char *__cdecl searchSubstring_401140(char *a1, const char *a2, int a3)
{
  unsigned int v3; // kr04_4
  char *result; // eax
  char *v5; // ebx

  v3 = strlen(a2) + 1;                          // strstr와 유사하지만, 검색 범위를 제한 
  result = a1;
  v5 = &a1[a3 - (v3 - 1)];
  if ( a1 > v5 )
    return 0;
  while ( memcmp(result, a2, (v3 - 1)) )        // 문자열 a1에서 문자열 a2가 처음으로 등장하는 위치를 찾음 
  {
    if ( ++result > v5 )
      return 0;
  }
  return result;
}
