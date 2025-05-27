// --- Metadata ---
// Function Name: replacePlaceholders_401190
// Address: 0x401190
// Exported At: 20250527_181447
// Signature: unknown_signature
// ---------------
unsigned int __cdecl replacePlaceholders_401190(char *a1, int a2, char *a3, char *a4, char *a5)
{
  unsigned int v5; // ebp
  char *v6; // esi
  char *v7; // edi
  char *v8; // eax
  int v9; // edx
  char *v10; // eax
  int v11; // edx
  char *v13; // [esp+10h] [ebp-4h]

  v5 = a2;
  v6 = a1;
  v7 = a1;                                      // 입력 문자열 a1에서 특정한 자리 표시자(placeholder) 문자열을 찾아, 해당 위치에 사용자 ID(a4)와 트리 ID(a5)를 각각 삽입하여 a3에 결과 문자열을 생성 
  v8 = searchSubstring_401140(a1, aUseridPlacehol, a2);
  v13 = v8;
  if ( v8 )
  {
    v9 = v8 - a1;
    qmemcpy(a3, a1, v8 - a1);
    a3[v9] = *a4;
    a3[v9 + 1] = a4[1];
    qmemcpy(&a3[v8 - a1 + 2], &v8[strlen(aUseridPlacehol)], a2 - (v8 - a1) - strlen(aUseridPlacehol));
    v6 = a1;
    v7 = a3;
    v5 = a2 - strlen(aUseridPlacehol) + 2;
  }
  v10 = searchSubstring_401140(v7, aTreeidPlacehol, v5);
  if ( v10 )
  {
    v11 = v10 - v7;
    qmemcpy(a3, v7, v10 - v7);
    a3[v11] = *a5;
    a3[v11 + 1] = a5[1];
    qmemcpy(&a3[v11 + 2], &v10[strlen(aUseridPlacehol)], v5 - v11 - strlen(aTreeidPlacehol));
    v6 = a1;
    v5 += 2 - strlen(aTreeidPlacehol);
  }
  if ( !v13 && !v10 )
    qmemcpy(a3, v6, v5);
  return v5;
}
