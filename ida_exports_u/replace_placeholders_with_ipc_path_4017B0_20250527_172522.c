// --- Metadata ---
// Function Name: replace_placeholders_with_ipc_path_4017B0
// Address: 0x4017B0
// Exported At: 20250527_172522
// Signature: unknown_signature
// ---------------
int __cdecl replace_placeholders_with_ipc_path_4017B0(const char *a1, char *a2)
{
  int finalLength; // ebx
  unsigned int v3; // kr04_4
  char *placeholderPos; // eax
  int v5; // edx
  int v6; // ebx
  char v7; // al
  char *v8; // eax
  char *v10; // [esp+10h] [ebp-4D0h]
  char Buffer; // [esp+18h] [ebp-4C8h] BYREF
  char v12[196]; // [esp+19h] [ebp-4C7h] BYREF
  __int16 v13; // [esp+DDh] [ebp-403h]
  char v14; // [esp+DFh] [ebp-401h]
  char modifiedTemplate[1024]; // [esp+E0h] [ebp-400h] BYREF

  Buffer = 0;
  memset(v12, 0, sizeof(v12));
  v13 = 0;
  v14 = 0;
  finalLength = 95;
  sprintf(&Buffer, "\\\\%s\\IPC$", a1);         // 최종 결과는 공유 폴더(\\<IP>\IPC$) 경로를 포함한 문자열로 만들어짐 
  v3 = strlen(&Buffer) + 1;
  placeholderPos = searchSubstring_401140(byte_42E494, aUseridPlacehol, 95);
  v10 = placeholderPos;
  if ( placeholderPos )
  {
    v6 = 95 - (placeholderPos - byte_42E494);
    v5 = placeholderPos - byte_42E494;
    qmemcpy(modifiedTemplate, byte_42E494, placeholderPos - byte_42E494);
    v7 = a2[1];
    modifiedTemplate[v5] = *a2;
    modifiedTemplate[v5 + 1] = v7;              // 템플릿 문자열(byte_42E494) 안의 특정 플레이스홀더(aUseridPlacehol, aTreepathReplac)를 주어진 정보(a1, a2)로 교체하여 최종 문자열을 구성 
    qmemcpy(&modifiedTemplate[v5 + 2], &v10[strlen(aUseridPlacehol)], v6 - strlen(aUseridPlacehol));
    finalLength = 97 - strlen(aUseridPlacehol);
  }
  v8 = searchSubstring_401140(modifiedTemplate, aTreepathReplac, finalLength);
  if ( v8 )
  {
    qmemcpy(byte_42E494, modifiedTemplate, v8 - modifiedTemplate);
    qmemcpy(&byte_42E494[v8 - modifiedTemplate], &Buffer, v3);
    qmemcpy(
      &byte_42E494[v8 - modifiedTemplate + v3],
      &v8[strlen(aTreepathReplac)],
      finalLength - (v8 - modifiedTemplate) - strlen(aTreepathReplac));
    finalLength += v3 - strlen(aTreepathReplac);
  }
  byte_42E497 = finalLength - 4;
  return finalLength;
}
