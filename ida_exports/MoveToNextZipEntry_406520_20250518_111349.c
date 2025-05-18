// --- Metadata ---
// Function Name: MoveToNextZipEntry_406520
// Address: 0x406520
// Exported At: 20250518_111349
// Signature: unknown_signature
// ---------------
int __cdecl MoveToNextZipEntry_406520(_DWORD *zipContext)
{
  int v1; // eax
  int result; // eax
  int v3; // edx
  int v4; // ecx

  if ( !zipContext )
    return -102;
  if ( !zipContext[6] )                         // 내용이 없거나 끝까지 읽음 
    return -100;
  v1 = zipContext[4] + 1;
  if ( v1 == zipContext[1] )
    return -100;
  v3 = zipContext[18];
  v4 = zipContext[19] + zipContext[20];         // 인덱스와 엔트리 업데이트 
  zipContext[4] = v1;
  zipContext[5] += v4 + v3 + 46;
  result = parseCentralZipEntry_4061E0(zipContext, (zipContext + 10), (zipContext + 30), 0, 0, 0, 0, 0, 0);
  zipContext[6] = result == 0;
  return result;
}
