// --- Metadata ---
// Function Name: DetermineState_10002E70
// Address: 0x10002E70
// Exported At: 20250522_175237
// Signature: unknown_signature
// ---------------
int __stdcall DetermineState_10002E70(_DWORD *context, unsigned int action)
{
  int statusFlag; // esi
  int v4; // ecx
  int v5; // eax
  int v6; // edi
  bool v7; // zf
  int v8; // eax

  if ( action >= 4 )                            // switch문 상태값 반환 
    return 4;
  statusFlag = context[312];
  if ( !statusFlag )
    return 1;
  if ( action == 3 )
    return 4;
  if ( statusFlag == 5 )
    return 1;
  if ( statusFlag == 4 )
    return 2;
  v4 = context[311];
  v5 = 0;
  v6 = 0;
  v7 = v4 == 0;
  if ( !v4 )
  {
    if ( context[310] <= 0x400u )
      v5 = 1;
    v7 = 1;
  }
  if ( !v7 || context[310] >= 0xC800000u )
    v6 = 1;
  if ( action == 1 )
  {
    if ( statusFlag == 2 )
    {
      if ( v6 )
        return 3;
LABEL_30:
      v8 = -(v5 != 0);
      LOBYTE(v8) = v8 & 0xFD;
      return v8 + 4;
    }
    if ( statusFlag == 3 )
      return 1;
  }
  else if ( action == 2 )
  {
    if ( statusFlag == 2 )
      return 1;
    if ( statusFlag == 3 )
    {
      if ( v6 )
        return 3;
      goto LABEL_30;
    }
  }
  return 0;
}
