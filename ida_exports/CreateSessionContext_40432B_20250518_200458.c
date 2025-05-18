// --- Metadata ---
// Function Name: CreateSessionContext_40432B
// Address: 0x40432B
// Exported At: 20250518_200458
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl CreateSessionContext_40432B(int a1, int a2, int a3)
{
  _DWORD *sessionContext; // edi
  int v4; // eax
  int v5; // eax

  sessionContext = (*(a1 + 32))(*(a1 + 40), 1, 64);// 구조체 SessionContext를 동적으로 할당하고 초기화 
  if ( !sessionContext )
    return 0;
  v4 = (*(a1 + 32))(*(a1 + 40), 8, 1440);
  sessionContext[9] = v4;
  if ( !v4 )
  {
    (*(a1 + 36))(*(a1 + 40), sessionContext);
    return 0;
  }
  v5 = (*(a1 + 32))(*(a1 + 40), 1, a3);
  sessionContext[10] = v5;
  if ( !v5 )
  {
    (*(a1 + 36))(*(a1 + 40), sessionContext[9]);
    (*(a1 + 36))(*(a1 + 40), sessionContext);
    return 0;
  }
  *sessionContext = 0;
  sessionContext[11] = a3 + v5;
  sessionContext[14] = a2;
  initObject_4042C0(sessionContext, a1, 0);
  return sessionContext;
}
