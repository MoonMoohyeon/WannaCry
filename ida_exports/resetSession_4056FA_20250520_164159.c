// --- Metadata ---
// Function Name: resetSession_4056FA
// Address: 0x4056FA
// Exported At: 20250520_164159
// Signature: unknown_signature
// ---------------
int __cdecl resetSession_4056FA(_DWORD *sessionContext)
{
  _DWORD *v1; // ecx

  if ( !sessionContext )                        // 전달받은 구조체를 초기화함 
    return -2;
  v1 = sessionContext[7];
  if ( !v1 )
    return -2;
  sessionContext[5] = 0;
  sessionContext[2] = 0;
  sessionContext[6] = 0;
  *v1 = v1[3] != 0 ? 7 : 0;
  initObject_4042C0(*(sessionContext[7] + 20), sessionContext, 0);
  return 0;
}
