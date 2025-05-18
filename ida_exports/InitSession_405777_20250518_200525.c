// --- Metadata ---
// Function Name: InitSession_405777
// Address: 0x405777
// Exported At: 20250518_200525
// Signature: unknown_signature
// ---------------
BOOL __stdcall InitSession_405777(DWORD session)
{
  bool v1; // zf
  int v2; // eax

  if ( !"1.1.3" )                               // 압축/해제 세션 객체 설정 준비 
    return -6;
  if ( !session )                               // 세션 객체 검증 
    return -2;
  v1 = *(session + 32) == 0;
  *(session + 24) = 0;
  if ( v1 )                                     // 메모리 할당 
  {
    *(session + 32) = callocWrapper_4056DD;
    *(session + 40) = 0;
  }
  if ( !*(session + 36) )
    *(session + 36) = freeWrapper_4056EE;
  v2 = (*(session + 32))(*(session + 40), 1, 24);// 세션 구조체 할당 
  *(session + 28) = v2;
  if ( v2 )                                     // 구조체 필드 설정 
  {
    *(v2 + 20) = 0;
    *(*(session + 28) + 12) = 0;
    *(*(session + 28) + 12) = 1;
    *(*(session + 28) + 16) = 15;
    *(*(session + 28) + 20) = CreateSessionContext_40432B(
                                session,
                                *(*(session + 28) + 12) == 0 ? calculateAdler32Hash_4055C4 : 0,
                                0x8000);        // 내부 버퍼 및 해시 설정 
    if ( *(*(session + 28) + 20) )              // 성공 시 추가 초기화 
    {
      resetSession_4056FA(session);
      return 0;
    }
    cleanUpSession_405739(session);             // 실패 시 정리 
  }
  return -4;
}
