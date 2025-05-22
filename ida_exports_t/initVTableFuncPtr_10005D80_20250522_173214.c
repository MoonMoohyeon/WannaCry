// --- Metadata ---
// Function Name: initVTableFuncPtr_10005D80
// Address: 0x10005D80
// Exported At: 20250522_173214
// Signature: unknown_signature
// ---------------
_BYTE *__thiscall initVTableFuncPtr_10005D80(_BYTE *byteFieldObject)
{
  _BYTE *initializedObj; // eax

  initializedObj = byteFieldObject;             // 가상 함수 테이블 포인터를 설정 
  byteFieldObject[4] = 0;
  *(_DWORD *)byteFieldObject = &off_1000ACBC;
  return initializedObj;
}
