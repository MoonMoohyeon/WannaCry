// --- Metadata ---
// Function Name: GetStreamOffset_405CDD
// Address: 0x405CDD
// Exported At: 20250520_130349
// Signature: unknown_signature
// ---------------
DWORD __cdecl GetStreamOffset_405CDD(int streamPtr)
{
  DWORD result; // eax

  if ( !*streamPtr )                            // 메모리 블록 모드 
    goto LABEL_6;
  if ( *(streamPtr + 1) )
    return SetFilePointer(*(streamPtr + 4), 0, 0, 1u) - *(streamPtr + 12);// 현재 커서 위치 - 시작 오프셋 
  if ( *streamPtr )
    result = 0;
  else
LABEL_6:
    result = *(streamPtr + 28);
  return result;
}
