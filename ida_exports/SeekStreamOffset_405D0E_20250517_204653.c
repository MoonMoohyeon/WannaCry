// --- Metadata ---
// Function Name: SeekStreamOffset_405D0E
// Address: 0x405D0E
// Exported At: 20250517_204653
// Signature: unknown_signature
// ---------------
int __cdecl SeekStreamOffset_405D0E(int streamObject, LONG offset, int origin)
{
  LONG v4; // ecx
  DWORD v5; // [esp-4h] [ebp-4h]

  if ( !*streamObject )                         // 파일 또는 메모리 스트림의 현재 위치 이동 시키기 
    goto MEMORY_STREAM_LABEL;
  if ( !*(streamObject + 1) )
  {
    if ( *streamObject )
      return 29;
MEMORY_STREAM_LABEL:
    if ( origin )
    {
      if ( origin == 1 )                        // FILE Current 
      {
        *(streamObject + 28) += offset;
        return 0;
      }
      if ( origin != 2 )                        // FILE End
        return 0;
      v4 = offset + *(streamObject + 24);
    }
    else                                        // FILE Begin 
    {
      v4 = offset;
    }
    *(streamObject + 28) = v4;
    return 0;
  }
  if ( origin )
  {
    if ( origin == 1 )
    {
      v5 = 1;
FILE_SEEK_LABEL:                                // 파일 스트림 처리 
      SetFilePointer(*(streamObject + 4), offset, 0, v5);
      return 0;
    }
    if ( origin == 2 )
    {
      v5 = 2;
      goto FILE_SEEK_LABEL;
    }
    return 19;
  }
  SetFilePointer(*(streamObject + 4), offset + *(streamObject + 12), 0, 0);
  return 0;
}
