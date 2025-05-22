// --- Metadata ---
// Function Name: WStringAssign_10003810
// Address: 0x10003810
// Exported At: 20250522_174936
// Signature: unknown_signature
// ---------------
void __cdecl WStringAssign_10003810(int destWstring, char *srcWstring)
{
  char firstChar; // al
  unsigned int srcLength; // edi
  unsigned int newPos; // ebx
  unsigned int remainLength; // eax
  unsigned int grownLength; // edi
  LPCWSTR srcData; // eax
  LPCWSTR srcData_1; // eax
  LPCWSTR srcData_2; // ecx
  _WORD *destBuffer; // eax
  unsigned int copyLength; // edx
  __int16 curChar; // bx
  int destDataAddr; // edx

  if ( destWstring )                            // std::wstring의 복사 또는 초기화 함수 
  {
    firstChar = *srcWstring;
    *(_DWORD *)(destWstring + 4) = 0;
    *(_BYTE *)destWstring = firstChar;
    *(_DWORD *)(destWstring + 8) = 0;
    *(_DWORD *)(destWstring + 12) = 0;
    srcLength = *((_DWORD *)srcWstring + 2);
    if ( std::wstring::npos < srcLength )
      srcLength = std::wstring::npos;
    if ( (char *)destWstring == srcWstring )
    {
      newPos = std::wstring::npos;
      if ( srcLength )
        std::_Xran();
      std::wstring::_Split(destWstring);
      remainLength = *(_DWORD *)(destWstring + 8) - srcLength;
      if ( remainLength < std::wstring::npos )
        newPos = *(_DWORD *)(destWstring + 8) - srcLength;
      if ( newPos )
      {
        wmemmove(
          (wchar_t *)(*(_DWORD *)(destWstring + 4) + 2 * srcLength),
          (const wchar_t *)(*(_DWORD *)(destWstring + 4) + 2 * (newPos + srcLength)),
          remainLength - newPos);
        grownLength = *(_DWORD *)(destWstring + 8) - newPos;
        if ( (unsigned __int8)std::wstring::_Grow(destWstring, grownLength, 0) )
          std::wstring::_Eos(destWstring, grownLength);
      }
      std::wstring::_Split(destWstring);
    }
    else
    {
      if ( !srcLength || srcLength != *((_DWORD *)srcWstring + 2) )
        goto LABEL_30;
      srcData = (LPCWSTR)*((_DWORD *)srcWstring + 1);
      if ( !srcData )
        srcData = `std::wstring::_Nullstr'::`2'::_C;
      if ( *((_BYTE *)srcData - 1) < 0xFEu )
      {
        std::wstring::_Tidy(destWstring, 1);
        srcData_1 = (LPCWSTR)*((_DWORD *)srcWstring + 1);
        if ( !srcData_1 )
          srcData_1 = `std::wstring::_Nullstr'::`2'::_C;
        *(_DWORD *)(destWstring + 4) = srcData_1;
        *(_DWORD *)(destWstring + 8) = *((_DWORD *)srcWstring + 2);
        *(_DWORD *)(destWstring + 12) = *((_DWORD *)srcWstring + 3);
        ++*((_BYTE *)srcData_1 - 1);
      }
      else
      {
LABEL_30:
        if ( (unsigned __int8)std::wstring::_Grow(destWstring, srcLength, 1) )
        {
          srcData_2 = (LPCWSTR)*((_DWORD *)srcWstring + 1);
          if ( !srcData_2 )
            srcData_2 = `std::wstring::_Nullstr'::`2'::_C;
          destBuffer = *(_WORD **)(destWstring + 4);
          if ( srcLength )
          {
            copyLength = srcLength;
            do
            {
              curChar = *srcData_2++;
              *destBuffer++ = curChar;
              --copyLength;
            }
            while ( copyLength );
          }
          destDataAddr = *(_DWORD *)(destWstring + 4);
          *(_DWORD *)(destWstring + 8) = srcLength;
          *(_WORD *)(destDataAddr + 2 * srcLength) = 0;
        }
      }
    }
  }
}
