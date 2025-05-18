// --- Metadata ---
// Function Name: parseCentralZipEntry_4061E0
// Address: 0x4061E0
// Exported At: 20250518_111311
// Signature: unknown_signature
// ---------------
int __cdecl parseCentralZipEntry_4061E0(int zipContext, int a2, int a3, LPVOID lpBuffer, int a5, LPVOID a6, int a7, LPVOID a8, int a9)
{
  int v11; // eax
  LONG v12; // edx
  int v13; // edi
  int v14; // edi
  LONG v15; // edx
  int v16; // ebx
  int v17[20]; // [esp+8h] [ebp-5Ch] BYREF
  int v18; // [esp+58h] [ebp-Ch] BYREF
  int signature; // [esp+5Ch] [ebp-8h] BYREF
  int status; // [esp+60h] [ebp-4h]
  int zipContexta; // [esp+6Ch] [ebp+8h]

  status = 0;
  if ( !zipContext )
    return -102;
  if ( SeekStreamOffset_405D0E(*zipContext, *(zipContext + 12) + *(zipContext + 20), 0) )
  {
    status = -1;
  }
  else if ( ReadPointerFromStream_405E6B(*zipContext, &signature) )
  {
    status = -1;
  }
  else if ( signature != 33639248 )             // ZIP Central Directory File Header signature MAGIC NUMBER 
  {
    status = -103;
  }
  if ( readLE16_405E27(*zipContext, v17) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[1]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[2]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[3]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[4]) )
    status = -1;
  sub_406191(v17[4], &v17[14]);
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[5]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[6]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[7]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[8]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[9]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[10]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[11]) )
    status = -1;
  if ( readLE16_405E27(*zipContext, &v17[12]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v17[13]) )
    status = -1;
  if ( ReadPointerFromStream_405E6B(*zipContext, &v18) )
    status = -1;
  v11 = v17[8];
  v12 = v17[8];
  zipContexta = v17[8];
  if ( status )
    goto LABEL_61;                              // 파일 읽기 
  if ( lpBuffer )
  {
    if ( v17[8] >= a5 )
    {
      v13 = a5;
    }
    else
    {
      *(lpBuffer + v17[8]) = 0;
      v11 = v17[8];
      v13 = v17[8];
    }
    if ( v11 && a5 && readFromReader_405D8A(lpBuffer, v13, 1, *zipContext) != 1 )
      status = -1;
    v12 = zipContexta - v13;
    zipContexta -= v13;
    if ( status )
      goto LABEL_61;
  }
  if ( !a6 )
  {
LABEL_61:
    v15 = v17[9] + v12;
  }
  else
  {
    v14 = v17[9];
    if ( v17[9] >= a7 )
      v14 = a7;
    if ( v12 )
    {
      if ( SeekStreamOffset_405D0E(*zipContext, v12, 1) )
        status = -1;
      else
        zipContexta = 0;
    }
    if ( v17[9] && a7 && readFromReader_405D8A(a6, v14, 1, *zipContext) != 1 )
      status = -1;
    v15 = v17[9] - v14 + zipContexta;
  }
  if ( !status )
  {
    if ( !a8 )
      goto LABEL_74;
    v16 = a9;
    if ( v17[10] < a9 )
    {
      *(a8 + v17[10]) = 0;
      v16 = v17[10];
    }
    if ( v15 && SeekStreamOffset_405D0E(*zipContext, v15, 1) )
      status = -1;
    if ( v17[10] && a9 && readFromReader_405D8A(a8, v16, 1, *zipContext) != 1 )
      status = -1;
    if ( !status )
    {
LABEL_74:                                       // output 필드에 쓰기 
      if ( a2 )
        qmemcpy(a2, v17, 0x50u);
      if ( a3 )
        *a3 = v18;
    }
  }
  return status;
}
