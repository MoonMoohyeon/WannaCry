// --- Metadata ---
// Function Name: LoadZipEntryMetadata_406C40
// Address: 0x406C40
// Exported At: 20250518_111457
// Signature: unknown_signature
// ---------------
int __thiscall LoadZipEntryMetadata_406C40(int *this, int entryIndex, void *outEntryInfo)
{
  bool v4; // zf
  void *v6; // eax
  int *v7; // ecx
  unsigned int v8; // eax
  int v9; // eax
  char *i; // edi
  unsigned __int8 v12; // al
  unsigned __int8 *v13; // eax
  bool v14; // al
  char v15; // cl
  unsigned int v16; // edi
  bool v17; // bl
  int v18; // edi
  DWORD v19; // eax
  DWORD v20; // ecx
  bool v21; // cc
  _BYTE *v22; // ebx
  char v23; // al
  char v24; // cl
  bool v25; // al
  int v26; // edi
  int v27; // edx
  unsigned __int8 *v28; // eax
  int v29; // edx
  unsigned __int8 *v30; // eax
  int *v31; // esi
  void *v32; // [esp-8h] [ebp-294h]
  unsigned int v33; // [esp-4h] [ebp-290h]
  char Destination[260]; // [esp+Ch] [ebp-280h] BYREF
  char Source[260]; // [esp+110h] [ebp-17Ch] BYREF
  int v36[4]; // [esp+214h] [ebp-78h] BYREF
  unsigned int v37; // [esp+224h] [ebp-68h]
  int v38; // [esp+22Ch] [ebp-60h]
  int v39; // [esp+230h] [ebp-5Ch]
  int v40; // [esp+248h] [ebp-44h]
  int v41; // [esp+264h] [ebp-28h] BYREF
  FILETIME LocalFileTime; // [esp+268h] [ebp-24h] BYREF
  struct _FILETIME FileTime; // [esp+270h] [ebp-1Ch] BYREF
  int *v44; // [esp+278h] [ebp-14h]
  LONG lDistanceToMove; // [esp+27Ch] [ebp-10h] BYREF
  unsigned int v46; // [esp+280h] [ebp-Ch] BYREF
  char Str1[4]; // [esp+284h] [ebp-8h] BYREF
  bool v48; // [esp+28Bh] [ebp-1h]
  void *Srca; // [esp+298h] [ebp+Ch]
  bool Src_3; // [esp+29Bh] [ebp+Fh]
  bool Src_3a; // [esp+29Bh] [ebp+Fh]

  v44 = this;
  if ( entryIndex >= -1 && entryIndex < *(*this + 4) )// 지정된 ZIP 인덱스에 해당하는 파일의 정보를 로드하여 구조체에 저장
  {
    if ( this[1] != -1 )
      closeSession_406A97(*this);
    v4 = entryIndex == this[77];
    this[1] = -1;
    if ( v4 )
    {
      if ( entryIndex != -1 )
      {
        memcpy(outEntryInfo, this + 2, 0x12Cu);
        return 0;
      }
    }
    else if ( entryIndex != -1 )
    {
      if ( entryIndex < *(*this + 16) )
        initCentralZipIterator_4064E2(*this);
      while ( *(*this + 16) < entryIndex )
        MoveToNextZipEntry_406520(*this);
      callParseZip_4064BB(*this, v36, Source, 260, 0, 0, 0, 0);
      if ( zipHeaderParsing_40657A(*this, &v41, &lDistanceToMove, &v46) )
        return 1792;
      if ( !SeekStreamOffset_405D0E(**this, lDistanceToMove, 0) )
      {
        v6 = operator new(v46);
        v7 = *this;
        *Str1 = v6;
        v8 = readFromReader_405D8A(v6, 1, v46, *v7);
        if ( v8 == v46 )
        {
          v9 = *this;
          *outEntryInfo = *(v9 + 16);
          strcpy(Destination, Source);
          for ( i = Destination; ; i = (v13 + 4) )
          {
            while ( 1 )
            {
              while ( 1 )
              {
                v12 = *i;
                if ( !*i || i[1] != 58 )
                  break;
                i += 2;
              }
              if ( v12 != 92 && v12 != 47 )
                break;
              ++i;
            }
            v13 = mbsstr(i, "\\..\\");          // 경로 탐색 취약점 회피 
            if ( !v13 )
            {
              v13 = mbsstr(i, "\\../");
              if ( !v13 )
              {
                v13 = mbsstr(i, "/../");
                if ( !v13 )
                {
                  v13 = mbsstr(i, "/..\\");
                  if ( !v13 )
                    break;
                }
              }
            }
          }
          strcpy(outEntryInfo + 4, i);
          Src_3 = 0;
          v48 = 0;
          v14 = (v40 & 0x40000000) != 0;
          v15 = (v40 & 0x800000) == 0;
          v16 = v36[0] >> 8;
          v17 = 1;
          if ( !(v36[0] >> 8) || v16 == 7 || v16 == 11 || v16 == 14 )
          {
            Src_3 = (v40 & 2) != 0;
            v15 = v40 & 1;
            v48 = (v40 & 4) != 0;
            v14 = (v40 & 0x10) != 0;
            v17 = (v40 & 0x20) != 0;
          }
          v18 = 0;
          *(outEntryInfo + 66) = 0;
          if ( v14 )
            *(outEntryInfo + 66) = 16;
          if ( v17 )
            *(outEntryInfo + 66) |= 0x20u;
          if ( Src_3 )
            *(outEntryInfo + 66) |= 2u;
          if ( v15 )
            *(outEntryInfo + 66) |= 1u;
          if ( v48 )
            *(outEntryInfo + 66) |= 4u;
          v33 = v37;
          *(outEntryInfo + 73) = v38;
          *(outEntryInfo + 74) = v39;
          LocalFileTime = getTimestamp_406B23(HIWORD(v37), v33);
          LocalFileTimeToFileTime(&LocalFileTime, &FileTime);
          v19 = FileTime.dwLowDateTime;
          v20 = FileTime.dwHighDateTime;
          v21 = v46 <= 4;
          v22 = *Str1;
          *(outEntryInfo + 67) = FileTime.dwLowDateTime;
          *(outEntryInfo + 69) = v19;
          *(outEntryInfo + 71) = v19;
          *(outEntryInfo + 68) = v20;
          *(outEntryInfo + 70) = v20;
          *(outEntryInfo + 72) = v20;
          if ( !v21 )
          {
            while ( 1 )
            {
              Str1[0] = v22[v18];
              v23 = v22[v18 + 1];
              Str1[2] = 0;
              Str1[1] = v23;
              Srca = v22[v18 + 2];
              if ( !strcmp(Str1, "UT") )
                break;
              v18 += Srca + 4;
              if ( v18 + 4 >= v46 )
                goto LABEL_57;
            }
            v24 = v22[v18 + 4];
            v25 = (v24 & 2) != 0;
            v26 = v18 + 5;
            Src_3a = v25;
            v48 = (v24 & 4) != 0;
            if ( (v24 & 1) != 0 )
            {
              v27 = v22[v26 + 1];
              v28 = &v22[v26];
              v26 += 4;
              *(outEntryInfo + 284) = calculateWindowsFileTimeFromUnix_406B02(((v27 | (*(v28 + 1) << 8)) << 8) | *v28);
              v25 = Src_3a;
            }
            if ( v25 )
            {
              v29 = v22[v26 + 1];
              v30 = &v22[v26];
              v26 += 4;
              *(outEntryInfo + 268) = calculateWindowsFileTimeFromUnix_406B02(((v29 | (*(v30 + 1) << 8)) << 8) | *v30);
            }
            if ( v48 )
              *(outEntryInfo + 276) = calculateWindowsFileTimeFromUnix_406B02(((v22[v26 + 1] | (*&v22[v26 + 2] << 8)) << 8) | v22[v26]);
          }
LABEL_57:
          if ( v22 )
            operator delete(v22);
          v32 = outEntryInfo;
          v31 = v44;
          memcpy(v44 + 2, v32, 0x12Cu);
          v31[77] = entryIndex;
          return 0;
        }
        operator delete(*Str1);
      }
      return 2048;
    }
    *outEntryInfo = *(*this + 4);
    *(outEntryInfo + 4) = 0;
    *(outEntryInfo + 66) = 0;
    *(outEntryInfo + 67) = 0;
    *(outEntryInfo + 68) = 0;
    *(outEntryInfo + 69) = 0;
    *(outEntryInfo + 70) = 0;
    *(outEntryInfo + 71) = 0;
    *(outEntryInfo + 72) = 0;
    *(outEntryInfo + 73) = 0;
    *(outEntryInfo + 74) = 0;
    return 0;
  }
  return 0x10000;
}
