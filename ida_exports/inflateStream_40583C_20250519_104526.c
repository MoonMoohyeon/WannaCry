// --- Metadata ---
// Function Name: inflateStream_40583C
// Address: 0x40583C
// Exported At: 20250519_104526
// Signature: unknown_signature
// ---------------
int __cdecl inflateStream_40583C(void *z_stream, int flag)
{
  int *v2; // eax zlib inflate 상태 기계에 기반한 압축 해제 과정 
  int v3; // ebx
  int v4; // ecx
  int v5; // ecx
  _DWORD *v6; // eax
  int v7; // ecx
  int v8; // eax
  _DWORD *v9; // ecx
  int v10; // ebx
  int v11; // eax
  int v12; // eax
  _DWORD *v13; // eax
  int v14; // eax
  int v15; // ecx
  _DWORD *v16; // eax
  int v17; // eax
  unsigned __int8 *v18; // ecx
  _DWORD *v19; // eax
  int v20; // eax
  unsigned __int8 *v21; // ecx
  _DWORD *v22; // eax
  int v23; // eax
  unsigned __int8 *v24; // ecx
  _DWORD *v25; // eax
  int v27; // eax
  int v28; // ecx
  _DWORD *v29; // eax
  int v30; // eax
  unsigned __int8 *v31; // ecx
  _DWORD *v32; // eax
  int v33; // eax
  unsigned __int8 *v34; // ecx
  _DWORD *v35; // eax
  int v36; // eax
  unsigned __int8 *v37; // ecx
  _DWORD *v38; // eax
  int v39; // eax
  int v40; // [esp-4h] [ebp-10h]
  int flaga; // [esp+18h] [ebp+Ch]

  if ( !z_stream )
    return -2;
  v2 = *(z_stream + 7);
  if ( !v2 || !*z_stream )
    return -2;
  v3 = -5;
  if ( flag == 4 )
    flaga = -5;
  else
    flaga = 0;
  v4 = *v2;
  while ( 2 )
  {
    switch ( v4 )
    {
      case 0:
        v5 = *(z_stream + 1);
        if ( !v5 )
          return v3;
        ++*(z_stream + 2);
        *(z_stream + 1) = v5 - 1;
        v3 = flaga;
        v2[1] = **z_stream;
        v6 = *(z_stream + 7);
        v7 = v6[1] & 0xF;
        ++*z_stream;
        if ( v7 != 8 )
        {
          *v6 = 13;
          *(z_stream + 6) = "unknown compression method";
          goto LABEL_37;
        }
        if ( ((v6[1] >> 4) + 8) > v6[4] )
        {
          *v6 = 13;
          *(z_stream + 6) = "invalid window size";
          goto LABEL_37;
        }
        *v6 = 1;
LABEL_15:
        v8 = *(z_stream + 1);
        if ( !v8 )
          return v3;
        ++*(z_stream + 2);
        *(z_stream + 1) = v8 - 1;
        v9 = *(z_stream + 7);
        v10 = *(*z_stream)++;
        if ( (v10 + (v9[1] << 8)) % 0x1Fu )
        {
          v3 = flaga;
          *v9 = 13;
          v11 = *(z_stream + 7);
          *(z_stream + 6) = "incorrect header check";
          *(v11 + 4) = 5;
        }
        else
        {
          if ( (v10 & 0x20) != 0 )
          {
            v3 = flaga;
            **(z_stream + 7) = 2;
LABEL_41:
            v27 = *(z_stream + 1);
            if ( v27 )
            {
              ++*(z_stream + 2);
              v28 = *(z_stream + 7);
              *(z_stream + 1) = v27 - 1;
              v3 = flaga;
              *(v28 + 8) = **z_stream << 24;
              v29 = *(z_stream + 7);
              ++*z_stream;
              *v29 = 3;
LABEL_43:
              v30 = *(z_stream + 1);
              if ( v30 )
              {
                v31 = *z_stream;
                ++*(z_stream + 2);
                *(z_stream + 1) = v30 - 1;
                v3 = flaga;
                *(*(z_stream + 7) + 8) += *v31 << 16;
                v32 = *(z_stream + 7);
                ++*z_stream;
                *v32 = 4;
LABEL_45:
                v33 = *(z_stream + 1);
                if ( v33 )
                {
                  v34 = *z_stream;
                  ++*(z_stream + 2);
                  *(z_stream + 1) = v33 - 1;
                  v3 = flaga;
                  *(*(z_stream + 7) + 8) += *v34 << 8;
                  v35 = *(z_stream + 7);
                  ++*z_stream;
                  *v35 = 5;
LABEL_47:
                  v36 = *(z_stream + 1);
                  if ( v36 )
                  {
                    v37 = *z_stream;
                    ++*(z_stream + 2);
                    *(z_stream + 1) = v36 - 1;
                    v40 = 2;
                    *(*(z_stream + 7) + 8) += *v37;
                    v38 = *(z_stream + 7);
                    ++*z_stream;
                    *(z_stream + 12) = v38[2];
                    *v38 = 6;
                    return v40;
                  }
                }
              }
            }
            return v3;
          }
          v3 = flaga;
          *v9 = 7;
        }
        goto LABEL_38;
      case 1:
        goto LABEL_15;
      case 2:
        goto LABEL_41;
      case 3:
        goto LABEL_43;
      case 4:
        goto LABEL_45;
      case 5:
        goto LABEL_47;
      case 6:
        **(z_stream + 7) = 13;
        v39 = *(z_stream + 7);
        *(z_stream + 6) = "need dictionary";
        *(v39 + 4) = 0;
        return -2;
      case 7:
        v12 = inflateCompressedBlock_4043B6(v2[5], z_stream, v3);
        v3 = v12;
        if ( v12 == -3 )
        {
          **(z_stream + 7) = 13;
          *(*(z_stream + 7) + 4) = 0;
          goto LABEL_38;
        }
        if ( !v12 )
          v3 = flaga;
        if ( v3 != 1 )
          return v3;
        v3 = flaga;
        initObject_4042C0(*(*(z_stream + 7) + 20), z_stream, (*(z_stream + 7) + 4));
        v13 = *(z_stream + 7);
        if ( v13[3] )
        {
          *v13 = 12;
          goto LABEL_38;
        }
        *v13 = 8;
LABEL_28:
        v14 = *(z_stream + 1);
        if ( !v14 )
          return v3;
        ++*(z_stream + 2);
        v15 = *(z_stream + 7);
        *(z_stream + 1) = v14 - 1;
        v3 = flaga;
        *(v15 + 8) = **z_stream << 24;
        v16 = *(z_stream + 7);
        ++*z_stream;
        *v16 = 9;
LABEL_30:
        v17 = *(z_stream + 1);
        if ( !v17 )
          return v3;
        v18 = *z_stream;
        ++*(z_stream + 2);
        *(z_stream + 1) = v17 - 1;
        v3 = flaga;
        *(*(z_stream + 7) + 8) += *v18 << 16;
        v19 = *(z_stream + 7);
        ++*z_stream;
        *v19 = 10;
LABEL_32:
        v20 = *(z_stream + 1);
        if ( !v20 )
          return v3;
        v21 = *z_stream;
        ++*(z_stream + 2);
        *(z_stream + 1) = v20 - 1;
        v3 = flaga;
        *(*(z_stream + 7) + 8) += *v21 << 8;
        v22 = *(z_stream + 7);
        ++*z_stream;
        *v22 = 11;
LABEL_34:
        v23 = *(z_stream + 1);
        if ( !v23 )
          return v3;
        v24 = *z_stream;
        ++*(z_stream + 2);
        *(z_stream + 1) = v23 - 1;
        v3 = flaga;
        *(*(z_stream + 7) + 8) += *v24;
        v25 = *(z_stream + 7);
        ++*z_stream;
        if ( v25[1] != v25[2] )
        {
          *v25 = 13;
          *(z_stream + 6) = "incorrect data check";
LABEL_37:
          *(*(z_stream + 7) + 4) = 5;
LABEL_38:
          v2 = *(z_stream + 7);
          v4 = *v2;
          continue;
        }
        **(z_stream + 7) = 12;
        return 1;
      case 8:
        goto LABEL_28;
      case 9:
        goto LABEL_30;
      case 10:
        goto LABEL_32;
      case 11:
        goto LABEL_34;
      case 12:
        return 1;
      case 13:
        return -3;
      default:
        return -2;
    }
  }
}
