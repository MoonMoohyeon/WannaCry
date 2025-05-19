// --- Metadata ---
// Function Name: InflateMainLoop_403CFC
// Address: 0x403CFC
// Exported At: 20250519_104441
// Signature: unknown_signature
// ---------------
int __cdecl InflateMainLoop_403CFC(int inflate_state, void *z_stream, int flag)
{
  _BYTE *v5; // edx 압축 해제 메인 루프 
  int v6; // ebx
  unsigned int v7; // eax
  unsigned int v8; // eax
  unsigned __int8 *v9; // ecx
  unsigned int v10; // eax
  unsigned int v11; // eax
  unsigned __int8 *v12; // ecx
  int v13; // eax
  int v14; // eax
  unsigned int v15; // eax
  int v16; // ecx
  int v17; // eax
  unsigned int v18; // eax
  unsigned int v19; // eax
  int v20; // ecx
  int v21; // eax
  unsigned int v22; // ecx
  unsigned int v23; // eax
  unsigned int v24; // ecx
  int v25; // eax
  unsigned int v26; // eax
  unsigned int v27; // ecx
  unsigned int v29; // eax
  unsigned int v30; // ecx
  int v31; // eax
  unsigned int v32; // eax
  unsigned int v33; // ecx
  unsigned __int8 *v34; // ecx
  int result; // eax
  unsigned __int8 *v36; // ecx
  int v37; // eax
  unsigned __int8 *v38; // ebx
  unsigned __int8 *v39; // ecx
  unsigned __int8 *v40; // ecx
  unsigned int v41; // [esp+Ch] [ebp-18h]
  unsigned int v42; // [esp+Ch] [ebp-18h]
  unsigned __int8 *v43; // [esp+10h] [ebp-14h]
  unsigned __int8 *v44; // [esp+10h] [ebp-14h]
  _BYTE *v45; // [esp+10h] [ebp-14h]
  _BYTE *v46; // [esp+10h] [ebp-14h]
  _BYTE *v47; // [esp+14h] [ebp-10h]
  unsigned int v48; // [esp+18h] [ebp-Ch]
  unsigned int v49; // [esp+1Ch] [ebp-8h]
  unsigned __int8 *v50; // [esp+20h] [ebp-4h]
  unsigned int inflate_statea; // [esp+2Ch] [ebp+8h]
  unsigned int Srca; // [esp+30h] [ebp+Ch]

  v50 = *z_stream;
  v5 = *(inflate_state + 52);
  v49 = *(z_stream + 1);
  v6 = *(inflate_state + 4);
  Srca = *(inflate_state + 32);
  inflate_statea = *(inflate_state + 28);
  v7 = *(inflate_state + 48);
  if ( v5 >= v7 )
    v8 = *(inflate_state + 44) - v5;
  else
    v8 = v7 - v5 - 1;
  v48 = v8;
  while ( 2 )
  {
    switch ( *v6 )
    {
      case 0:
        if ( v8 >= 0x102 && v49 >= 0xA )
        {
          *(inflate_state + 32) = Srca;
          *(inflate_state + 28) = inflate_statea;
          *(z_stream + 1) = v49;
          v9 = &v50[-*z_stream];
          *z_stream = v50;
          *(z_stream + 2) += v9;
          *(inflate_state + 52) = v5;
          flag = InflateHuffmanBlock_40514D(*(v6 + 16), *(v6 + 17), *(v6 + 20), *(v6 + 24), inflate_state, z_stream);
          v50 = *z_stream;
          v5 = *(inflate_state + 52);
          v49 = *(z_stream + 1);
          Srca = *(inflate_state + 32);
          inflate_statea = *(inflate_state + 28);
          v10 = *(inflate_state + 48);
          v8 = v5 >= v10 ? *(inflate_state + 44) - v5 : v10 - v5 - 1;
          v48 = v8;
          if ( flag )
          {
            *v6 = flag != 1 ? 9 : 7;
            continue;
          }
        }
        *(v6 + 12) = *(v6 + 16);
        *(v6 + 8) = *(v6 + 20);
        *v6 = 1;
        goto LABEL_14;
      case 1:
LABEL_14:
        while ( 2 )
        {
          v11 = *(v6 + 12);
          if ( inflate_statea < v11 )
          {
            if ( v49 )
            {
              flag = 0;
              --v49;
              Srca |= *v50++ << inflate_statea;
              inflate_statea += 8;
              continue;
            }
            goto LABEL_81;
          }
          break;
        }
        v43 = (*(v6 + 8) + 8 * (Srca & dword_40BCA8[v11]));
        Srca >>= v43[1];
        v12 = v43;
        inflate_statea -= v43[1];
        v13 = *v43;
        if ( !*v43 )
        {
          v14 = *(v43 + 1);
          *v6 = 6;
          *(v6 + 8) = v14;
          goto LABEL_19;
        }
        if ( (v13 & 0x10) != 0 )
        {
          *(v6 + 8) = v13 & 0xF;
          *(v6 + 4) = *(v43 + 1);
          *v6 = 2;
          goto LABEL_19;
        }
        if ( (v13 & 0x40) == 0 )
          goto LABEL_35;
        if ( (v13 & 0x20) == 0 )
        {
          *v6 = 9;
          *(z_stream + 6) = "invalid literal/length code";
LABEL_83:
          *(inflate_state + 32) = Srca;
          *(inflate_state + 28) = inflate_statea;
          *(z_stream + 1) = v49;
          v34 = &v50[-*z_stream];
          *z_stream = v50;
          *(z_stream + 2) += v34;
          *(inflate_state + 52) = v5;
          return copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, -3);
        }
        *v6 = 7;
        goto LABEL_19;
      case 2:
        while ( 2 )
        {
          v15 = *(v6 + 8);
          if ( inflate_statea < v15 )
          {
            if ( v49 )
            {
              flag = 0;
              --v49;
              Srca |= *v50++ << inflate_statea;
              inflate_statea += 8;
              continue;
            }
            goto LABEL_81;
          }
          break;
        }
        v16 = *(v6 + 8);
        v17 = Srca & dword_40BCA8[v15];
        *v6 = 3;
        Srca >>= v16;
        *(v6 + 4) += v17;
        inflate_statea -= v16;
        *(v6 + 12) = *(v6 + 17);
        *(v6 + 8) = *(v6 + 24);
LABEL_29:
        while ( 1 )
        {
          v18 = *(v6 + 12);
          if ( inflate_statea >= v18 )
            break;
          if ( !v49 )
            goto LABEL_81;
          flag = 0;
          --v49;
          Srca |= *v50++ << inflate_statea;
          inflate_statea += 8;
        }
        v44 = (*(v6 + 8) + 8 * (Srca & dword_40BCA8[v18]));
        Srca >>= v44[1];
        v12 = v44;
        inflate_statea -= v44[1];
        v13 = *v44;
        if ( (v13 & 0x10) != 0 )
        {
          *(v6 + 8) = v13 & 0xF;
          *(v6 + 12) = *(v44 + 1);
          *v6 = 4;
        }
        else
        {
          if ( (v13 & 0x40) != 0 )
          {
            *v6 = 9;
            *(z_stream + 6) = "invalid distance code";
            goto LABEL_83;
          }
LABEL_35:
          *(v6 + 12) = v13;
          *(v6 + 8) = &v12[8 * *(v12 + 1)];
        }
LABEL_19:
        v8 = v48;
        continue;
      case 3:
        goto LABEL_29;
      case 4:
LABEL_36:
        v19 = *(v6 + 8);
        if ( inflate_statea >= v19 )
        {
          v20 = *(v6 + 8);
          v21 = Srca & dword_40BCA8[v19];
          *v6 = 5;
          Srca >>= v20;
          *(v6 + 12) += v21;
          inflate_statea -= v20;
LABEL_40:
          v22 = *(inflate_state + 40);
          v47 = &v5[-*(v6 + 12)];
          if ( v47 < v22 )
          {
            do
              v47 += *(inflate_state + 44) - v22;
            while ( v47 < *(inflate_state + 40) );
          }
          v8 = v48;
          if ( *(v6 + 4) )
          {
            while ( 1 )
            {
              if ( !v8 )
              {
                if ( v5 != *(inflate_state + 44)
                  || (v23 = *(inflate_state + 48), v24 = *(inflate_state + 40), v23 == v24)
                  || ((v5 = *(inflate_state + 40), v24 >= v23) ? (v8 = *(inflate_state + 44) - v24) : (v8 = v23 - v24 - 1),
                      !v8) )
                {
                  *(inflate_state + 52) = v5;
                  v25 = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, flag);
                  v5 = *(inflate_state + 52);
                  flag = v25;
                  v26 = *(inflate_state + 48);
                  v41 = v26;
                  if ( v5 >= v26 )
                    v8 = *(inflate_state + 44) - v5;
                  else
                    v8 = v26 - v5 - 1;
                  v45 = *(inflate_state + 44);
                  if ( v5 == v45 )
                  {
                    v27 = *(inflate_state + 40);
                    if ( v41 != v27 )
                    {
                      v5 = *(inflate_state + 40);
                      if ( v27 >= v41 )
                        v8 = &v45[-v27];
                      else
                        v8 = v41 - v27 - 1;
                    }
                  }
                  if ( !v8 )
                    break;
                }
              }
              flag = 0;
              *v5++ = *v47++;
              v48 = --v8;
              if ( v47 == *(inflate_state + 44) )
                v47 = *(inflate_state + 40);
              if ( (*(v6 + 4))-- == 1 )
                goto LABEL_80;
            }
LABEL_85:
            *(inflate_state + 32) = Srca;
            *(inflate_state + 28) = inflate_statea;
            *(z_stream + 1) = v49;
            goto LABEL_86;
          }
LABEL_80:
          *v6 = 0;
          continue;
        }
        if ( v49 )
        {
          flag = 0;
          --v49;
          Srca |= *v50++ << inflate_statea;
          inflate_statea += 8;
          goto LABEL_36;
        }
LABEL_81:
        *(inflate_state + 32) = Srca;
        *(inflate_state + 28) = inflate_statea;
        *(z_stream + 1) = 0;
LABEL_86:
        v36 = &v50[-*z_stream];
        *z_stream = v50;
        *(z_stream + 2) += v36;
        *(inflate_state + 52) = v5;
        return copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, flag);
      case 5:
        goto LABEL_40;
      case 6:
        if ( !v8 )
        {
          if ( v5 != *(inflate_state + 44)
            || (v29 = *(inflate_state + 48), v30 = *(inflate_state + 40), v29 == v30)
            || ((v5 = *(inflate_state + 40), v30 >= v29) ? (v8 = *(inflate_state + 44) - v30) : (v8 = v29 - v30 - 1), !v8) )
          {
            *(inflate_state + 52) = v5;
            v31 = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, flag);
            v5 = *(inflate_state + 52);
            flag = v31;
            v32 = *(inflate_state + 48);
            v42 = v32;
            if ( v5 >= v32 )
              v8 = *(inflate_state + 44) - v5;
            else
              v8 = v32 - v5 - 1;
            v46 = *(inflate_state + 44);
            if ( v5 == v46 )
            {
              v33 = *(inflate_state + 40);
              if ( v42 != v33 )
              {
                v5 = *(inflate_state + 40);
                if ( v33 >= v42 )
                  v8 = &v46[-v33];
                else
                  v8 = v42 - v33 - 1;
              }
            }
            if ( !v8 )
              goto LABEL_85;
          }
        }
        flag = 0;
        *v5++ = *(v6 + 8);
        v48 = --v8;
        goto LABEL_80;
      case 7:
        if ( inflate_statea > 7 )
        {
          inflate_statea -= 8;
          ++v49;
          --v50;
        }
        *(inflate_state + 52) = v5;
        v37 = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, flag);
        v5 = *(inflate_state + 52);
        if ( *(inflate_state + 48) == v5 )
        {
          *v6 = 8;
LABEL_92:
          *(inflate_state + 32) = Srca;
          *(inflate_state + 28) = inflate_statea;
          *(z_stream + 1) = v49;
          v39 = &v50[-*z_stream];
          *z_stream = v50;
          *(z_stream + 2) += v39;
          *(inflate_state + 52) = v5;
          result = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, 1);
        }
        else
        {
          *(inflate_state + 32) = Srca;
          *(inflate_state + 28) = inflate_statea;
          *(z_stream + 1) = v49;
          v38 = &v50[-*z_stream];
          *z_stream = v50;
          *(z_stream + 2) += v38;
          *(inflate_state + 52) = v5;
          result = copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, v37);
        }
        return result;
      case 8:
        goto LABEL_92;
      case 9:
        goto LABEL_83;
      default:
        *(inflate_state + 32) = Srca;
        *(inflate_state + 28) = inflate_statea;
        *(z_stream + 1) = v49;
        v40 = &v50[-*z_stream];
        *z_stream = v50;
        *(z_stream + 2) += v40;
        *(inflate_state + 52) = v5;
        return copyBufferedDataWithCallback_403BD6(inflate_state, z_stream, -2);
    }
  }
}
