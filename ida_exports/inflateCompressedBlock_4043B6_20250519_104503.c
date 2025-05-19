// --- Metadata ---
// Function Name: inflateCompressedBlock_4043B6
// Address: 0x4043B6
// Exported At: 20250519_104503
// Signature: unknown_signature
// ---------------
int __cdecl inflateCompressedBlock_4043B6(int state, void *Src, int a3)
{
  void *v5; // edx  비트 스트림 디코딩 및 블록 압축 해제 
  unsigned __int8 *v6; // ebx
  unsigned int v7; // eax
  int v8; // ecx
  int v9; // eax
  int v10; // eax
  int v11; // eax
  int v12; // eax
  int v13; // eax
  int v14; // eax
  int v15; // eax
  int v16; // ecx
  unsigned int v17; // ecx
  int v18; // eax
  void *v19; // ecx
  unsigned int v20; // eax
  unsigned int v21; // edx
  int v22; // eax
  unsigned int v23; // ecx
  void *v24; // edx
  unsigned int v25; // eax
  unsigned int v26; // ecx
  int v27; // eax
  unsigned int v28; // eax
  unsigned int v29; // ecx
  int v30; // eax
  unsigned int i; // ecx
  int v32; // eax
  int v33; // eax
  unsigned int v34; // ecx
  unsigned int v35; // eax
  int v36; // edx
  int v37; // ecx
  int v38; // eax
  size_t v39; // ecx
  int v40; // eax
  int v41; // edx
  int v42; // ecx
  int v43; // eax
  unsigned int v44; // eax
  int v45; // eax
  unsigned __int8 *v46; // eax
  int v47; // eax
  void *v48; // ecx
  unsigned int v49; // eax
  int v50; // eax
  unsigned __int8 *v51; // eax
  int result; // eax
  unsigned int v53; // eax
  unsigned __int8 *v54; // eax
  unsigned __int8 *v55; // eax
  bool v56; // zf
  unsigned __int8 *v57; // eax
  unsigned __int8 *v58; // eax
  unsigned __int8 *v59; // eax
  unsigned __int8 *v60; // ecx
  unsigned __int8 *v61; // eax
  int *v62; // [esp-1Ch] [ebp-54h]
  int *v63; // [esp-14h] [ebp-4Ch]
  int v64; // [esp-8h] [ebp-40h]
  int v65; // [esp-8h] [ebp-40h]
  int v66; // [esp-4h] [ebp-3Ch]
  int v67; // [esp+Ch] [ebp-2Ch] BYREF
  int v68; // [esp+10h] [ebp-28h] BYREF
  int v69; // [esp+14h] [ebp-24h] BYREF
  int v70; // [esp+18h] [ebp-20h] BYREF
  int v71; // [esp+1Ch] [ebp-1Ch] BYREF
  int v72; // [esp+20h] [ebp-18h] BYREF
  unsigned int v73; // [esp+24h] [ebp-14h] BYREF
  size_t v74; // [esp+28h] [ebp-10h] BYREF
  size_t Size; // [esp+2Ch] [ebp-Ch]
  void *v76; // [esp+30h] [ebp-8h]
  size_t v77; // [esp+34h] [ebp-4h]
  unsigned int statea; // [esp+40h] [ebp+8h]
  unsigned int stateb; // [esp+40h] [ebp+8h]
  unsigned int Srca; // [esp+44h] [ebp+Ch]
  void *Srcb; // [esp+44h] [ebp+Ch]

  v5 = *(state + 52);
  v6 = *Src;
  v77 = *(Src + 1);
  statea = *(state + 32);
  Srca = *(state + 28);
  v7 = *(state + 48);
  v76 = v5;
  if ( v5 >= v7 )
    v8 = *(state + 44) - v5;
  else
    v8 = v7 - v5 - 1;
  v9 = *state;
  v74 = v8;
  while ( 2 )
  {
    switch ( v9 )
    {
      case 0:
        while ( Srca < 3 )
        {
          if ( !v77 )
            goto LABEL_106;
          v10 = *v6;
          a3 = 0;
          --v77;
          statea |= v10 << Srca;
          ++v6;
          Srca += 8;
        }
        v11 = (statea & 7) >> 1;
        *(state + 24) = statea & 1;
        if ( !v11 )
        {
          Srcb = (Srca - 3);
          *state = 1;
          v16 = Srcb & 7;
          Srca = Srcb - v16;
          statea = statea >> 3 >> v16;
          goto LABEL_98;
        }
        v12 = v11 - 1;
        if ( v12 )
        {
          v13 = v12 - 1;
          if ( !v13 )
          {
            statea >>= 3;
            v14 = 3;
            Srca -= 3;
            goto LABEL_16;
          }
          if ( v13 != 1 )
            goto LABEL_98;
          *state = 9;
          *(Src + 6) = "invalid block type";
          *(state + 32) = statea >> 3;
          v53 = Srca - 3;
          goto LABEL_104;
        }
        initTable_405122(&v69, &v70, &v71, &v72);
        v15 = initObject_403CC8(v69, v70, v71, v72, Src);
        *(state + 4) = v15;
        if ( !v15 )
          goto LABEL_115;
        statea >>= 3;
        Srca -= 3;
        *state = 6;
        goto LABEL_98;
      case 1:
        v17 = Srca;
        while ( 2 )
        {
          if ( v17 < 0x20 )
          {
            if ( v77 )
            {
              v18 = *v6;
              a3 = 0;
              --v77;
              statea |= v18 << v17;
              ++v6;
              v17 += 8;
              Srca = v17;
              continue;
            }
LABEL_106:
            *(state + 32) = statea;
            *(state + 28) = Srca;
            *(Src + 1) = 0;
            goto LABEL_107;
          }
          break;
        }
        if ( statea != ~statea >> 16 )
        {
          *state = 9;
          *(Src + 6) = "invalid stored block lengths";
          goto LABEL_103;
        }
        *(state + 4) = statea;
        Srca = 0;
        statea = 0;
        if ( *(state + 4) )
          v14 = 2;
        else
LABEL_49:
          v14 = *(state + 24) != 0 ? 7 : 0;
LABEL_16:
        *state = v14;
        goto LABEL_98;
      case 2:
        if ( !v77 )
          goto LABEL_106;
        if ( !v8 )
        {
          if ( (v19 = *(state + 44), v5 != v19)
            || (v20 = *(state + 48), v21 = *(state + 40), v21 == v20)
            || ((v76 = *(state + 40), v21 >= v20) ? (v74 = v19 - v21) : (v74 = v20 - v21 - 1), !v74) )
          {
            *(state + 52) = v76;
            v22 = copyBufferedDataWithCallback_403BD6(state, Src, a3);
            v23 = *(state + 48);
            a3 = v22;
            v76 = *(state + 52);
            if ( v76 >= v23 )
              v74 = *(state + 44) - v76;
            else
              v74 = v23 - v76 - 1;
            v24 = *(state + 44);
            if ( v76 == v24 )
            {
              v25 = *(state + 40);
              if ( v25 != v23 )
              {
                v76 = *(state + 40);
                if ( v25 >= v23 )
                  v74 = v24 - v25;
                else
                  v74 = v23 - v25 - 1;
              }
            }
            if ( !v74 )
            {
              *(state + 32) = statea;
              *(state + 28) = Srca;
              *(Src + 1) = v77;
LABEL_107:
              v55 = &v6[-*Src];
              *Src = v6;
              *(Src + 2) += v55;
              *(state + 52) = v76;
              return copyBufferedDataWithCallback_403BD6(state, Src, a3);
            }
          }
        }
        a3 = 0;
        Size = *(state + 4);
        if ( Size > v77 )
          Size = v77;
        if ( Size > v74 )
          Size = v74;
        memcpy(v76, v6, Size);
        v77 -= Size;
        v76 = v76 + Size;
        v74 -= Size;
        v6 += Size;
        v56 = *(state + 4) == Size;
        *(state + 4) -= Size;
        if ( v56 )
          goto LABEL_49;
        goto LABEL_98;
      case 3:
        v26 = Srca;
        while ( 2 )
        {
          if ( v26 < 0xE )
          {
            if ( v77 )
            {
              v27 = *v6;
              a3 = 0;
              --v77;
              statea |= v27 << v26;
              ++v6;
              v26 += 8;
              Srca = v26;
              continue;
            }
            goto LABEL_106;
          }
          break;
        }
        v28 = statea & 0x3FFF;
        *(state + 4) = v28;
        v29 = statea & 0x1F;
        if ( v29 > 0x1D || (statea & 0x3E0) > 0x3A0 )
        {
          *state = 9;
          *(Src + 6) = "too many length or distance symbols";
LABEL_103:
          *(state + 32) = statea;
          v53 = Srca;
LABEL_104:
          *(state + 28) = v53;
          *(Src + 1) = v77;
          v54 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v54;
          *(state + 52) = v76;
          return copyBufferedDataWithCallback_403BD6(state, Src, -3);
        }
        v30 = (*(Src + 8))(*(Src + 10), ((v28 >> 5) & 0x1F) + v29 + 258, 4);
        *(state + 12) = v30;
        if ( !v30 )
          goto LABEL_115;
        statea >>= 14;
        Srca -= 14;
        *(state + 8) = 0;
        *state = 4;
LABEL_58:
        if ( *(state + 8) < ((*(state + 4) >> 10) + 4) )
        {
          do
          {
            for ( i = Srca; i < 3; Srca = i )
            {
              if ( !v77 )
                goto LABEL_106;
              v32 = *v6;
              a3 = 0;
              --v77;
              statea |= v32 << i;
              ++v6;
              i += 8;
            }
            v33 = statea & 7;
            Srca -= 3;
            statea >>= 3;
            *(*(state + 12) + 4 * dword_40CDF0[*(state + 8)]) = v33;
            v34 = *(state + 4);
            ++*(state + 8);
          }
          while ( *(state + 8) < (v34 >> 10) + 4 );
        }
        while ( *(state + 8) < 0x13u )
          *(*(state + 12) + 4 * dword_40CDF0[(*(state + 8))++]) = 0;
        v64 = *(state + 36);
        v63 = *(state + 12);
        *(state + 16) = 7;
        Size = buildDynamicHuffmanTree_404FA0(v63, (state + 16), (state + 20), v64, Src);
        if ( Size )
        {
          v56 = Size == -3;
LABEL_112:
          if ( v56 )
          {
            (*(Src + 9))(*(Src + 10));
            *state = 9;
          }
          v66 = Size;
          *(state + 32) = statea;
          *(state + 28) = Srca;
          *(Src + 1) = v77;
          v58 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v58;
          *(state + 52) = v76;
          return copyBufferedDataWithCallback_403BD6(state, Src, v66);
        }
        *(state + 8) = 0;
        *state = 5;
LABEL_68:
        while ( *(state + 8) < ((*(state + 4) >> 5) & 0x1F) + (*(state + 4) & 0x1Fu) + 258 )
        {
          v35 = *(state + 16);
          while ( Srca < v35 )
          {
            if ( !v77 )
              goto LABEL_106;
            v36 = *v6;
            a3 = 0;
            --v77;
            statea |= v36 << Srca;
            ++v6;
            Srca += 8;
          }
          v37 = *(state + 20);
          v38 = statea & dword_40BCA8[v35];
          v73 = *(v37 + 8 * v38 + 4);
          v39 = *(v37 + 8 * v38 + 1);
          Size = v39;
          if ( v73 >= 0x10 )
          {
            if ( v73 == 18 )
              v40 = 7;
            else
              v40 = v73 - 14;
            v74 = v73 != 18 ? 3 : 11;
            while ( Srca < v40 + Size )
            {
              if ( !v77 )
                goto LABEL_106;
              v41 = *v6;
              a3 = 0;
              --v77;
              statea |= v41 << Srca;
              ++v6;
              Srca += 8;
            }
            stateb = statea >> Size;
            v74 += stateb & dword_40BCA8[v40];
            statea = stateb >> v40;
            v42 = *(state + 8);
            Srca -= Size + v40;
            if ( v42 + v74 > ((*(state + 4) >> 5) & 0x1F) + (*(state + 4) & 0x1Fu) + 258 )
            {
LABEL_110:
              (*(Src + 9))(*(Src + 10), *(state + 12));
              *state = 9;
              *(Src + 6) = "invalid bit length repeat";
              *(state + 32) = statea;
              *(state + 28) = Srca;
              *(Src + 1) = v77;
              v57 = &v6[-*Src];
              *Src = v6;
              *(Src + 2) += v57;
              *(state + 52) = v76;
              return copyBufferedDataWithCallback_403BD6(state, Src, -3);
            }
            if ( v73 == 16 )
            {
              if ( !v42 )
                goto LABEL_110;
              v43 = *(*(state + 12) + 4 * v42 - 4);
            }
            else
            {
              v43 = 0;
            }
            do
            {
              *(*(state + 12) + 4 * v42++) = v43;
              --v74;
            }
            while ( v74 );
            *(state + 8) = v42;
          }
          else
          {
            statea >>= v39;
            Srca -= v39;
            *(*(state + 12) + 4 * (*(state + 8))++) = v73;
          }
        }
        v65 = *(state + 36);
        v44 = *(state + 4);
        *(state + 20) = 0;
        v73 = 9;
        v62 = *(state + 12);
        v74 = 6;
        Size = BuildDynamicHuffmanTrees_40501F(
                 (v44 & 0x1F) + 257,
                 ((v44 >> 5) & 0x1F) + 1,
                 v62,
                 &v73,
                 &v74,
                 &v67,
                 &v68,
                 v65,
                 Src);
        if ( Size )
        {
          v56 = Size == -3;
          goto LABEL_112;
        }
        v45 = initObject_403CC8(v73, v74, v67, v68, Src);
        if ( !v45 )
        {
LABEL_115:
          *(state + 32) = statea;
          *(state + 28) = Srca;
          *(Src + 1) = v77;
          v59 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v59;
          *(state + 52) = v76;
          return copyBufferedDataWithCallback_403BD6(state, Src, -4);
        }
        *(state + 4) = v45;
        (*(Src + 9))(*(Src + 10));
        *state = 6;
LABEL_92:
        *(state + 32) = statea;
        *(state + 28) = Srca;
        *(Src + 1) = v77;
        v46 = &v6[-*Src];
        *Src = v6;
        *(Src + 2) += v46;
        *(state + 52) = v76;
        v47 = InflateMainLoop_403CFC(state, Src, a3);
        if ( v47 != 1 )
          goto LABEL_119;
        a3 = 0;
        retFuncPointer_4042AF(*(state + 4), Src);
        v6 = *Src;
        v77 = *(Src + 1);
        statea = *(state + 32);
        v48 = *(state + 52);
        Srca = *(state + 28);
        v49 = *(state + 48);
        v76 = v48;
        if ( v48 >= v49 )
          v50 = *(state + 44) - v76;
        else
          v50 = v49 - v48 - 1;
        v56 = *(state + 24) == 0;
        v74 = v50;
        if ( v56 )
        {
          *state = 0;
LABEL_98:
          v9 = *state;
          if ( *state > 9u )
          {
LABEL_99:
            *(state + 32) = statea;
            *(state + 28) = Srca;
            *(Src + 1) = v77;
            v51 = &v6[-*Src];
            *Src = v6;
            *(Src + 2) += v51;
            *(state + 52) = v76;
            return copyBufferedDataWithCallback_403BD6(state, Src, -2);
          }
          v8 = v74;
          v5 = v76;
          continue;
        }
        *state = 7;
LABEL_117:
        *(state + 52) = v76;
        v47 = copyBufferedDataWithCallback_403BD6(state, Src, a3);
        v56 = *(state + 48) == *(state + 52);
        v76 = *(state + 52);
        if ( v56 )
        {
          *state = 8;
LABEL_121:
          *(state + 32) = statea;
          *(state + 28) = Srca;
          *(Src + 1) = v77;
          v61 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v61;
          *(state + 52) = v76;
          result = copyBufferedDataWithCallback_403BD6(state, Src, 1);
        }
        else
        {
          *(state + 32) = statea;
          *(state + 28) = Srca;
          *(Src + 1) = v77;
          v60 = &v6[-*Src];
          *Src = v6;
          *(Src + 2) += v60;
          *(state + 52) = v76;
LABEL_119:
          result = copyBufferedDataWithCallback_403BD6(state, Src, v47);
        }
        return result;
      case 4:
        goto LABEL_58;
      case 5:
        goto LABEL_68;
      case 6:
        goto LABEL_92;
      case 7:
        goto LABEL_117;
      case 8:
        goto LABEL_121;
      case 9:
        goto LABEL_103;
      default:
        goto LABEL_99;
    }
  }
}
