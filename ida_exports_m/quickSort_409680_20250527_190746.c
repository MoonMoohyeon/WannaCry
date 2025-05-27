// --- Metadata ---
// Function Name: quickSort_409680
// Address: 0x409680
// Exported At: 20250527_190746
// Signature: unknown_signature
// ---------------
int __cdecl quickSort_409680(char *a1, char *a2)
{
  char *v2; // ebx
  char *v3; // edi
  int result; // eax
  unsigned int v5; // ecx
  unsigned int v6; // esi
  unsigned int v7; // eax
  char *v8; // eax
  char *i; // esi
  unsigned int v10; // edx
  unsigned int v11; // edx
  unsigned int v12; // edx
  int v13; // edx
  signed int v14; // eax

  v2 = a2;
  v3 = a1;
  result = a2 - a1;
  if ( ((a2 - a1) & 0xFFFFFFFC) > 64 )
  {
    while ( 1 )
    {
      v5 = *v3;
      v6 = *(v2 - 1);
      v7 = *&v3[4 * ((result >> 2) / 2)];
      if ( *v3 < v7 )
        break;
      if ( v5 >= v6 )
      {
        v5 = *(v2 - 1);
        if ( v7 >= v6 )
          goto LABEL_8;
      }
LABEL_9:
      v8 = v2;
      for ( i = v3; ; i += 4 )
      {
        if ( *i < v5 )
        {
          do
          {
            v10 = *(i + 1);
            i += 4;
          }
          while ( v10 < v5 );
        }
        v11 = *(v8 - 1);
        v8 -= 4;
        if ( v5 < v11 )
        {
          do
          {
            v12 = *(v8 - 1);
            v8 -= 4;
          }
          while ( v5 < v12 );
        }
        if ( v8 <= i )
          break;
        v13 = *i;
        *i = *v8;
        *v8 = v13;
      }
      v14 = i - v3;
      LOBYTE(v14) = (i - v3) & 0xFC;
      if ( ((v2 - i) & 0xFFFFFFFC) > v14 )
      {
        quickSort_409680(v3, i);
        v3 = i;
      }
      else
      {
        quickSort_409680(i, v2);
        v2 = i;
      }
      result = v2 - v3;
      if ( ((v2 - v3) & 0xFFFFFFFC) <= 64 )
        return result;
    }
    if ( v7 >= v6 )
    {
      if ( v5 < v6 )
        v5 = *(v2 - 1);
      goto LABEL_9;
    }
LABEL_8:
    v5 = v7;
    goto LABEL_9;
  }
  return result;
}
