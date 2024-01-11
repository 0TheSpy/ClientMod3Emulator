#include "hash.h"
#include "defs.h"


__int64 __stdcall sub_10AB8430(__int64 a1, __int64 a2)
{ 
	if (HIDWORD(a1) | HIDWORD(a2))
		return a1 * a2;
	else
		return (unsigned int)a2 * (unsigned __int64)(unsigned int)a1;
}

unsigned __int64 __cdecl friends_name_hash(unsigned __int8* input_data, unsigned int input_length, unsigned __int64 a3)
{
  __int64 v3; // rax
  int v4; // ecx
  int v5; // esi
  int v6; // ecx
  unsigned __int8* v7; // edi
  unsigned __int8* v8; // eax
  unsigned int v9; // esi
  unsigned int v10; // edi
  unsigned int v11; // edx
  unsigned int v12; // ecx
  int v13; // esi
  unsigned __int64 v14; // rt0
  unsigned int v15; // edi
  unsigned int v16; // esi
  __int64 v17; // rax
  __int64 v18; // rax
  __int64 v19; // rax
  __int64 v20; // rax
  __int64 v21; // rdi
  __int64 v22; // rax
  __int64 v23; // rax
  __int64 v24; // rax
  unsigned int v25; // ecx
  unsigned int v26; // esi
  __int64 v27; // rax
  bool v28; // cf
  int v29; // edi
  unsigned __int64 v30; // kr40_8
  __int64 v31; // rax
  int v32; // ecx
  unsigned int v33; // ecx
  unsigned int v34; // esi
  __int64 v35; // rax
  BOOL v36; // ett
  int v37; // edx
  int v38; // ecx
  int v39; // eax
  unsigned int v40; // edi
  int v41; // kr98_4
  unsigned int v42; // esi
  int v43; // krA0_4
  __int64 v44; // rax
  BOOL v45; // ett
  unsigned int v46; // ecx
  __int64 v47; // rax
  __int64 v48; // krC8_8
  int v49; // ecx
  __int64 v50; // rax
  int v51; // esi
  int v52; // edi
  unsigned int v53; // ecx
  __int64 v54; // rax
  BOOL v55; // ett
  __int64 v57; // [esp-10h] [ebp-90h]
  int v58; // [esp+8h] [ebp-78h]
  unsigned int v59; // [esp+Ch] [ebp-74h]
  unsigned int v60; // [esp+10h] [ebp-70h]
  unsigned int v61; // [esp+10h] [ebp-70h]
  int v62; // [esp+18h] [ebp-68h]
  unsigned int v63; // [esp+1Ch] [ebp-64h]
  unsigned int v64; // [esp+20h] [ebp-60h]
  unsigned __int8* v65; // [esp+30h] [ebp-50h]
  unsigned int v66; // [esp+34h] [ebp-4Ch]
  unsigned int v67; // [esp+38h] [ebp-48h]
  unsigned int v68; // [esp+38h] [ebp-48h]
  unsigned int v69; // [esp+44h] [ebp-3Ch]
  unsigned int v70; // [esp+44h] [ebp-3Ch]
  unsigned int v71; // [esp+44h] [ebp-3Ch]
  unsigned int v72; // [esp+44h] [ebp-3Ch]
  unsigned int v73; // [esp+44h] [ebp-3Ch]
  unsigned int v74; // [esp+44h] [ebp-3Ch]
  unsigned int v75; // [esp+48h] [ebp-38h]
  unsigned int v76; // [esp+4Ch] [ebp-34h]
  __int64 v77; // [esp+50h] [ebp-30h]
  __int64 v78; // [esp+58h] [ebp-28h]
  unsigned __int64 v79; // [esp+60h] [ebp-20h]
  unsigned int v80; // [esp+6Ch] [ebp-14h]
  int v81; // [esp+6Ch] [ebp-14h]
  unsigned int v82; // [esp+70h] [ebp-10h]
  int v83; // [esp+70h] [ebp-10h]
  int v84; // [esp+70h] [ebp-10h]
  int v85; // [esp+70h] [ebp-10h]
  int v86; // [esp+70h] [ebp-10h]
  int v87; // [esp+70h] [ebp-10h]
  int v88; // [esp+70h] [ebp-10h]
  unsigned int v89; // [esp+74h] [ebp-Ch]
  int v90; // [esp+74h] [ebp-Ch]
  int v91; // [esp+74h] [ebp-Ch]
  int v92; // [esp+74h] [ebp-Ch]
  int v93; // [esp+74h] [ebp-Ch]
  int v94; // [esp+74h] [ebp-Ch]
  int v95; // [esp+78h] [ebp-8h]
  int v96; // [esp+78h] [ebp-8h]
  unsigned int v97; // [esp+78h] [ebp-8h]

  v3 = input_length;
  v4 = a3;
  v58 = a3;
  v59 = 0;
  v60 = input_length;
  v5 = HIDWORD(a3);
  v62 = HIDWORD(a3);
  if (input_length <= 32)
  {
    v7 = input_data;
    v65 = input_data;
  }
  else
  {
    v64 = (input_length >> 23) + ~(_DWORD)a3;
    v66 = (__PAIR64__(__PAIR64__(input_length, 0) >> 23, input_length >> 23) + ~a3) >> 32;
    v6 = a3 >> 19;
    v67 = v6 + ~input_length;
    v61 = (__PAIR64__(a3, HIDWORD(a3)) >> 19) + __CFADD__(v6, ~input_length) - 1;
    v7 = input_data;
    v69 = input_length;
    v78 = input_length;
    v79 = a3;
    do
    {
      v8 = v7;
      v65 = v7 + 32;
      v9 = *((_DWORD*)v7 + 1);
      v10 = *(_DWORD*)v7;
      v11 = *((_DWORD*)v8 + 2);
      v12 = *((_DWORD*)v8 + 3);
      v75 = v9;
      v82 = *((_DWORD*)v8 + 4);
      v76 = *((_DWORD*)v8 + 5);
      v77 = *((_QWORD*)v8 + 3);
      LODWORD(v14) = (__PAIR64__(v61, v82) + __PAIR64__(v76, v67)) >> 32;
      HIDWORD(v14) = v82 + v67;
      v13 = v14 >> 24;
      v89 = v10 + v13;
      v63 = v75 + __CFADD__(v10, v13) + (unsigned int)((__PAIR64__(v61, v82) + __PAIR64__(v76, v67)) >> 24);
      v80 = v10;
      LODWORD(v14) = (v77 + __PAIR64__(v66, v64)) >> 32;
      HIDWORD(v14) = v77 + v64;
      v15 = (__PAIR64__(v12, v11) + __PAIR64__(v14 >> 19, (v77 + __PAIR64__(v66, v64)) >> 19)) >> 32;
      v16 = v11 + ((v77 + __PAIR64__(v66, v64)) >> 19);
      LODWORD(v17) = __PAIR64__(v11, v12) >> 6;
      HIDWORD(v17) = __PAIR64__(v12, v11) >> 6;
      v18 = __PAIR64__(v59, v69) + v17;
      v67 ^= v18;
      v61 ^= HIDWORD(v18);
      LODWORD(v18) = __PAIR64__(v80, v75) >> 25;
      HIDWORD(v18) = __PAIR64__(v75, v80) >> 25;
      v19 = __PAIR64__(v62, v58) + v18;
      v64 ^= v19;
      v66 ^= HIDWORD(v19);
      v20 = sub_10AB8430(__PAIR64__(v76, v82) + __PAIR64__(v15, v16), 0xCB5AF53AE3AAAC31ui64);
      v21 = v78 ^ v20;
      v81 = HIDWORD(v78) ^ HIDWORD(v20);
      v69 = v78 ^ v20;
      v59 = HIDWORD(v78) ^ HIDWORD(v20);
      v22 = sub_10AB8430(v77 + __PAIR64__(v63, v89), 0xC060724A8424F345ui64);
      LODWORD(v79) = v79 ^ v22;
      v58 = v79;
      v78 = v21;
      v7 = v65;
      v83 = HIDWORD(v79) ^ HIDWORD(v22);
      v62 = HIDWORD(v79) ^ HIDWORD(v22);
      HIDWORD(v79) ^= HIDWORD(v22);
    } while (v65 < &input_data[input_length - 31]);
    v23 = sub_10AB8430(
      __PAIR64__(v66, v64) + __PAIR64__(__PAIR64__(v67, v61) >> 23, __PAIR64__(v61, v67) >> 23),
      0xCB5AF53AE3AAAC31ui64);
    v5 = v83 ^ HIDWORD(v23);
    v58 = v79 ^ v23;
    v62 = v83 ^ HIDWORD(v23);
    v24 = sub_10AB8430(
      __PAIR64__(v61, v67) + __PAIR64__(__PAIR64__(v64, v66) >> 19, __PAIR64__(v66, v64) >> 19),
      0xC060724A8424F345ui64);
    HIDWORD(v3) = v81 ^ HIDWORD(v24);
    v4 = v58;
    v60 = v69 ^ v24;
    LODWORD(v3) = input_length & 0x1F;
    v59 = HIDWORD(v3);
    LOBYTE(input_length) = input_length & 0x1F;
  }
  switch ((int)v3)
  {
  case 0:
    v46 = v59;
    goto LABEL_21;
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8:
    goto LABEL_10;
  case 9:
  case 10:
  case 11:
  case 12:
  case 13:
  case 14:
  case 15:
  case 16:
    goto LABEL_9;
  case 17:
  case 18:
  case 19:
  case 20:
  case 21:
  case 22:
  case 23:
  case 24:
    goto LABEL_8;
  default:
    v25 = *(_DWORD*)v7 + v60;
    v26 = (*(_QWORD*)v7 + __PAIR64__(HIDWORD(v3), v60)) >> 32;
    v95 = -802954325 * v25;
    v90 = (3492012971u * (unsigned __int64)v26) >> 32;
    v84 = (2617703156u * (unsigned __int64)v25) >> 32;
    v25 *= -1677264140;
    v27 = 2617703156i64 * v26;
    v70 = (__PAIR64__(-802954325 * v26, 0) + 3492012971i64 * (*(_DWORD*)v7 + v60)) >> 32;
    v28 = __CFADD__(__CFADD__(__PAIR64__(-802954325 * v26, 0), 3492012971i64 * (*(_DWORD*)v7 + v60)), (_DWORD)v27);
    LODWORD(v27) = v90
      + __CFADD__(__PAIR64__(-802954325 * v26, 0), 3492012971i64 * (*(_DWORD*)v7 + v60))
      - 1677264140 * v26;
    HIDWORD(v27) += v28 | __CFADD__(
      v90,
      __CFADD__(__PAIR64__(-802954325 * v26, 0), 3492012971i64 * (*(_DWORD*)v7 + v60))
      - 1677264140 * v26);
    v29 = (__PAIR64__(v25, 0) + __PAIR64__(-802954325 * v26, 0) + 3492012971i64 * (*(_DWORD*)v7 + v60)) >> 32;
    v28 = __CFADD__(__CFADD__(__PAIR64__(v25, 0), __PAIR64__(v70, v95)), (_DWORD)v27);
    LODWORD(v27) = __CFADD__(__PAIR64__(v25, 0), __PAIR64__(v70, v95)) + (_DWORD)v27;
    v28 |= __CFADD__(v84, (_DWORD)v27);
    LODWORD(v27) = v84 + v27;
    HIDWORD(v27) += v28;
    v4 = v95 ^ v58;
    v5 = v29 ^ v62;
    v58 ^= v95;
    v59 = (v27 + __PAIR64__(v59, v60)) >> 32;
    v60 += v27;
    v7 = v65 + 8;
    v62 = v5;
    v65 += 8;
  LABEL_8:
    v30 = *(_QWORD*)v7 + __PAIR64__(v5, v4);
    v91 = (745444721 * (unsigned __int64)HIDWORD(v30)) >> 32;
    v85 = (3181161666u * (unsigned __int64)(unsigned int)v30) >> 32;
    v31 = 3181161666i64 * HIDWORD(v30);
    v28 = __CFADD__(__CFADD__(__PAIR64__(745444721 * HIDWORD(v30), 0), 745444721i64 * (unsigned int)v30), (_DWORD)v31);
    LODWORD(v31) = v85
      + __CFADD__(
        __PAIR64__(-1113805630 * (int)v30, 0),
        __PAIR64__(745444721 * HIDWORD(v30), 0) + 745444721i64 * (unsigned int)v30)
      + v91
      + __CFADD__(__PAIR64__(745444721 * HIDWORD(v30), 0), 745444721i64 * (unsigned int)v30)
      - 1113805630 * HIDWORD(v30);
    HIDWORD(v31) += (__CFADD__(
      __CFADD__(
        __PAIR64__(-1113805630 * (int)v30, 0),
        __PAIR64__(745444721 * HIDWORD(v30), 0) + 745444721i64 * (unsigned int)v30),
      v91
      + __CFADD__(__PAIR64__(745444721 * HIDWORD(v30), 0), 745444721i64 * (unsigned int)v30)
      - 1113805630 * HIDWORD(v30)) | __CFADD__(
        v85,
        __CFADD__(
          __PAIR64__(-1113805630 * (int)v30, 0),
          __PAIR64__(745444721 * HIDWORD(v30), 0)
          + 745444721i64 * (unsigned int)v30)
        + v91
        + __CFADD__(
          __PAIR64__(745444721 * HIDWORD(v30), 0),
          745444721i64 * (unsigned int)v30)
        - 1113805630 * HIDWORD(v30)))
      + (v28 | __CFADD__(
        v91,
        __CFADD__(__PAIR64__(745444721 * HIDWORD(v30), 0), 745444721i64 * (unsigned int)v30)
        - 1113805630 * HIDWORD(v30)));
    v59 ^= (__PAIR64__(-1113805630 * (int)v30, 0)
      + __PAIR64__(745444721 * HIDWORD(v30), 0)
      + 745444721i64 * (unsigned int)v30) >> 32;
    v60 ^= 745444721 * v30;
    v32 = (v31 + __PAIR64__(v62, v58)) >> 32;
    v58 += v31;
    v7 = v65 + 8;
    v62 = v32;
    v65 += 8;
  LABEL_9:
    v33 = *(_DWORD*)v7 + v60;
    v34 = (*(_QWORD*)v7 + __PAIR64__(v59, v60)) >> 32;
    v92 = (2640821835u * (unsigned __int64)v34) >> 32;
    v86 = (3572526521u * (unsigned __int64)v33) >> 32;
    v33 *= -722440775;
    v35 = 3572526521i64 * v34;
    v36 = __CFADD__(__PAIR64__(-1654145461 * v34, 0), 2640821835i64 * (*(_DWORD*)v7 + v60));
    v28 = __CFADD__(v36, (_DWORD)v35);
    LODWORD(v35) = v86
      + __CFADD__(
        __PAIR64__(v33, 0),
        __PAIR64__(-1654145461 * v34, 0) + 2640821835i64 * (*(_DWORD*)v7 + v60))
      + v92
      + v36
      - 722440775 * v34;
    HIDWORD(v35) += (__CFADD__(
      __CFADD__(
        __PAIR64__(v33, 0),
        __PAIR64__(-1654145461 * v34, 0) + 2640821835i64 * (*(_DWORD*)v7 + v60)),
      v92 + v36 - 722440775 * v34) | __CFADD__(
        v86,
        __CFADD__(
          __PAIR64__(v33, 0),
          __PAIR64__(-1654145461 * v34, 0)
          + 2640821835i64 * (*(_DWORD*)v7 + v60))
        + v92
        + v36
        - 722440775 * v34))
      + (v28 | __CFADD__(v92, v36 - 722440775 * v34));
    v58 ^= -1654145461 * (*(_DWORD*)v7 + v60);
    v5 = ((__PAIR64__(v33, 0) + __PAIR64__(-1654145461 * v34, 0) + 2640821835i64 * (*(_DWORD*)v7 + v60)) >> 32) ^ v62;
    v59 = (v35 + __PAIR64__(v59, v60)) >> 32;
    v60 += v35;
    v7 = v65 + 8;
    v62 = v5;
  LABEL_10:
    v37 = 0;
    v38 = 0;
    v68 = 0;
    switch (input_length & 7)
    {
    case 0u:
      v39 = *(_DWORD*)v7;
      v40 = *((_DWORD*)v7 + 1);
      goto LABEL_19;
    case 1u:
      v39 = *v7;
      v40 = 0;
      goto LABEL_19;
    case 2u:
      goto LABEL_17;
    case 3u:
      v68 = (unsigned __int64)v7[2] >> 16;
      v38 = v7[2] << 16;
    LABEL_17:
      v41 = v38 + *(unsigned __int16*)v7;
      v40 = (__PAIR64__(v68, v38) + *(unsigned __int16*)v7) >> 32;
      v39 = v41;
      goto LABEL_19;
    case 4u:
      goto LABEL_15;
    case 5u:
      goto LABEL_14;
    case 6u:
      goto LABEL_13;
    case 7u:
      v38 = v7[6] << 8;
    LABEL_13:
      v38 = (v7[5] + v38) << 8;
    LABEL_14:
      v37 = v38 + v7[4];
    LABEL_15:
      v39 = *(_DWORD*)v7;
      v40 = v37;
    LABEL_19:
      v43 = v39 + v58;
      v42 = (__PAIR64__(v5, v39) + __PAIR64__(v40, v58)) >> 32;
      v71 = (249360185 * (unsigned __int64)(unsigned int)(v39 + v58)) >> 32;
      v96 = 249360185 * (v39 + v58);
      v93 = (249360185 * (unsigned __int64)v42) >> 32;
      v87 = (2185449449u * (unsigned __int64)(unsigned int)(v39 + v58)) >> 32;
      v44 = 2185449449i64 * v42;
      v28 = __CFADD__(__PAIR64__(249360185 * v42, 0), __PAIR64__(v71, v96));
      v72 = (__PAIR64__(249360185 * v42, 0) + __PAIR64__(v71, v96)) >> 32;
      v45 = v28;
      v28 = __CFADD__(v28, (_DWORD)v44);
      LODWORD(v44) = v93 + v45 - 2109517847 * v42;
      HIDWORD(v44) += v28 | __CFADD__(v93, v45 - 2109517847 * v42);
      v28 = __CFADD__(__CFADD__(__PAIR64__(-2109517847 * v43, 0), __PAIR64__(v72, v96)), (_DWORD)v44);
      LODWORD(v44) = __CFADD__(__PAIR64__(-2109517847 * v43, 0), __PAIR64__(v72, v96)) + (_DWORD)v44;
      v28 |= __CFADD__(v87, (_DWORD)v44);
      LODWORD(v44) = v87 + v44;
      HIDWORD(v44) += v28;
      v60 ^= v96;
      v46 = ((__PAIR64__(-2109517847 * v43, 0) + __PAIR64__(v72, v96)) >> 32) ^ v59;
      v59 = v46;
      v5 = (v44 + __PAIR64__(v62, v58)) >> 32;
      v58 += v44;
      break;
    }
  LABEL_21:
    LODWORD(v47) = __PAIR64__(v60, v46) >> 9;
    HIDWORD(v47) = __PAIR64__(v46, v60) >> 9;
    v48 = sub_10AB8430(v47 + __PAIR64__(v5, v58), 0xEC99BF0D8372CAABui64);
    v49 = __PAIR64__(v5, v58) >> 23;
    HIDWORD(v57) = (__PAIR64__(v58, v5) >> 23) + __CFADD__(v49, v60) + v59;
    LODWORD(v57) = v49 + v60;
    v50 = sub_10AB8430(v57, 0xCB5AF53AE3AAAC31ui64);
    v51 = HIDWORD(v48) ^ HIDWORD(v50);
    v73 = (2217014085u * (unsigned __int64)((unsigned int)v48 ^ (unsigned int)v50)) >> 32;
    v97 = -2077953211 * (v48 ^ v50);
    v94 = (2217014085u * (unsigned __int64)(unsigned int)(HIDWORD(v48) ^ HIDWORD(v50))) >> 32;
    v52 = -2077953211 * (HIDWORD(v48) ^ HIDWORD(v50));
    v88 = (3227546186u * (unsigned __int64)((unsigned int)v48 ^ (unsigned int)v50)) >> 32;
    v53 = -1067421110 * (v48 ^ v50);
    v54 = 3227546186i64 * (unsigned int)(HIDWORD(v48) ^ HIDWORD(v50));
    v28 = __CFADD__(__PAIR64__(v52, 0), __PAIR64__(v73, v97));
    v74 = (__PAIR64__(v52, 0) + __PAIR64__(v73, v97)) >> 32;
    v55 = v28;
    v28 = __CFADD__(v28, (_DWORD)v54);
    LODWORD(v54) = v94 + v55 - 1067421110 * v51;
    HIDWORD(v54) += v28 | __CFADD__(v94, v55 - 1067421110 * v51);
    v28 = __CFADD__(__CFADD__(__PAIR64__(v53, 0), __PAIR64__(v74, v97)), (_DWORD)v54);
    LODWORD(v54) = __CFADD__(__PAIR64__(v53, 0), __PAIR64__(v74, v97)) + (_DWORD)v54;
    v28 |= __CFADD__(v88, (_DWORD)v54);
    LODWORD(v54) = v88 + v54;
    HIDWORD(v54) += v28;
    return (__PAIR64__(v53, 0) + __PAIR64__(v74, v97)) ^ v54;
  }
}


