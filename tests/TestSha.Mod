MODULE TestSha;

IMPORT Sha256;

VAR data: ARRAY 4 OF SHORTCHAR;
  got, want: ARRAY Sha256.DigestLength OF SHORTCHAR;
  i, status: INTEGER;

BEGIN
  data := 'abc';
  want[0] := 0BAX; want[1] := 78X; want[2] := 16X; want[3] := 0BFX;
  want[4] := 8FX; want[5] := 01X; want[6] := 0CFX; want[7] := 0EAX;
  want[8] := 41X; want[9] := 41X; want[10] := 40X; want[11] := 0DEX;
  want[12] := 5DX; want[13] := 0AEX; want[14] := 22X; want[15] := 23X;
  want[16] := 0B0X; want[17] := 03X; want[18] := 61X; want[19] := 0A3X;
  want[20] := 96X; want[21] := 17X; want[22] := 7AX; want[23] := 9CX;
  want[24] := 0B4X; want[25] := 10X; want[26] := 0FFX; want[27] := 61X;
  want[28] := 0F2X; want[29] := 00X; want[30] := 15X; want[31] := 0ADX;
  status := Sha256.Hash(data, 3, got); ASSERT(status = 0, 1);
  i := 0; WHILE i < LEN(got) DO ASSERT(got[i] = want[i], 2); INC(i) END
END TestSha.
