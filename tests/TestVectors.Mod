MODULE TestVectors;

IMPORT HmacSha256, Pbkdf2;

VAR key: ARRAY 9 OF SHORTCHAR;
  data: ARRAY 5 OF SHORTCHAR;
  salt: ARRAY 5 OF SHORTCHAR;
  mac, dk: ARRAY 32 OF SHORTCHAR;
  expectedMac, expectedDk: ARRAY 32 OF SHORTCHAR;
  i, status: INTEGER;

BEGIN
  key := 'key'; data := 'data'; salt := 'salt';
  expectedMac[0] := 50X; expectedMac[1] := 31X; expectedMac[2] := 0FEX; expectedMac[3] := 3DX;
  expectedMac[4] := 98X; expectedMac[5] := 9CX; expectedMac[6] := 6DX; expectedMac[7] := 15X;
  expectedMac[8] := 37X; expectedMac[9] := 0A0X; expectedMac[10] := 13X; expectedMac[11] := 0FAX;
  expectedMac[12] := 6EX; expectedMac[13] := 73X; expectedMac[14] := 9DX; expectedMac[15] := 0A2X;
  expectedMac[16] := 34X; expectedMac[17] := 63X; expectedMac[18] := 0FDX; expectedMac[19] := 0AEX;
  expectedMac[20] := 0C3X; expectedMac[21] := 0B7X; expectedMac[22] := 01X; expectedMac[23] := 37X;
  expectedMac[24] := 0D8X; expectedMac[25] := 28X; expectedMac[26] := 0E3X; expectedMac[27] := 6AX;
  expectedMac[28] := 0CEX; expectedMac[29] := 22X; expectedMac[30] := 1BX; expectedMac[31] := 0D0X;
  status := HmacSha256.Compute(key, 3, data, 4, mac); ASSERT(status = 0, 1);
  i := 0; WHILE i < 32 DO ASSERT(mac[i] = expectedMac[i], 2); INC(i) END;

  key := 'password';
  expectedDk[0] := 12X; expectedDk[1] := 0FX; expectedDk[2] := 0B6X; expectedDk[3] := 0CFX;
  expectedDk[4] := 0FCX; expectedDk[5] := 0F8X; expectedDk[6] := 0B3X; expectedDk[7] := 2CX;
  expectedDk[8] := 43X; expectedDk[9] := 0E7X; expectedDk[10] := 22X; expectedDk[11] := 52X;
  expectedDk[12] := 56X; expectedDk[13] := 0C4X; expectedDk[14] := 0F8X; expectedDk[15] := 37X;
  expectedDk[16] := 0A8X; expectedDk[17] := 65X; expectedDk[18] := 48X; expectedDk[19] := 0C9X;
  expectedDk[20] := 2CX; expectedDk[21] := 0CCX; expectedDk[22] := 35X; expectedDk[23] := 48X;
  expectedDk[24] := 08X; expectedDk[25] := 05X; expectedDk[26] := 98X; expectedDk[27] := 7CX;
  expectedDk[28] := 0B7X; expectedDk[29] := 0BX; expectedDk[30] := 0E1X; expectedDk[31] := 7BX;
  status := Pbkdf2.Derive(key, 8, salt, 4, 1, 32, dk); ASSERT(status = 0, 3);
  i := 0; WHILE i < 32 DO ASSERT(dk[i] = expectedDk[i], 4); INC(i) END
END TestVectors.
