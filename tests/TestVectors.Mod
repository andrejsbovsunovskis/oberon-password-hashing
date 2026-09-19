MODULE TestVectors;

IMPORT HmacSha256, Pbkdf2;

VAR key: ARRAY 4 OF CHAR;
  data: ARRAY 5 OF CHAR;
  salt: ARRAY 5 OF CHAR;
  mac, dk: ARRAY 32 OF CHAR;
  expectedMac, expectedDk: ARRAY 32 OF CHAR;
  i, status: INTEGER;

BEGIN
  key := 'key'; data := 'data'; salt := 'salt';
  expectedMac[0] := 50X; expectedMac[1] := 31X; expectedMac[2] := 0F0X; expectedMac[3] := 0C0X;
  expectedMac[4] := 20X; expectedMac[5] := 1EX; expectedMac[6] := 69X; expectedMac[7] := 0BBX;
  expectedMac[8] := 48X; expectedMac[9] := 7EX; expectedMac[10] := 0AEX; expectedMac[11] := 37X;
  expectedMac[12] := 0CEX; expectedMac[13] := 0EEX; expectedMac[14] := 0D0X; expectedMac[15] := 0EEX;
  expectedMac[16] := 11X; expectedMac[17] := 0FFX; expectedMac[18] := 0C9X; expectedMac[19] := 0FEX;
  expectedMac[20] := 0AAX; expectedMac[21] := 0AAX; expectedMac[22] := 0FDX; expectedMac[23] := 0EEX;
  expectedMac[24] := 0F2X; expectedMac[25] := 0D9X; expectedMac[26] := 0BEX; expectedMac[27] := 5AX;
  expectedMac[28] := 0BAX; expectedMac[29] := 0AEX; expectedMac[30] := 0FAX; expectedMac[31] := 0EEX;
  status := HmacSha256.Compute(key, 3, data, 4, mac); ASSERT(status = 0, 1);
  i := 0; WHILE i < 32 DO ASSERT(mac[i] = expectedMac[i], 2); INC(i) END;

  expectedDk[0] := 12X; expectedDk[1] := 0FX; expectedDk[2] := 0B6X; expectedDk[3] := 0CFX;
  expectedDk[4] := 0FCX; expectedDk[5] := 0F8X; expectedDk[6] := 0B3X; expectedDk[7] := 2CX;
  expectedDk[8] := 43X; expectedDk[9] := 0E7X; expectedDk[10] := 22X; expectedDk[11] := 52X;
  expectedDk[12] := 56X; expectedDk[13] := 0C4X; expectedDk[14] := 0F8X; expectedDk[15] := 37X;
  expectedDk[16] := 0A8X; expectedDk[17] := 65X; expectedDk[18] := 48X; expectedDk[19] := 0C9X;
  expectedDk[20] := 2CX; expectedDk[21] := 0CCX; expectedDk[22] := 35X; expectedDk[23] := 48X;
  expectedDk[24] := 08X; expectedDk[25] := 05X; expectedDk[26] := 98X; expectedDk[27] := 7CX;
  expectedDk[28] := 0B7X; expectedDk[29] := 0BX; expectedDk[30] := 0E1X; expectedDk[31] := 7BX;
  status := Pbkdf2.Derive(key, 3, salt, 4, 1, 32, dk); ASSERT(status = 0, 3);
  i := 0; WHILE i < 32 DO ASSERT(dk[i] = expectedDk[i], 4); INC(i) END
END TestVectors.
