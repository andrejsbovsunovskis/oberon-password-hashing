MODULE TestVectors;

IMPORT SYSTEM, PasswordStatus, PasswordBytes, HmacSha256, Pbkdf2;

VAR key: ARRAY 65 OF SHORTCHAR;
  data: ARRAY 14 OF SHORTCHAR;
  password, salt: ARRAY 9 OF SHORTCHAR;
  empty: ARRAY 1 OF SHORTCHAR;
  mac, dk, expected: ARRAY 32 OF SHORTCHAR;
  i, status: INTEGER;

PROCEDURE Nibble(ch: SHORTCHAR): INTEGER;
BEGIN
  IF ('0' <= ch) & (ch <= '9') THEN RETURN ORD(ch) - ORD('0') END;
  RETURN ORD(ch) - ORD('a') + 10
END Nibble;

PROCEDURE DecodeHex(IN text: ARRAY OF SHORTCHAR; VAR output: ARRAY OF SHORTCHAR);
VAR j: INTEGER;
BEGIN
  j := 0;
  WHILE j < LEN(output) DO
    output[j] := SYSTEM.VAL(SHORTCHAR, Nibble(text[j * 2]) * 16 + Nibble(text[j * 2 + 1]));
    INC(j)
  END
END DecodeHex;

BEGIN
  i := 0; WHILE i < LEN(key) DO key[i] := SYSTEM.VAL(SHORTCHAR, i); INC(i) END;
  data := 'OpenAI Oberon';
  DecodeHex('86a1e9bf017a601628c63ad3c8a8f030a3837ab37fe7f92f04186dbde83c3656', expected);
  status := HmacSha256.Compute(key, 0, data, 13, mac); ASSERT(status = PasswordStatus.Ok, 1);
  ASSERT(PasswordBytes.EqualConstantTime(mac, expected, LEN(mac)), 2);
  DecodeHex('7940d8a28f93effeb28f3753ccf83eb28d88d2bd82530893ec8a8e107c075ccb', expected);
  status := HmacSha256.Compute(key, 63, data, 13, mac); ASSERT(status = PasswordStatus.Ok, 3);
  ASSERT(PasswordBytes.EqualConstantTime(mac, expected, LEN(mac)), 4);
  DecodeHex('f741b794ca0c2ecfcba96c3da89ad5e536497df4d723fea3defaa60b6615801c', expected);
  status := HmacSha256.Compute(key, 64, data, 13, mac); ASSERT(status = PasswordStatus.Ok, 5);
  ASSERT(PasswordBytes.EqualConstantTime(mac, expected, LEN(mac)), 6);
  DecodeHex('9c15b7001c0578156fba4d8d716d9a33c7ad17ba6eccb4b076ec0527560e9fe0', expected);
  status := HmacSha256.Compute(key, 65, data, 13, mac); ASSERT(status = PasswordStatus.Ok, 7);
  ASSERT(PasswordBytes.EqualConstantTime(mac, expected, LEN(mac)), 8);

  password := 'password'; salt := 'salt';
  DecodeHex('c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a', expected);
  status := Pbkdf2.Derive(password, 8, salt, 4, 4096, 32, dk); ASSERT(status = PasswordStatus.Ok, 9);
  ASSERT(PasswordBytes.EqualConstantTime(dk, expected, LEN(dk)), 10);
  DecodeHex('97398411d6aea43a77acef92226ab8278d4db0668bd1d7a76a725f7680ac45c5', expected);
  status := Pbkdf2.Derive(empty, 0, empty, 0, 2, 32, dk); ASSERT(status = PasswordStatus.Ok, 11);
  ASSERT(PasswordBytes.EqualConstantTime(dk, expected, LEN(dk)), 12)
END TestVectors.
