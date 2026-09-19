MODULE TestSha;

IMPORT SYSTEM, PasswordStatus, PasswordBytes, Sha256;

VAR abc: ARRAY 4 OF SHORTCHAR;
  empty: ARRAY 1 OF SHORTCHAR;
  boundary: ARRAY 55 OF SHORTCHAR;
  tail: ARRAY 54 OF SHORTCHAR;
  got, want, streamed: ARRAY Sha256.DigestLength OF SHORTCHAR;
  c: Sha256.Context;
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
  DecodeHex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', want);
  status := Sha256.Hash(empty, 0, got); ASSERT(status = PasswordStatus.Ok, 1);
  ASSERT(PasswordBytes.EqualConstantTime(got, want, LEN(got)), 2);

  abc := 'abc';
  DecodeHex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', want);
  status := Sha256.Hash(abc, 3, got); ASSERT(status = PasswordStatus.Ok, 3);
  ASSERT(PasswordBytes.EqualConstantTime(got, want, LEN(got)), 4);

  i := 0;
  WHILE i < LEN(boundary) DO boundary[i] := SYSTEM.VAL(SHORTCHAR, i); INC(i) END;
  i := 0;
  WHILE i < LEN(tail) DO tail[i] := boundary[i + 1]; INC(i) END;
  DecodeHex('463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59', want);
  status := Sha256.Hash(boundary, LEN(boundary), got); ASSERT(status = PasswordStatus.Ok, 5);
  ASSERT(PasswordBytes.EqualConstantTime(got, want, LEN(got)), 6);
  status := Sha256.Init(c); ASSERT(status = PasswordStatus.Ok, 7);
  status := Sha256.Update(c, boundary, 1); ASSERT(status = PasswordStatus.Ok, 8);
  status := Sha256.Update(c, tail, LEN(tail)); ASSERT(status = PasswordStatus.Ok, 9);
  status := Sha256.Final(c, streamed); ASSERT(status = PasswordStatus.Ok, 10);
  ASSERT(PasswordBytes.EqualConstantTime(streamed, want, LEN(streamed)), 11)
END TestSha.
