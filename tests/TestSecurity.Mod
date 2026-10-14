MODULE TestSecurity;

IMPORT SYSTEM, PasswordStatus, PasswordBytes, Sha256, HmacSha256, Pbkdf2, PasswordHash;

VAR key: ARRAY 21 OF SYSTEM.CHAR8;
  data: ARRAY 9 OF SYSTEM.CHAR8;
  password: ARRAY 9 OF SYSTEM.CHAR8;
  salt: ARRAY 5 OF SYSTEM.CHAR8;
  expectedMac: ARRAY 32 OF SYSTEM.CHAR8;
  expectedDk: ARRAY 40 OF SYSTEM.CHAR8;
  mac: ARRAY 32 OF SYSTEM.CHAR8;
  dk: ARRAY 40 OF SYSTEM.CHAR8;
  shortDk: ARRAY 31 OF SYSTEM.CHAR8;
  block: ARRAY 64 OF SYSTEM.CHAR8;
  tail: ARRAY 63 OF SYSTEM.CHAR8;
  longPassword: ARRAY PasswordHash.PasswordLimit + 1 OF SYSTEM.CHAR8;
  digest1, digest2: ARRAY Sha256.DigestLength OF SYSTEM.CHAR8;
  shortDigest: ARRAY Sha256.DigestLength - 1 OF SYSTEM.CHAR8;
  c: Sha256.Context;
  policy: PasswordHash.Policy;
  record: ARRAY PasswordHash.EncodedCapacity OF SYSTEM.CHAR8;
  tooSmall: ARRAY PasswordHash.EncodedCapacity - 1 OF SYSTEM.CHAR8;
  oversized: ARRAY PasswordHash.EncodedCapacity OF SYSTEM.CHAR8;
  alias: ARRAY PasswordHash.EncodedCapacity OF SYSTEM.CHAR8;
  recordLen, status, i: INTEGER;
  saved: SYSTEM.CHAR8;
  matches, needsRehash: BOOLEAN;

PROCEDURE Nibble(ch: SYSTEM.CHAR8): INTEGER;
VAR result: INTEGER;
BEGIN
  IF ('0' <= ch) & (ch <= '9') THEN result := ORD(ch) - ORD('0')
  ELSE result := ORD(ch) - ORD('a') + 10
  END
  RETURN result
END Nibble;

PROCEDURE DecodeHex(text: ARRAY OF SYSTEM.CHAR8; VAR output: ARRAY OF SYSTEM.CHAR8);
VAR j: INTEGER;
BEGIN
  j := 0;
  WHILE j < LEN(output) DO
    output[j] := SYSTEM.VAL(SYSTEM.CHAR8, Nibble(text[j * 2]) * 16 + Nibble(text[j * 2 + 1]));
    INC(j)
  END
END DecodeHex;

PROCEDURE IsCleared(value: ARRAY OF SYSTEM.CHAR8): BOOLEAN;
VAR j: INTEGER; ok: BOOLEAN;
BEGIN
  j := 0; ok := TRUE;
  WHILE (j < LEN(value)) & ok DO ok := value[j] = 0X; INC(j) END
  RETURN ok
END IsCleared;

BEGIN
  i := 0;
  WHILE i < 20 DO key[i] := 0BX; INC(i) END;
  data := 'Hi There';
  DecodeHex('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7', expectedMac);
  status := HmacSha256.Compute(key, 20, data, 8, mac); ASSERT(status = PasswordStatus.Ok, 1);
  ASSERT(PasswordBytes.EqualConstantTime(mac, expectedMac, LEN(mac)), 2);

  password := 'password'; salt := 'salt';
  DecodeHex('ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43830651afcb5c862f', expectedDk);
  status := Pbkdf2.Derive(password, 8, salt, 4, 2, LEN(dk), dk); ASSERT(status = PasswordStatus.Ok, 3);
  ASSERT(PasswordBytes.EqualConstantTime(dk, expectedDk, LEN(dk)), 4);
  status := Pbkdf2.Derive(password, 8, salt, 4, 1, 0, shortDk);
  ASSERT(status = PasswordStatus.InvalidArgument, 28);
  status := Pbkdf2.Derive(password, 8, salt, 4, 1, 32, shortDk);
  ASSERT(status = PasswordStatus.BufferTooSmall, 29); ASSERT(IsCleared(shortDk), 30);

  i := 0;
  WHILE i < LEN(block) DO block[i] := SYSTEM.VAL(SYSTEM.CHAR8, i); INC(i) END;
  i := 0; WHILE i < LEN(tail) DO tail[i] := block[i + 1]; INC(i) END;
  status := Sha256.Hash(block, LEN(block), digest1); ASSERT(status = PasswordStatus.Ok, 5);
  status := Sha256.Init(c); ASSERT(status = PasswordStatus.Ok, 6);
  status := Sha256.Update(c, block, 1); ASSERT(status = PasswordStatus.Ok, 7);
  status := Sha256.Update(c, tail, LEN(tail)); ASSERT(status = PasswordStatus.Ok, 8);
  status := Sha256.Final(c, digest2); ASSERT(status = PasswordStatus.Ok, 9);
  ASSERT(PasswordBytes.EqualConstantTime(digest1, digest2, LEN(digest1)), 10);
  status := Sha256.Init(c); ASSERT(status = PasswordStatus.Ok, 11);
  status := Sha256.Update(c, block, -1); ASSERT(status = PasswordStatus.InvalidArgument, 12);
  status := Sha256.Update(c, block, 0); ASSERT(status = PasswordStatus.InvalidState, 13);
  status := Sha256.Init(c); ASSERT(status = PasswordStatus.Ok, 14);
  status := Sha256.Final(c, shortDigest); ASSERT(status = PasswordStatus.BufferTooSmall, 15);
  status := Sha256.Update(c, block, 0); ASSERT(status = PasswordStatus.InvalidState, 16);

  PasswordHash.DefaultPolicy(policy);
  policy.minIterations := 1; policy.targetIterations := 1; policy.maxIterations := 2; policy.hardLimit := 2;
  status := PasswordHash.Create(password, 8, policy, tooSmall, recordLen); ASSERT(status = PasswordStatus.BufferTooSmall, 17);
  status := PasswordHash.Create(password, 8, policy, record, recordLen); ASSERT(status = PasswordStatus.Ok, 18);
  status := PasswordHash.Verify(password, 8, record, recordLen, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.Ok, 19); ASSERT(matches, 20); ASSERT(~needsRehash, 21);
  record[0] := 'O';
  status := PasswordHash.Verify(password, 8, record, recordLen, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.InvalidFormat, 22); ASSERT(~matches, 23); ASSERT(~needsRehash, 24);
  status := PasswordHash.Verify(password, 8, oversized, LEN(oversized), policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.InvalidFormat, 25); ASSERT(~matches, 26); ASSERT(~needsRehash, 27);

  password := 'password';
  status := PasswordHash.Create(password, 8, policy, record, recordLen); ASSERT(status = PasswordStatus.Ok, 31);
  policy.targetIterations := 2;
  status := PasswordHash.NeedsRehash(record, recordLen, policy, needsRehash);
  ASSERT(status = PasswordStatus.Ok, 32); ASSERT(needsRehash, 33);
  status := PasswordHash.Verify(password, 8, record, recordLen, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.Ok, 34); ASSERT(matches, 35); ASSERT(needsRehash, 36);
  policy.minIterations := 2;
  status := PasswordHash.Verify(password, 8, record, recordLen, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.PolicyRejected, 37); ASSERT(~matches, 38); ASSERT(~needsRehash, 39);

  PasswordHash.DefaultPolicy(policy);
  policy.minIterations := 1; policy.targetIterations := 1; policy.maxIterations := 2; policy.hardLimit := 2;
  saved := record[recordLen - 1]; record[recordLen - 1] := 'A';
  status := PasswordHash.Verify(password, 8, record, recordLen, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.InvalidFormat, 40); ASSERT(~matches, 41); ASSERT(~needsRehash, 42);
  record[recordLen - 1] := saved;

  i := 0; WHILE i < LEN(longPassword) DO longPassword[i] := 'a'; INC(i) END;
  record[0] := 'x'; record[1] := 'x';
  status := PasswordHash.Create(longPassword, LEN(longPassword), policy, record, recordLen);
  ASSERT(status = PasswordStatus.PasswordTooLong, 43); ASSERT(recordLen = 0, 44); ASSERT(IsCleared(record), 45);

  policy.minIterations := 0;
  record[0] := 'x';
  status := PasswordHash.Create(password, 8, policy, record, recordLen);
  ASSERT(status = PasswordStatus.InvalidPolicy, 46); ASSERT(recordLen = 0, 47); ASSERT(IsCleared(record), 48);

  PasswordHash.DefaultPolicy(policy);
  policy.minIterations := 1; policy.targetIterations := 1; policy.maxIterations := 2; policy.hardLimit := 2;
  alias := 'password';
  status := PasswordHash.Create(alias, 8, policy, alias, recordLen); ASSERT(status = PasswordStatus.Ok, 49);
  password := 'password';
  status := PasswordHash.Verify(password, 8, alias, recordLen, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.Ok, 50); ASSERT(matches, 51)
END TestSecurity.
