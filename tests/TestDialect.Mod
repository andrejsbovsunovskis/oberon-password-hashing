MODULE TestDialect;

IMPORT SYSTEM, PasswordBytes, PasswordWord, Sha256, BinaryDigest, PasswordRecords;

VAR octets, copied: ARRAY 256 OF SYSTEM.CHAR8;
  digest: ARRAY Sha256.DigestLength OF SYSTEM.CHAR8;
  a, b, sum: PasswordWord.Word;
  wide: SYSTEM.INT64;
  i, status: INTEGER;

BEGIN
  (* These assumptions must hold even when fob selects -7w. *)
  ASSERT(SYSTEM.SIZE(SYSTEM.CHAR8) = 1, 1);
  ASSERT(SYSTEM.SIZE(CHAR) = 2, 2);
  ASSERT(SYSTEM.SIZE(INTEGER) = 4, 3);
  ASSERT(SYSTEM.SIZE(LONGINT) = 4, 4);
  ASSERT(SYSTEM.SIZE(SYSTEM.INT64) = 8, 5);
  wide := SYSTEM.LONG(65536) * 65536;
  ASSERT(wide = SYSTEM.LONG(2147483647) * 2 + 2, 6);
  i := 0;
  WHILE i < LEN(octets) DO
    octets[i] := SYSTEM.VAL(SYSTEM.CHAR8, i);
    ASSERT(ORD(octets[i]) = i, 7);
    INC(i)
  END;
  PasswordBytes.Copy(octets, 0, copied, 0, LEN(octets));
  ASSERT(PasswordBytes.EqualConstantTime(octets, copied, LEN(octets)), 8);
  PasswordWord.Set(a, 8000H, 0); PasswordWord.Set(b, 8000H, 0);
  sum := PasswordWord.Add(a, b);
  ASSERT((PasswordWord.Hi(sum) = 0) & (PasswordWord.Lo(sum) = 0), 9);
  status := BinaryDigest.Hash(octets, LEN(octets), digest);
  ASSERT(status = 0, 10);
  (* Read-only open arrays must still accept literals without VAR parameters. *)
  ASSERT(PasswordBytes.Valid('abc', 3), 11);
  i := 0;
  WHILE i < LEN(octets) DO ASSERT(ORD(octets[i]) = i, 12); INC(i) END
END TestDialect.
