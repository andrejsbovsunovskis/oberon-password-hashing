MODULE TestParser;

IMPORT SYSTEM, PasswordStatus, PasswordBytes, PasswordHash;

CONST Mutations = 100000;

VAR policy: PasswordHash.Policy;
  password: ARRAY 9 OF SHORTCHAR;
  original, mutated: ARRAY PasswordHash.EncodedCapacity OF SHORTCHAR;
  originalLen, status, i, pos: INTEGER;
  matches, needsRehash: BOOLEAN;

PROCEDURE CopyRecord;
BEGIN
  PasswordBytes.Clear(mutated, LEN(mutated));
  PasswordBytes.Copy(original, 0, mutated, 0, originalLen)
END CopyRecord;

PROCEDURE IsExpected(status: INTEGER): BOOLEAN;
BEGIN
  RETURN (status = PasswordStatus.Ok) OR (status = PasswordStatus.InvalidFormat) OR
    (status = PasswordStatus.UnsupportedVersion) OR (status = PasswordStatus.UnsupportedAlgorithm) OR
    (status = PasswordStatus.PolicyRejected)
END IsExpected;

BEGIN
  password := 'password';
  PasswordHash.DefaultPolicy(policy);
  policy.minIterations := 1; policy.targetIterations := 1;
  policy.maxIterations := 2; policy.hardLimit := 2;
  status := PasswordHash.Create(password, 8, policy, original, originalLen);
  ASSERT(status = PasswordStatus.Ok, 1);

  i := 0;
  WHILE i < Mutations DO
    CopyRecord;
    pos := i MOD originalLen;
    mutated[pos] := SYSTEM.VAL(SHORTCHAR, (ORD(original[pos]) + 1 + i DIV originalLen) MOD 127);
    IF mutated[pos] = original[pos] THEN mutated[pos] := 0X END;
    status := PasswordHash.Verify(password, 8, mutated, originalLen, policy, matches, needsRehash);
    ASSERT(IsExpected(status), 2);
    IF status # PasswordStatus.Ok THEN ASSERT(~matches, 3); ASSERT(~needsRehash, 4) END;
    INC(i)
  END;

  CopyRecord;
  status := PasswordHash.Verify(password, 8, mutated, originalLen - 1, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.InvalidFormat, 5); ASSERT(~matches, 6); ASSERT(~needsRehash, 7);
  status := PasswordHash.Verify(password, 8, mutated, originalLen + 1, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.InvalidFormat, 8); ASSERT(~matches, 9); ASSERT(~needsRehash, 10)
END TestParser.
