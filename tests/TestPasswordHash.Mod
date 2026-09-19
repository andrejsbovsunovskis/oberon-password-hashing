MODULE TestPasswordHash;

IMPORT PasswordHash;

VAR policy: PasswordHash.Policy;
  password: ARRAY 7 OF CHAR;
  encoded: ARRAY PasswordHash.EncodedCapacity OF CHAR;
  encodedLen, status: INTEGER;
  matches, needsRehash: BOOLEAN;

BEGIN
  password := 'secret';
  PasswordHash.DefaultPolicy(policy);
  policy.minIterations := 1; policy.targetIterations := 1; policy.maxIterations := 2; policy.hardLimit := 2;
  status := PasswordHash.Create(password, 6, policy, encoded, encodedLen); ASSERT(status = 0, 1);
  ASSERT(encodedLen = 133, 2);
  status := PasswordHash.Verify(password, 6, encoded, encodedLen, policy, matches, needsRehash); ASSERT(status = 0, 3); ASSERT(matches, 4); ASSERT(~needsRehash, 5);
  password[0] := 'S';
  status := PasswordHash.Verify(password, 6, encoded, encodedLen, policy, matches, needsRehash); ASSERT(status = 0, 6); ASSERT(~matches, 7); ASSERT(~needsRehash, 8)
END TestPasswordHash.
