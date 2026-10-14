MODULE TestProductionCost;

IMPORT SYSTEM, PasswordStatus, PasswordHash;

VAR policy: PasswordHash.Policy;
  password: ARRAY 9 OF SYSTEM.CHAR8;
  record: ARRAY PasswordHash.EncodedCapacity OF SYSTEM.CHAR8;
  recordLen, status: INTEGER;
  matches, needsRehash: BOOLEAN;

BEGIN
  password := 'password';
  PasswordHash.DefaultPolicy(policy);
  status := PasswordHash.Create(password, 8, policy, record, recordLen);
  ASSERT(status = PasswordStatus.Ok, 1);
  status := PasswordHash.Verify(password, 8, record, recordLen, policy, matches, needsRehash);
  ASSERT(status = PasswordStatus.Ok, 2); ASSERT(matches, 3); ASSERT(~needsRehash, 4)
END TestProductionCost.
