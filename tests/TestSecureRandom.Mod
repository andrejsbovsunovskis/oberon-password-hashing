MODULE TestSecureRandom;

IMPORT SecureRandom;

VAR buffer: ARRAY 16 OF SHORTCHAR;
  i: INTEGER;
  nonzero: BOOLEAN;

BEGIN
  ASSERT(~SecureRandom.Fill(buffer, -1), 1);
  ASSERT(~SecureRandom.Fill(buffer, LEN(buffer) + 1), 2);
  ASSERT(SecureRandom.Fill(buffer, 0), 3);
  ASSERT(SecureRandom.Fill(buffer, LEN(buffer)), 4);
  nonzero := FALSE; i := 0;
  WHILE i < LEN(buffer) DO IF buffer[i] # 0X THEN nonzero := TRUE END; INC(i) END;
  ASSERT(nonzero, 5)
END TestSecureRandom.
