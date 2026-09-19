MODULE PasswordHash;

IMPORT SYSTEM, PasswordStatus, PasswordBytes, Pbkdf2, SecureRandom;

CONST SaltLength* = 16; DerivedKeyLength* = 32; PasswordLimit* = 1024;
  EncodedCapacity* = 143;

TYPE Policy* = RECORD
  minIterations*, targetIterations*, maxIterations*, hardLimit*: INTEGER;
  passwordLimit*, saltLength*, derivedKeyLength*: INTEGER
END;

TYPE Record = RECORD iterations: INTEGER; salt: ARRAY SaltLength OF SHORTCHAR; key: ARRAY DerivedKeyLength OF SHORTCHAR END;

PROCEDURE DefaultPolicy*(VAR p: Policy);
BEGIN
  p.minIterations := 600000; p.targetIterations := 600000;
  p.maxIterations := 1000000; p.hardLimit := 2000000;
  p.passwordLimit := PasswordLimit; p.saltLength := SaltLength; p.derivedKeyLength := DerivedKeyLength
END DefaultPolicy;

PROCEDURE ValidPolicy(p: Policy): BOOLEAN;
BEGIN
  RETURN (p.minIterations > 0) & (p.minIterations <= p.targetIterations) &
    (p.targetIterations <= p.maxIterations) & (p.maxIterations <= p.hardLimit) &
    (p.passwordLimit >= 0) & (p.passwordLimit <= PasswordLimit) &
    (p.saltLength = SaltLength) & (p.derivedKeyLength = DerivedKeyLength)
END ValidPolicy;

PROCEDURE ClearOutput(VAR encoded: ARRAY OF SHORTCHAR; VAR encodedLen: INTEGER);
BEGIN PasswordBytes.Clear(encoded, LEN(encoded)); encodedLen := 0 END ClearOutput;

PROCEDURE AppendChar(VAR out: ARRAY OF SHORTCHAR; VAR pos: INTEGER; ch: SHORTCHAR): BOOLEAN;
BEGIN
  IF pos >= LEN(out) - 1 THEN RETURN FALSE END;
  out[pos] := ch; INC(pos); RETURN TRUE
END AppendChar;

PROCEDURE AppendText(VAR out: ARRAY OF SHORTCHAR; VAR pos: INTEGER; IN text: ARRAY OF SHORTCHAR): BOOLEAN;
VAR i: INTEGER;
BEGIN
  i := 0;
  WHILE text[i] # 0X DO
    IF ~AppendChar(out, pos, text[i]) THEN RETURN FALSE END;
    INC(i)
  END;
  RETURN TRUE
END AppendText;

PROCEDURE AppendDecimal(VAR out: ARRAY OF SHORTCHAR; VAR pos: INTEGER; n: INTEGER): BOOLEAN;
VAR digits: ARRAY 10 OF SHORTCHAR; count: INTEGER;
BEGIN
  IF n <= 0 THEN RETURN FALSE END;
  count := 0;
  WHILE n > 0 DO digits[count] := SYSTEM.VAL(SHORTCHAR, ORD('0') + n MOD 10); n := n DIV 10; INC(count) END;
  WHILE count > 0 DO DEC(count); IF ~AppendChar(out, pos, digits[count]) THEN RETURN FALSE END END;
  RETURN TRUE
END AppendDecimal;

PROCEDURE Hex(n: INTEGER): SHORTCHAR;
BEGIN
  IF n < 10 THEN RETURN SYSTEM.VAL(SHORTCHAR, ORD('0') + n)
  ELSE RETURN SYSTEM.VAL(SHORTCHAR, ORD('a') + n - 10)
  END
END Hex;

PROCEDURE AppendHex(VAR out: ARRAY OF SHORTCHAR; VAR pos: INTEGER; IN data: ARRAY OF SHORTCHAR; n: INTEGER): BOOLEAN;
VAR i: INTEGER;
BEGIN
  i := 0;
  WHILE i < n DO
    IF ~AppendChar(out, pos, Hex(ORD(data[i]) DIV 16)) THEN RETURN FALSE END;
    IF ~AppendChar(out, pos, Hex(ORD(data[i]) MOD 16)) THEN RETURN FALSE END;
    INC(i)
  END;
  RETURN TRUE
END AppendHex;

PROCEDURE Serialize(IN r: Record; VAR encoded: ARRAY OF SHORTCHAR; VAR encodedLen: INTEGER): INTEGER;
VAR pos: INTEGER;
BEGIN
  ClearOutput(encoded, encodedLen); pos := 0;
  IF ~AppendText(encoded, pos, 'oberon-pwh$1$pbkdf2-sha256$i=') OR
     ~AppendDecimal(encoded, pos, r.iterations) OR ~AppendText(encoded, pos, '$s=') OR
     ~AppendHex(encoded, pos, r.salt, SaltLength) OR ~AppendText(encoded, pos, '$dk=') OR
     ~AppendHex(encoded, pos, r.key, DerivedKeyLength) THEN
    ClearOutput(encoded, encodedLen); RETURN PasswordStatus.BufferTooSmall
  END;
  encoded[pos] := 0X; encodedLen := pos; RETURN PasswordStatus.Ok
END Serialize;

PROCEDURE Consume(IN input: ARRAY OF SHORTCHAR; inputLen: INTEGER; VAR pos: INTEGER; IN text: ARRAY OF SHORTCHAR): BOOLEAN;
VAR i: INTEGER;
BEGIN
  i := 0;
  WHILE text[i] # 0X DO
    IF (pos >= inputLen) OR (input[pos] # text[i]) THEN RETURN FALSE END;
    INC(pos); INC(i)
  END;
  RETURN TRUE
END Consume;

PROCEDURE Nibble(ch: SHORTCHAR): INTEGER;
BEGIN
  IF ('0' <= ch) & (ch <= '9') THEN RETURN ORD(ch) - ORD('0') END;
  IF ('a' <= ch) & (ch <= 'f') THEN RETURN ORD(ch) - ORD('a') + 10 END;
  RETURN -1
END Nibble;

PROCEDURE ReadHex(IN input: ARRAY OF SHORTCHAR; inputLen: INTEGER; VAR pos: INTEGER; VAR data: ARRAY OF SHORTCHAR; n: INTEGER): BOOLEAN;
VAR i, a, b: INTEGER;
BEGIN
  IF (n > LEN(data)) OR (inputLen - pos # n * 2) THEN RETURN FALSE END;
  i := 0;
  WHILE i < n DO
    a := Nibble(input[pos]); b := Nibble(input[pos + 1]);
    IF (a < 0) OR (b < 0) THEN RETURN FALSE END;
    data[i] := SYSTEM.VAL(SHORTCHAR, a * 16 + b); pos := pos + 2; INC(i)
  END;
  RETURN TRUE
END ReadHex;

PROCEDURE ReadIterations(IN input: ARRAY OF SHORTCHAR; inputLen: INTEGER; VAR pos: INTEGER; VAR n: INTEGER): BOOLEAN;
VAR digit: INTEGER;
BEGIN
  n := 0;
  IF (pos >= inputLen) OR (input[pos] = '0') THEN RETURN FALSE END;
  WHILE (pos < inputLen) & (input[pos] # '$') DO
    IF (input[pos] < '0') OR (input[pos] > '9') THEN RETURN FALSE END;
    digit := ORD(input[pos]) - ORD('0');
    IF n > (2147483647 - digit) DIV 10 THEN RETURN FALSE END;
    n := n * 10 + digit; INC(pos)
  END;
  RETURN pos < inputLen
END ReadIterations;

PROCEDURE Parse(IN encoded: ARRAY OF SHORTCHAR; encodedLen: INTEGER; policy: Policy; VAR r: Record): INTEGER;
VAR pos: INTEGER;
BEGIN
  IF ~PasswordBytes.Valid(encoded, encodedLen) OR (encodedLen < 133) OR (encodedLen > EncodedCapacity - 1) THEN
    RETURN PasswordStatus.InvalidFormat
  END;
  pos := 0;
  IF ~Consume(encoded, encodedLen, pos, 'oberon-pwh$') THEN RETURN PasswordStatus.InvalidFormat END;
  IF ~Consume(encoded, encodedLen, pos, '1$') THEN RETURN PasswordStatus.UnsupportedVersion END;
  IF ~Consume(encoded, encodedLen, pos, 'pbkdf2-sha256$i=') THEN RETURN PasswordStatus.UnsupportedAlgorithm END;
  IF ~ReadIterations(encoded, encodedLen, pos, r.iterations) THEN RETURN PasswordStatus.InvalidFormat END;
  IF ~Consume(encoded, encodedLen, pos, '$s=') THEN RETURN PasswordStatus.InvalidFormat END;
  IF encodedLen - pos < SaltLength * 2 + 4 THEN RETURN PasswordStatus.InvalidFormat END;
  IF ~ReadHex(encoded, pos + SaltLength * 2, pos, r.salt, SaltLength) THEN RETURN PasswordStatus.InvalidFormat END;
  IF ~Consume(encoded, encodedLen, pos, '$dk=') THEN RETURN PasswordStatus.InvalidFormat END;
  IF ~ReadHex(encoded, encodedLen, pos, r.key, DerivedKeyLength) OR (pos # encodedLen) THEN RETURN PasswordStatus.InvalidFormat END;
  IF (r.iterations < policy.minIterations) OR (r.iterations > policy.maxIterations) OR (r.iterations > policy.hardLimit) THEN RETURN PasswordStatus.PolicyRejected END;
  RETURN PasswordStatus.Ok
END Parse;

PROCEDURE Create*(IN password: ARRAY OF SHORTCHAR; passwordLen: INTEGER; policy: Policy; VAR encoded: ARRAY OF SHORTCHAR; VAR encodedLen: INTEGER): INTEGER;
VAR r: Record; status: INTEGER;
BEGIN
  encodedLen := 0;
  IF ~ValidPolicy(policy) THEN ClearOutput(encoded, encodedLen); RETURN PasswordStatus.InvalidPolicy END;
  IF ~PasswordBytes.Valid(password, passwordLen) THEN ClearOutput(encoded, encodedLen); RETURN PasswordStatus.InvalidArgument END;
  IF passwordLen > policy.passwordLimit THEN ClearOutput(encoded, encodedLen); RETURN PasswordStatus.PasswordTooLong END;
  IF LEN(encoded) < EncodedCapacity THEN ClearOutput(encoded, encodedLen); RETURN PasswordStatus.BufferTooSmall END;
  IF ~SecureRandom.Fill(r.salt, SaltLength) THEN
    PasswordBytes.Clear(r.salt, LEN(r.salt)); PasswordBytes.Clear(r.key, LEN(r.key));
    ClearOutput(encoded, encodedLen); RETURN PasswordStatus.RandomUnavailable
  END;
  r.iterations := policy.targetIterations;
  status := Pbkdf2.Derive(password, passwordLen, r.salt, SaltLength, r.iterations, DerivedKeyLength, r.key);
  IF status = PasswordStatus.Ok THEN status := Serialize(r, encoded, encodedLen) END;
  PasswordBytes.Clear(r.salt, LEN(r.salt)); PasswordBytes.Clear(r.key, LEN(r.key));
  IF status # PasswordStatus.Ok THEN ClearOutput(encoded, encodedLen) END;
  RETURN status
END Create;

PROCEDURE NeedsRehash*(IN encoded: ARRAY OF SHORTCHAR; encodedLen: INTEGER; policy: Policy; VAR needed: BOOLEAN): INTEGER;
VAR r: Record; status: INTEGER;
BEGIN
  needed := FALSE;
  IF ~ValidPolicy(policy) THEN RETURN PasswordStatus.InvalidPolicy END;
  status := Parse(encoded, encodedLen, policy, r);
  IF status = PasswordStatus.Ok THEN needed := r.iterations < policy.targetIterations END;
  PasswordBytes.Clear(r.salt, LEN(r.salt)); PasswordBytes.Clear(r.key, LEN(r.key));
  RETURN status
END NeedsRehash;

PROCEDURE Verify*(IN password: ARRAY OF SHORTCHAR; passwordLen: INTEGER; IN encoded: ARRAY OF SHORTCHAR; encodedLen: INTEGER; policy: Policy; VAR matches, needsRehash: BOOLEAN): INTEGER;
VAR r: Record; derived: ARRAY DerivedKeyLength OF SHORTCHAR; status: INTEGER;
BEGIN
  matches := FALSE; needsRehash := FALSE;
  IF ~ValidPolicy(policy) THEN RETURN PasswordStatus.InvalidPolicy END;
  IF ~PasswordBytes.Valid(password, passwordLen) THEN RETURN PasswordStatus.InvalidArgument END;
  IF passwordLen > policy.passwordLimit THEN RETURN PasswordStatus.PasswordTooLong END;
  status := Parse(encoded, encodedLen, policy, r);
  IF status = PasswordStatus.Ok THEN status := Pbkdf2.Derive(password, passwordLen, r.salt, SaltLength, r.iterations, DerivedKeyLength, derived) END;
  IF status = PasswordStatus.Ok THEN
    matches := PasswordBytes.EqualConstantTime(derived, r.key, DerivedKeyLength);
    IF matches THEN needsRehash := r.iterations < policy.targetIterations END
  END;
  PasswordBytes.Clear(derived, LEN(derived)); PasswordBytes.Clear(r.salt, LEN(r.salt)); PasswordBytes.Clear(r.key, LEN(r.key));
  IF status # PasswordStatus.Ok THEN matches := FALSE; needsRehash := FALSE END;
  RETURN status
END Verify;

END PasswordHash.
