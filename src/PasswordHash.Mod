MODULE PasswordHash;

IMPORT SYSTEM, PasswordStatus, PasswordBytes, Pbkdf2, SecureRandom;

CONST SaltLength* = 16; DerivedKeyLength* = 32; PasswordLimit* = 1024;
  EncodedCapacity* = 143;

TYPE Policy* = RECORD
  minIterations*, targetIterations*, maxIterations*, hardLimit*: INTEGER;
  passwordLimit*, saltLength*, derivedKeyLength*: INTEGER
END;

  Record = RECORD iterations: INTEGER; salt: ARRAY SaltLength OF SYSTEM.CHAR8; key: ARRAY DerivedKeyLength OF SYSTEM.CHAR8 END;

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

PROCEDURE ClearOutput(VAR encoded: ARRAY OF SYSTEM.CHAR8; VAR encodedLen: INTEGER);
BEGIN PasswordBytes.Clear(encoded, LEN(encoded)); encodedLen := 0 END ClearOutput;

PROCEDURE AppendChar(VAR out: ARRAY OF SYSTEM.CHAR8; VAR pos: INTEGER; ch: SYSTEM.CHAR8): BOOLEAN;
VAR ok: BOOLEAN;
BEGIN
  ok := pos < LEN(out) - 1;
  IF ok THEN out[pos] := ch; INC(pos) END
  RETURN ok
END AppendChar;

PROCEDURE AppendText(VAR out: ARRAY OF SYSTEM.CHAR8; VAR pos: INTEGER; text: ARRAY OF SYSTEM.CHAR8): BOOLEAN;
VAR i: INTEGER; ok: BOOLEAN;
BEGIN
  i := 0; ok := TRUE;
  WHILE (text[i] # 0X) & ok DO
    ok := AppendChar(out, pos, text[i]); INC(i)
  END
  RETURN ok
END AppendText;

PROCEDURE AppendDecimal(VAR out: ARRAY OF SYSTEM.CHAR8; VAR pos: INTEGER; n: INTEGER): BOOLEAN;
VAR digits: ARRAY 10 OF SYSTEM.CHAR8; count: INTEGER; ok: BOOLEAN;
BEGIN
  ok := n > 0;
  IF ok THEN
    count := 0;
    WHILE n > 0 DO digits[count] := SYSTEM.VAL(SYSTEM.CHAR8, ORD('0') + n MOD 10); n := n DIV 10; INC(count) END;
    WHILE (count > 0) & ok DO DEC(count); ok := AppendChar(out, pos, digits[count]) END
  END
  RETURN ok
END AppendDecimal;

PROCEDURE Hex(n: INTEGER): SYSTEM.CHAR8;
VAR result: SYSTEM.CHAR8;
BEGIN
  IF n < 10 THEN result := SYSTEM.VAL(SYSTEM.CHAR8, ORD('0') + n)
  ELSE result := SYSTEM.VAL(SYSTEM.CHAR8, ORD('a') + n - 10)
  END
  RETURN result
END Hex;

PROCEDURE AppendHex(VAR out: ARRAY OF SYSTEM.CHAR8; VAR pos: INTEGER; data: ARRAY OF SYSTEM.CHAR8; n: INTEGER): BOOLEAN;
VAR i: INTEGER; ok: BOOLEAN;
BEGIN
  i := 0; ok := TRUE;
  WHILE (i < n) & ok DO
    ok := AppendChar(out, pos, Hex(ORD(data[i]) DIV 16));
    IF ok THEN ok := AppendChar(out, pos, Hex(ORD(data[i]) MOD 16)) END;
    INC(i)
  END
  RETURN ok
END AppendHex;

PROCEDURE Serialize(r: Record; VAR encoded: ARRAY OF SYSTEM.CHAR8; VAR encodedLen: INTEGER): INTEGER;
VAR pos, status: INTEGER;
BEGIN
  ClearOutput(encoded, encodedLen); pos := 0;
  IF ~AppendText(encoded, pos, 'oberon-pwh$1$pbkdf2-sha256$i=') OR
     ~AppendDecimal(encoded, pos, r.iterations) OR ~AppendText(encoded, pos, '$s=') OR
     ~AppendHex(encoded, pos, r.salt, SaltLength) OR ~AppendText(encoded, pos, '$dk=') OR
     ~AppendHex(encoded, pos, r.key, DerivedKeyLength) THEN
    ClearOutput(encoded, encodedLen); status := PasswordStatus.BufferTooSmall
  ELSE encoded[pos] := 0X; encodedLen := pos; status := PasswordStatus.Ok
  END
  RETURN status
END Serialize;

PROCEDURE Consume(input: ARRAY OF SYSTEM.CHAR8; inputLen: INTEGER; VAR pos: INTEGER; text: ARRAY OF SYSTEM.CHAR8): BOOLEAN;
VAR i: INTEGER; ok: BOOLEAN;
BEGIN
  i := 0; ok := TRUE;
  WHILE (text[i] # 0X) & ok DO
    ok := (pos < inputLen) & (input[pos] = text[i]);
    IF ok THEN INC(pos); INC(i) END
  END
  RETURN ok
END Consume;

PROCEDURE Nibble(ch: SYSTEM.CHAR8): INTEGER;
VAR result: INTEGER;
BEGIN
  IF ('0' <= ch) & (ch <= '9') THEN result := ORD(ch) - ORD('0')
  ELSIF ('a' <= ch) & (ch <= 'f') THEN result := ORD(ch) - ORD('a') + 10
  ELSE result := -1
  END
  RETURN result
END Nibble;

PROCEDURE ReadHex(input: ARRAY OF SYSTEM.CHAR8; inputLen: INTEGER; VAR pos: INTEGER; VAR data: ARRAY OF SYSTEM.CHAR8; n: INTEGER): BOOLEAN;
VAR i, a, b: INTEGER; ok: BOOLEAN;
BEGIN
  ok := (n <= LEN(data)) & (inputLen - pos = n * 2);
  i := 0;
  WHILE (i < n) & ok DO
    a := Nibble(input[pos]); b := Nibble(input[pos + 1]);
    ok := (a >= 0) & (b >= 0);
    IF ok THEN data[i] := SYSTEM.VAL(SYSTEM.CHAR8, a * 16 + b); pos := pos + 2; INC(i) END
  END
  RETURN ok
END ReadHex;

PROCEDURE ReadIterations(input: ARRAY OF SYSTEM.CHAR8; inputLen: INTEGER; VAR pos: INTEGER; VAR n: INTEGER): BOOLEAN;
VAR digit: INTEGER; ok: BOOLEAN;
BEGIN
  n := 0;
  ok := (pos < inputLen) & (input[pos] # '0');
  WHILE ok & (pos < inputLen) & (input[pos] # '$') DO
    ok := (input[pos] >= '0') & (input[pos] <= '9');
    IF ok THEN
      digit := ORD(input[pos]) - ORD('0');
      ok := n <= (2147483647 - digit) DIV 10;
      IF ok THEN n := n * 10 + digit; INC(pos) END
    END
  END
  RETURN ok & (pos < inputLen)
END ReadIterations;

PROCEDURE Parse(encoded: ARRAY OF SYSTEM.CHAR8; encodedLen: INTEGER; policy: Policy; VAR r: Record): INTEGER;
VAR pos, status: INTEGER;
BEGIN
  pos := 0;
  IF ~PasswordBytes.Valid(encoded, encodedLen) OR (encodedLen < 133) OR (encodedLen > EncodedCapacity - 1) THEN
    status := PasswordStatus.InvalidFormat
  ELSIF ~Consume(encoded, encodedLen, pos, 'oberon-pwh$') THEN status := PasswordStatus.InvalidFormat
  ELSIF ~Consume(encoded, encodedLen, pos, '1$') THEN status := PasswordStatus.UnsupportedVersion
  ELSIF ~Consume(encoded, encodedLen, pos, 'pbkdf2-sha256$i=') THEN status := PasswordStatus.UnsupportedAlgorithm
  ELSIF ~ReadIterations(encoded, encodedLen, pos, r.iterations) THEN status := PasswordStatus.InvalidFormat
  ELSIF ~Consume(encoded, encodedLen, pos, '$s=') THEN status := PasswordStatus.InvalidFormat
  ELSIF encodedLen - pos < SaltLength * 2 + 4 THEN status := PasswordStatus.InvalidFormat
  ELSIF ~ReadHex(encoded, pos + SaltLength * 2, pos, r.salt, SaltLength) THEN status := PasswordStatus.InvalidFormat
  ELSIF ~Consume(encoded, encodedLen, pos, '$dk=') THEN status := PasswordStatus.InvalidFormat
  ELSIF ~ReadHex(encoded, encodedLen, pos, r.key, DerivedKeyLength) OR (pos # encodedLen) THEN status := PasswordStatus.InvalidFormat
  ELSIF (r.iterations < policy.minIterations) OR (r.iterations > policy.maxIterations) OR (r.iterations > policy.hardLimit) THEN status := PasswordStatus.PolicyRejected
  ELSE status := PasswordStatus.Ok
  END
  RETURN status
END Parse;

PROCEDURE Create*(password: ARRAY OF SYSTEM.CHAR8; passwordLen: INTEGER; policy: Policy; VAR encoded: ARRAY OF SYSTEM.CHAR8; VAR encodedLen: INTEGER): INTEGER;
VAR r: Record; status: INTEGER;
BEGIN
  encodedLen := 0;
  IF ~ValidPolicy(policy) THEN status := PasswordStatus.InvalidPolicy
  ELSIF ~PasswordBytes.Valid(password, passwordLen) THEN status := PasswordStatus.InvalidArgument
  ELSIF passwordLen > policy.passwordLimit THEN status := PasswordStatus.PasswordTooLong
  ELSIF LEN(encoded) < EncodedCapacity THEN status := PasswordStatus.BufferTooSmall
  ELSE
    IF ~SecureRandom.Fill(r.salt, SaltLength) THEN status := PasswordStatus.RandomUnavailable
    ELSE
      r.iterations := policy.targetIterations;
      status := Pbkdf2.Derive(password, passwordLen, r.salt, SaltLength, r.iterations, DerivedKeyLength, r.key);
      IF status = PasswordStatus.Ok THEN status := Serialize(r, encoded, encodedLen) END
    END;
    PasswordBytes.Clear(r.salt, LEN(r.salt)); PasswordBytes.Clear(r.key, LEN(r.key))
  END;
  IF status # PasswordStatus.Ok THEN ClearOutput(encoded, encodedLen) END
  RETURN status
END Create;

PROCEDURE NeedsRehash*(encoded: ARRAY OF SYSTEM.CHAR8; encodedLen: INTEGER; policy: Policy; VAR needed: BOOLEAN): INTEGER;
VAR r: Record; status: INTEGER;
BEGIN
  needed := FALSE;
  IF ~ValidPolicy(policy) THEN status := PasswordStatus.InvalidPolicy
  ELSE
    status := Parse(encoded, encodedLen, policy, r);
    IF status = PasswordStatus.Ok THEN needed := r.iterations < policy.targetIterations END;
    PasswordBytes.Clear(r.salt, LEN(r.salt)); PasswordBytes.Clear(r.key, LEN(r.key))
  END
  RETURN status
END NeedsRehash;

PROCEDURE Verify*(password: ARRAY OF SYSTEM.CHAR8; passwordLen: INTEGER; encoded: ARRAY OF SYSTEM.CHAR8; encodedLen: INTEGER; policy: Policy; VAR matches, needsRehash: BOOLEAN): INTEGER;
VAR r: Record; derived: ARRAY DerivedKeyLength OF SYSTEM.CHAR8; status: INTEGER;
BEGIN
  matches := FALSE; needsRehash := FALSE;
  IF ~ValidPolicy(policy) THEN status := PasswordStatus.InvalidPolicy
  ELSIF ~PasswordBytes.Valid(password, passwordLen) THEN status := PasswordStatus.InvalidArgument
  ELSIF passwordLen > policy.passwordLimit THEN status := PasswordStatus.PasswordTooLong
  ELSE
    status := Parse(encoded, encodedLen, policy, r);
    IF status = PasswordStatus.Ok THEN status := Pbkdf2.Derive(password, passwordLen, r.salt, SaltLength, r.iterations, DerivedKeyLength, derived) END;
    IF status = PasswordStatus.Ok THEN
      matches := PasswordBytes.EqualConstantTime(derived, r.key, DerivedKeyLength);
      IF matches THEN needsRehash := r.iterations < policy.targetIterations END
    END;
    PasswordBytes.Clear(derived, LEN(derived)); PasswordBytes.Clear(r.salt, LEN(r.salt)); PasswordBytes.Clear(r.key, LEN(r.key))
  END;
  IF status # PasswordStatus.Ok THEN matches := FALSE; needsRehash := FALSE END
  RETURN status
END Verify;

END PasswordHash.
