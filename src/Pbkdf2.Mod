MODULE Pbkdf2;

IMPORT SYSTEM, PasswordStatus, PasswordBytes, HmacSha256;

CONST MaxDerivedLength* = 1024;

PROCEDURE XorByte(a, b: SYSTEM.CHAR8): SYSTEM.CHAR8;
VAR x, y: INTEGER;
BEGIN
  x := ORD(a); y := ORD(b);
  RETURN SYSTEM.VAL(SYSTEM.CHAR8, SYSTEM.VAL(INTEGER,
    SYSTEM.VAL(SET, x) / SYSTEM.VAL(SET, y)))
END XorByte;

PROCEDURE Derive*(password: ARRAY OF SYSTEM.CHAR8; passwordLen: INTEGER;
                  salt: ARRAY OF SYSTEM.CHAR8; saltLen, iterations, dkLen: INTEGER;
                  VAR key: ARRAY OF SYSTEM.CHAR8): INTEGER;
VAR h: HmacSha256.Context;
  input: ARRAY 1028 OF SYSTEM.CHAR8;
  u, t: ARRAY HmacSha256.MacLength OF SYSTEM.CHAR8;
  block, pos, i, j, take, status: INTEGER;
BEGIN
  IF (dkLen <= 0) OR (dkLen > MaxDerivedLength) THEN
    PasswordBytes.Clear(key, LEN(key)); status := PasswordStatus.InvalidArgument
  ELSIF dkLen > LEN(key) THEN
    PasswordBytes.Clear(key, LEN(key)); status := PasswordStatus.BufferTooSmall
  ELSIF ~PasswordBytes.Valid(password, passwordLen) OR ~PasswordBytes.Valid(salt, saltLen) OR
     (saltLen > 1024) OR (iterations <= 0) THEN
    PasswordBytes.Clear(key, dkLen); status := PasswordStatus.InvalidArgument
  ELSE
    status := HmacSha256.Prepare(h, password, passwordLen);
    pos := 0; block := 1;
    WHILE (pos < dkLen) & (status = PasswordStatus.Ok) DO
      PasswordBytes.Copy(salt, 0, input, 0, saltLen);
      input[saltLen] := SYSTEM.VAL(SYSTEM.CHAR8, block DIV 1000000H);
      input[saltLen + 1] := SYSTEM.VAL(SYSTEM.CHAR8, (block DIV 10000H) MOD 256);
      input[saltLen + 2] := SYSTEM.VAL(SYSTEM.CHAR8, (block DIV 100H) MOD 256);
      input[saltLen + 3] := SYSTEM.VAL(SYSTEM.CHAR8, block MOD 256);
      status := HmacSha256.ComputePrepared(h, input, saltLen + 4, u);
      IF status = PasswordStatus.Ok THEN
        PasswordBytes.Copy(u, 0, t, 0, LEN(t)); i := 1;
        WHILE (i < iterations) & (status = PasswordStatus.Ok) DO
          status := HmacSha256.ComputePrepared(h, u, LEN(u), u);
          IF status = PasswordStatus.Ok THEN
            j := 0; WHILE j < LEN(t) DO t[j] := XorByte(t[j], u[j]); INC(j) END;
            INC(i)
          END
        END;
        IF status = PasswordStatus.Ok THEN
          take := dkLen - pos; IF take > LEN(t) THEN take := LEN(t) END;
          PasswordBytes.Copy(t, 0, key, pos, take); pos := pos + take; INC(block)
        END
      END
    END;
    IF status # PasswordStatus.Ok THEN PasswordBytes.Clear(key, dkLen) END;
    PasswordBytes.Clear(input, LEN(input)); PasswordBytes.Clear(u, LEN(u)); PasswordBytes.Clear(t, LEN(t)); HmacSha256.Clear(h)
  END
  RETURN status
END Derive;

END Pbkdf2.
