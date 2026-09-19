MODULE Pbkdf2;

IMPORT SYSTEM, PasswordStatus, PasswordBytes, HmacSha256;

CONST MaxDerivedLength* = 1024;

PROCEDURE Derive*(IN password: ARRAY OF SHORTCHAR; passwordLen: INTEGER;
                  IN salt: ARRAY OF SHORTCHAR; saltLen, iterations, dkLen: INTEGER;
                  VAR key: ARRAY OF SHORTCHAR): INTEGER;
VAR h: HmacSha256.Context;
  input: ARRAY 1028 OF SHORTCHAR;
  u, t: ARRAY HmacSha256.MacLength OF SHORTCHAR;
  block, pos, i, j, take, status: INTEGER;
BEGIN
  IF (dkLen <= 0) OR (dkLen > MaxDerivedLength) OR (dkLen > LEN(key)) THEN
    PasswordBytes.Clear(key, LEN(key)); RETURN PasswordStatus.BufferTooSmall
  END;
  IF ~PasswordBytes.Valid(password, passwordLen) OR ~PasswordBytes.Valid(salt, saltLen) OR
     (saltLen > 1024) OR (iterations <= 0) THEN
    PasswordBytes.Clear(key, dkLen); RETURN PasswordStatus.InvalidArgument
  END;
  status := HmacSha256.Prepare(h, password, passwordLen);
  IF status # PasswordStatus.Ok THEN PasswordBytes.Clear(key, dkLen); HmacSha256.Clear(h); RETURN status END;
  pos := 0; block := 1;
  WHILE pos < dkLen DO
    PasswordBytes.Copy(salt, 0, input, 0, saltLen);
    input[saltLen] := SYSTEM.VAL(SHORTCHAR, block DIV 1000000H);
    input[saltLen + 1] := SYSTEM.VAL(SHORTCHAR, (block DIV 10000H) MOD 256);
    input[saltLen + 2] := SYSTEM.VAL(SHORTCHAR, (block DIV 100H) MOD 256);
    input[saltLen + 3] := SYSTEM.VAL(SHORTCHAR, block MOD 256);
    status := HmacSha256.ComputePrepared(h, input, saltLen + 4, u);
    IF status # PasswordStatus.Ok THEN
      PasswordBytes.Clear(key, dkLen); PasswordBytes.Clear(input, LEN(input));
      PasswordBytes.Clear(u, LEN(u)); PasswordBytes.Clear(t, LEN(t)); HmacSha256.Clear(h); RETURN status
    END;
    PasswordBytes.Copy(u, 0, t, 0, LEN(t)); i := 1;
    WHILE i < iterations DO
      status := HmacSha256.ComputePrepared(h, u, LEN(u), u);
      IF status # PasswordStatus.Ok THEN
        PasswordBytes.Clear(key, dkLen); PasswordBytes.Clear(input, LEN(input));
        PasswordBytes.Clear(u, LEN(u)); PasswordBytes.Clear(t, LEN(t)); HmacSha256.Clear(h); RETURN status
      END;
      j := 0; WHILE j < LEN(t) DO t[j] := PasswordBytes.XorByte(t[j], u[j]); INC(j) END;
      INC(i)
    END;
    take := dkLen - pos; IF take > LEN(t) THEN take := LEN(t) END;
    PasswordBytes.Copy(t, 0, key, pos, take); pos := pos + take; INC(block)
  END;
  PasswordBytes.Clear(input, LEN(input)); PasswordBytes.Clear(u, LEN(u)); PasswordBytes.Clear(t, LEN(t)); HmacSha256.Clear(h);
  RETURN PasswordStatus.Ok
END Derive;

END Pbkdf2.
