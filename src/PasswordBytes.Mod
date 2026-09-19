MODULE PasswordBytes;

IMPORT SYSTEM;

PROCEDURE Valid*(IN a: ARRAY OF CHAR; n: INTEGER): BOOLEAN;
BEGIN
  RETURN (n >= 0) & (n <= LEN(a))
END Valid;

PROCEDURE Clear*(VAR a: ARRAY OF CHAR; n: INTEGER);
VAR i, limit: INTEGER;
BEGIN
  limit := n;
  IF limit < 0 THEN limit := 0 END;
  IF limit > LEN(a) THEN limit := LEN(a) END;
  i := 0;
  WHILE i < limit DO a[i] := 0X; INC(i) END
END Clear;

PROCEDURE Copy*(IN src: ARRAY OF CHAR; srcPos: INTEGER;
               VAR dst: ARRAY OF CHAR; dstPos, n: INTEGER);
VAR i: INTEGER;
BEGIN
  IF (srcPos < 0) OR (dstPos < 0) OR (n < 0) THEN RETURN END;
  IF (srcPos > LEN(src)) OR (n > LEN(src) - srcPos) THEN RETURN END;
  IF (dstPos > LEN(dst)) OR (n > LEN(dst) - dstPos) THEN RETURN END;
  i := 0;
  WHILE i < n DO dst[dstPos + i] := src[srcPos + i]; INC(i) END;
END Copy;

PROCEDURE EqualConstantTime*(IN a, b: ARRAY OF CHAR; n: INTEGER): BOOLEAN;
VAR i, d: INTEGER;
BEGIN
  IF (n < 0) OR (n > LEN(a)) OR (n > LEN(b)) THEN RETURN FALSE END;
  d := 0; i := 0;
  WHILE i < n DO
    d := SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, d) /
      (SYSTEM.VAL(SET, ORD(a[i])) / SYSTEM.VAL(SET, ORD(b[i]))));
    INC(i)
  END;
  RETURN d = 0
END EqualConstantTime;

PROCEDURE XorByte*(a, b: CHAR): CHAR;
BEGIN
  RETURN CHR(SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, ORD(a)) / SYSTEM.VAL(SET, ORD(b))))
END XorByte;

END PasswordBytes.
