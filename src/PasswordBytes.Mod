MODULE PasswordBytes;

IMPORT SYSTEM;

(* In Ofront+ Oberon-07, array/record parameters without VAR are read-only
   references. Explicit CHAR8 keeps octets 8-bit even with fob's -7w. *)

PROCEDURE Valid*(a: ARRAY OF SYSTEM.CHAR8; n: INTEGER): BOOLEAN;
BEGIN
  RETURN (n >= 0) & (n <= LEN(a))
END Valid;

PROCEDURE Clear*(VAR a: ARRAY OF SYSTEM.CHAR8; n: INTEGER);
VAR i, limit: INTEGER;
BEGIN
  limit := n;
  IF limit < 0 THEN limit := 0 END;
  IF limit > LEN(a) THEN limit := LEN(a) END;
  i := 0;
  WHILE i < limit DO a[i] := 0X; INC(i) END
END Clear;

PROCEDURE ClearWords*(VAR a: ARRAY OF INTEGER; n: INTEGER);
VAR i, limit: INTEGER;
BEGIN
  limit := n;
  IF limit < 0 THEN limit := 0 END;
  IF limit > LEN(a) THEN limit := LEN(a) END;
  i := 0;
  WHILE i < limit DO a[i] := 0; INC(i) END
END ClearWords;

PROCEDURE Copy*(src: ARRAY OF SYSTEM.CHAR8; srcPos: INTEGER;
               VAR dst: ARRAY OF SYSTEM.CHAR8; dstPos, n: INTEGER);
VAR i: INTEGER;
BEGIN
  IF (srcPos >= 0) & (dstPos >= 0) & (n >= 0) &
     (srcPos <= LEN(src)) & (n <= LEN(src) - srcPos) &
     (dstPos <= LEN(dst)) & (n <= LEN(dst) - dstPos) THEN
    i := 0;
    WHILE i < n DO dst[dstPos + i] := src[srcPos + i]; INC(i) END
  END
END Copy;

PROCEDURE EqualConstantTime*(a, b: ARRAY OF SYSTEM.CHAR8; n: INTEGER): BOOLEAN;
VAR i, d, x, y: INTEGER; valid: BOOLEAN;
BEGIN
  valid := (n >= 0) & (n <= LEN(a)) & (n <= LEN(b));
  d := 0;
  IF valid THEN
    i := 0;
    WHILE i < n DO
      x := ORD(a[i]); y := ORD(b[i]);
      d := SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, d) /
        (SYSTEM.VAL(SET, x) / SYSTEM.VAL(SET, y)));
      INC(i)
    END
  END
  RETURN valid & (d = 0)
END EqualConstantTime;

PROCEDURE XorByte*(a, b: SYSTEM.CHAR8): SYSTEM.CHAR8;
VAR x, y: INTEGER;
BEGIN
  x := ORD(a); y := ORD(b);
  RETURN SYSTEM.VAL(SYSTEM.CHAR8, SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, x) / SYSTEM.VAL(SET, y)))
END XorByte;

END PasswordBytes.
