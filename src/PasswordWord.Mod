MODULE PasswordWord;

IMPORT SYSTEM;

CONST Base = 65536;

TYPE Word* = INTEGER;

PROCEDURE Set*(VAR x: Word; hi, lo: INTEGER);
BEGIN
  x := SYSTEM.VAL(INTEGER,
    SYSTEM.VAL(SET, SYSTEM.LSH(hi MOD Base, 16)) + SYSTEM.VAL(SET, lo MOD Base))
END Set;

PROCEDURE Hi*(x: Word): INTEGER;
BEGIN RETURN SYSTEM.LSH(x, -16) MOD Base END Hi;

PROCEDURE Lo*(x: Word): INTEGER;
BEGIN RETURN SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, x) * SYSTEM.VAL(SET, Base - 1)) END Lo;

PROCEDURE FromBytes*(a, b, c, d: SYSTEM.CHAR8): Word;
BEGIN
  RETURN SYSTEM.VAL(INTEGER,
    SYSTEM.VAL(SET, SYSTEM.LSH(ORD(a) * 256 + ORD(b), 16)) +
    SYSTEM.VAL(SET, ORD(c) * 256 + ORD(d)))
END FromBytes;

PROCEDURE PutBytes*(x: Word; VAR a, b, c, d: SYSTEM.CHAR8);
VAR hi, lo: INTEGER;
BEGIN
  hi := Hi(x); lo := Lo(x);
  a := SYSTEM.VAL(SYSTEM.CHAR8, hi DIV 256); b := SYSTEM.VAL(SYSTEM.CHAR8, hi MOD 256);
  c := SYSTEM.VAL(SYSTEM.CHAR8, lo DIV 256); d := SYSTEM.VAL(SYSTEM.CHAR8, lo MOD 256)
END PutBytes;

PROCEDURE Add*(a, b: Word): Word;
VAR sum, modulus, topBit: SYSTEM.INT64; result: Word;
BEGIN
  (* Convert signed bit patterns to 0..2^32-1, add in SYSTEM.INT64, then convert
     back without signed INTEGER overflow. *)
  modulus := SYSTEM.LONG(Base) * Base;
  topBit := SYSTEM.LONG(32768) * Base;
  sum := SYSTEM.LONG(a); IF sum < 0 THEN sum := sum + modulus END;
  IF b < 0 THEN sum := sum + SYSTEM.LONG(b) + modulus ELSE sum := sum + SYSTEM.LONG(b) END;
  IF sum >= modulus THEN sum := sum - modulus END;
  IF sum >= topBit THEN result := (-2147483647 - 1) + SYSTEM.SHORT(sum - topBit) ELSE result := SYSTEM.SHORT(sum) END
  RETURN result
END Add;

PROCEDURE XorPart(a, b: INTEGER): INTEGER;
BEGIN RETURN SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, a) / SYSTEM.VAL(SET, b)) END XorPart;

PROCEDURE Xor*(a, b: Word): Word;
BEGIN RETURN SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, a) / SYSTEM.VAL(SET, b)) END Xor;

PROCEDURE AndPart(a, b: INTEGER): INTEGER;
BEGIN RETURN SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, a) * SYSTEM.VAL(SET, b)) END AndPart;

PROCEDURE And*(a, b: Word): Word;
BEGIN RETURN SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, a) * SYSTEM.VAL(SET, b)) END And;

PROCEDURE Not*(a: Word): Word;
BEGIN RETURN SYSTEM.VAL(INTEGER, -SYSTEM.VAL(SET, a)) END Not;

PROCEDURE Ror*(a: Word; n: INTEGER): Word;
VAR result: Word;
BEGIN
  n := n MOD 32;
  IF n = 0 THEN result := a ELSE result := SYSTEM.ROT(a, -n) END
  RETURN result
END Ror;

PROCEDURE Shr*(a: Word; n: INTEGER): Word;
VAR result: Word;
BEGIN
  IF n >= 32 THEN result := 0 ELSE result := SYSTEM.LSH(a, -n) END
  RETURN result
END Shr;

END PasswordWord.
