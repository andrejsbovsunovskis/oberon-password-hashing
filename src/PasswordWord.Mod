MODULE PasswordWord;

IMPORT SYSTEM;

CONST Base = 65536;

TYPE Word* = LONGINT;

PROCEDURE Set*(VAR x: Word; hi, lo: INTEGER);
BEGIN x := LONG(hi MOD Base) * Base + lo MOD Base END Set;

PROCEDURE Hi*(x: Word): INTEGER;
BEGIN RETURN SHORT(x DIV Base) END Hi;

PROCEDURE Lo*(x: Word): INTEGER;
BEGIN RETURN SHORT(x MOD Base) END Lo;

PROCEDURE FromBytes*(a, b, c, d: CHAR): Word;
BEGIN RETURN LONG(ORD(a) * 256 + ORD(b)) * Base + ORD(c) * 256 + ORD(d) END FromBytes;

PROCEDURE PutBytes*(x: Word; VAR a, b, c, d: CHAR);
VAR hi, lo: INTEGER;
BEGIN hi := Hi(x); lo := Lo(x); a := CHR(hi DIV 256); b := CHR(hi MOD 256); c := CHR(lo DIV 256); d := CHR(lo MOD 256) END PutBytes;

PROCEDURE Add*(a, b: Word): Word;
VAR hi, lo: INTEGER;
BEGIN lo := Lo(a) + Lo(b); hi := (Hi(a) + Hi(b) + lo DIV Base) MOD Base; RETURN LONG(hi) * Base + lo MOD Base END Add;

PROCEDURE XorPart(a, b: INTEGER): INTEGER;
BEGIN RETURN SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, a) / SYSTEM.VAL(SET, b)) END XorPart;

PROCEDURE Xor*(a, b: Word): Word;
BEGIN RETURN LONG(XorPart(Hi(a), Hi(b))) * Base + XorPart(Lo(a), Lo(b)) END Xor;

PROCEDURE AndPart(a, b: INTEGER): INTEGER;
BEGIN RETURN SYSTEM.VAL(INTEGER, SYSTEM.VAL(SET, a) * SYSTEM.VAL(SET, b)) END AndPart;

PROCEDURE And*(a, b: Word): Word;
BEGIN RETURN LONG(AndPart(Hi(a), Hi(b))) * Base + AndPart(Lo(a), Lo(b)) END And;

PROCEDURE Not*(a: Word): Word;
BEGIN RETURN LONG(65535 - Hi(a)) * Base + 65535 - Lo(a) END Not;

PROCEDURE Pow2(n: INTEGER): LONGINT;
VAR p: LONGINT; i: INTEGER;
BEGIN p := 1; i := 0; WHILE i < n DO p := p * 2; INC(i) END; RETURN p END Pow2;

PROCEDURE Ror*(a: Word; n: INTEGER): Word;
VAR p, q: LONGINT;
BEGIN n := n MOD 32; IF n = 0 THEN RETURN a END; p := Pow2(n); q := Pow2(32 - n); RETURN a DIV p + (a MOD p) * q END Ror;

PROCEDURE Shr*(a: Word; n: INTEGER): Word;
BEGIN IF n >= 32 THEN RETURN 0 ELSE RETURN a DIV Pow2(n) END END Shr;

END PasswordWord.
