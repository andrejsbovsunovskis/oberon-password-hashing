MODULE Sha256;

IMPORT PasswordStatus, PasswordBytes, W := PasswordWord;

CONST DigestLength* = 32; BlockLength* = 64;

TYPE Context* = RECORD
  h: ARRAY 8 OF W.Word;
  block: ARRAY BlockLength OF SHORTCHAR;
  used: INTEGER;
  bytesHi, bytesLo: W.Word;
  initialized, finished: BOOLEAN
END;

PROCEDURE C(hi, lo: INTEGER): W.Word;
BEGIN RETURN LONG(hi) * 65536 + lo END C;

PROCEDURE Add4(a, b, c, d: W.Word): W.Word;
BEGIN RETURN W.Add(W.Add(a, b), W.Add(c, d)) END Add4;

PROCEDURE Ch(x, y, z: W.Word): W.Word;
BEGIN RETURN W.Xor(W.And(x, y), W.And(W.Not(x), z)) END Ch;

PROCEDURE Maj(x, y, z: W.Word): W.Word;
BEGIN RETURN W.Xor(W.Xor(W.And(x, y), W.And(x, z)), W.And(y, z)) END Maj;

PROCEDURE Big0(x: W.Word): W.Word;
BEGIN RETURN W.Xor(W.Xor(W.Ror(x, 2), W.Ror(x, 13)), W.Ror(x, 22)) END Big0;

PROCEDURE Big1(x: W.Word): W.Word;
BEGIN RETURN W.Xor(W.Xor(W.Ror(x, 6), W.Ror(x, 11)), W.Ror(x, 25)) END Big1;

PROCEDURE Small0(x: W.Word): W.Word;
BEGIN RETURN W.Xor(W.Xor(W.Ror(x, 7), W.Ror(x, 18)), W.Shr(x, 3)) END Small0;

PROCEDURE Small1(x: W.Word): W.Word;
BEGIN RETURN W.Xor(W.Xor(W.Ror(x, 17), W.Ror(x, 19)), W.Shr(x, 10)) END Small1;

PROCEDURE K(i: INTEGER): W.Word;
BEGIN
  CASE i OF
  | 0: RETURN C(428AH, 2F98H) | 1: RETURN C(7137H, 4491H)
  | 2: RETURN C(0B5C0H, 0FBCFH) | 3: RETURN C(0E9B5H, 0DBA5H)
  | 4: RETURN C(3956H, 0C25BH) | 5: RETURN C(59F1H, 11F1H)
  | 6: RETURN C(923FH, 82A4H) | 7: RETURN C(0AB1CH, 5ED5H)
  | 8: RETURN C(0D807H, 0AA98H) | 9: RETURN C(1283H, 5B01H)
  | 10: RETURN C(2431H, 85BEH) | 11: RETURN C(550CH, 7DC3H)
  | 12: RETURN C(72BEH, 5D74H) | 13: RETURN C(80DEH, 0B1FEH)
  | 14: RETURN C(9BDCH, 06A7H) | 15: RETURN C(0C19BH, 0F174H)
  | 16: RETURN C(0E49BH, 69C1H) | 17: RETURN C(0EFBEH, 4786H)
  | 18: RETURN C(0FC1H, 9DC6H) | 19: RETURN C(240CH, 0A1CCH)
  | 20: RETURN C(2DE9H, 2C6FH) | 21: RETURN C(4A74H, 84AAH)
  | 22: RETURN C(5CB0H, 0A9DCH) | 23: RETURN C(76F9H, 88DAH)
  | 24: RETURN C(983EH, 5152H) | 25: RETURN C(0A831H, 0C66DH)
  | 26: RETURN C(0B003H, 27C8H) | 27: RETURN C(0BF59H, 7FC7H)
  | 28: RETURN C(0C6E0H, 0BF3H) | 29: RETURN C(0D5A7H, 9147H)
  | 30: RETURN C(06CAH, 6351H) | 31: RETURN C(1429H, 2967H)
  | 32: RETURN C(27B7H, 0A85H) | 33: RETURN C(2E1BH, 2138H)
  | 34: RETURN C(4D2CH, 6DFCH) | 35: RETURN C(5338H, 0D13H)
  | 36: RETURN C(650AH, 7354H) | 37: RETURN C(766AH, 0ABBH)
  | 38: RETURN C(81C2H, 0C92EH) | 39: RETURN C(9272H, 2C85H)
  | 40: RETURN C(0A2BFH, 0E8A1H) | 41: RETURN C(0A81AH, 664BH)
  | 42: RETURN C(0C24BH, 8B70H) | 43: RETURN C(0C76CH, 51A3H)
  | 44: RETURN C(0D192H, 0E819H) | 45: RETURN C(0D699H, 0624H)
  | 46: RETURN C(0F40EH, 3585H) | 47: RETURN C(106AH, 0A070H)
  | 48: RETURN C(19A4H, 0C116H) | 49: RETURN C(1E37H, 6C08H)
  | 50: RETURN C(2748H, 774CH) | 51: RETURN C(34B0H, 0BCB5H)
  | 52: RETURN C(391CH, 0CB3H) | 53: RETURN C(4ED8H, 0AA4AH)
  | 54: RETURN C(5B9CH, 0CA4FH) | 55: RETURN C(682EH, 6FF3H)
  | 56: RETURN C(748FH, 82EEH) | 57: RETURN C(78A5H, 636FH)
  | 58: RETURN C(84C8H, 7814H) | 59: RETURN C(8CC7H, 0208H)
  | 60: RETURN C(90BEH, 0FFFAH) | 61: RETURN C(0A450H, 6CEBH)
  | 62: RETURN C(0BEF9H, 0A3F7H) | 63: RETURN C(0C671H, 78F2H)
  END;
  RETURN C(0, 0)
END K;

PROCEDURE Transform(VAR c: Context; IN b: ARRAY OF SHORTCHAR);
VAR w: ARRAY 64 OF W.Word;
  a, bb, cc, d, e, f, g, h, t1, t2: W.Word;
  i: INTEGER;
BEGIN
  i := 0;
  WHILE i < 16 DO w[i] := W.FromBytes(b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]); INC(i) END;
  WHILE i < 64 DO w[i] := Add4(Small1(w[i - 2]), w[i - 7], Small0(w[i - 15]), w[i - 16]); INC(i) END;
  a := c.h[0]; bb := c.h[1]; cc := c.h[2]; d := c.h[3];
  e := c.h[4]; f := c.h[5]; g := c.h[6]; h := c.h[7];
  i := 0;
  WHILE i < 64 DO
    t1 := W.Add(W.Add(W.Add(W.Add(h, Big1(e)), Ch(e, f, g)), K(i)), w[i]);
    t2 := W.Add(Big0(a), Maj(a, bb, cc));
    h := g; g := f; f := e; e := W.Add(d, t1);
    d := cc; cc := bb; bb := a; a := W.Add(t1, t2);
    INC(i)
  END;
  c.h[0] := W.Add(c.h[0], a); c.h[1] := W.Add(c.h[1], bb);
  c.h[2] := W.Add(c.h[2], cc); c.h[3] := W.Add(c.h[3], d);
  c.h[4] := W.Add(c.h[4], e); c.h[5] := W.Add(c.h[5], f);
  c.h[6] := W.Add(c.h[6], g); c.h[7] := W.Add(c.h[7], h);
END Transform;

PROCEDURE Init*(VAR c: Context): INTEGER;
BEGIN
  c.h[0] := C(6A09H, 0E667H); c.h[1] := C(0BB67H, 0AE85H);
  c.h[2] := C(3C6EH, 0F372H); c.h[3] := C(0A54FH, 0F53AH);
  c.h[4] := C(510EH, 527FH); c.h[5] := C(9B05H, 688CH);
  c.h[6] := C(1F83H, 0D9ABH); c.h[7] := C(5BE0H, 0CD19H);
  c.used := 0; W.Set(c.bytesHi, 0, 0); W.Set(c.bytesLo, 0, 0);
  c.initialized := TRUE; c.finished := FALSE;
  RETURN PasswordStatus.Ok
END Init;

PROCEDURE Clear*(VAR c: Context);
VAR i: INTEGER;
BEGIN
  PasswordBytes.Clear(c.block, LEN(c.block));
  i := 0;
  WHILE i < LEN(c.h) DO W.Set(c.h[i], 0, 0); INC(i) END;
  W.Set(c.bytesHi, 0, 0); W.Set(c.bytesLo, 0, 0);
  c.used := 0; c.initialized := FALSE; c.finished := FALSE
END Clear;

PROCEDURE AddLength(VAR c: Context; n: INTEGER): BOOLEAN;
VAR q, old, newLo, newHi: W.Word;
BEGIN
  W.Set(q, n DIV 65536, n MOD 65536); old := c.bytesLo; newLo := W.Add(c.bytesLo, q); newHi := c.bytesHi;
  IF W.Hi(newLo) < W.Hi(old) THEN newHi := W.Add(newHi, C(0, 1)) END;
  IF W.Hi(newHi) >= 8192 THEN RETURN FALSE END;
  c.bytesLo := newLo; c.bytesHi := newHi;
  RETURN TRUE
END AddLength;

PROCEDURE Update*(VAR c: Context; IN data: ARRAY OF SHORTCHAR; dataLen: INTEGER): INTEGER;
VAR pos, take: INTEGER;
BEGIN
  IF ~c.initialized OR c.finished THEN RETURN PasswordStatus.InvalidState END;
  IF ~PasswordBytes.Valid(data, dataLen) THEN Clear(c); RETURN PasswordStatus.InvalidArgument END;
  IF ~AddLength(c, dataLen) THEN Clear(c); RETURN PasswordStatus.InvalidArgument END;
  pos := 0;
  WHILE pos < dataLen DO
    take := BlockLength - c.used;
    IF take > dataLen - pos THEN take := dataLen - pos END;
    PasswordBytes.Copy(data, pos, c.block, c.used, take);
    c.used := c.used + take; pos := pos + take;
    IF c.used = BlockLength THEN Transform(c, c.block); c.used := 0 END
  END;
  RETURN PasswordStatus.Ok
END Update;

PROCEDURE Final*(VAR c: Context; VAR digest: ARRAY OF SHORTCHAR): INTEGER;
VAR i: INTEGER; bitHi, bitLo: W.Word;
  a, b, d, e: SHORTCHAR;
BEGIN
  IF LEN(digest) < DigestLength THEN PasswordBytes.Clear(digest, LEN(digest)); Clear(c); RETURN PasswordStatus.BufferTooSmall END;
  IF ~c.initialized OR c.finished THEN PasswordBytes.Clear(digest, DigestLength); Clear(c); RETURN PasswordStatus.InvalidState END;
  c.block[c.used] := 80X; INC(c.used);
  IF c.used > 56 THEN
    WHILE c.used < BlockLength DO c.block[c.used] := 0X; INC(c.used) END;
    Transform(c, c.block); c.used := 0
  END;
  WHILE c.used < 56 DO c.block[c.used] := 0X; INC(c.used) END;
  bitLo := c.bytesLo; bitLo := C((W.Hi(bitLo) * 8 + W.Lo(bitLo) DIV 8192) MOD 65536, (W.Lo(bitLo) * 8) MOD 65536);
  bitHi := c.bytesHi; bitHi := C((W.Hi(bitHi) * 8 + W.Lo(bitHi) DIV 8192) MOD 65536, (W.Lo(bitHi) * 8) MOD 65536);
  bitHi := W.Add(bitHi, C(0, W.Hi(c.bytesLo) DIV 8192));
  W.PutBytes(bitHi, a, b, d, e); c.block[56] := a; c.block[57] := b; c.block[58] := d; c.block[59] := e;
  W.PutBytes(bitLo, a, b, d, e); c.block[60] := a; c.block[61] := b; c.block[62] := d; c.block[63] := e;
  Transform(c, c.block);
  i := 0;
  WHILE i < 8 DO W.PutBytes(c.h[i], digest[i * 4], digest[i * 4 + 1], digest[i * 4 + 2], digest[i * 4 + 3]); INC(i) END;
  PasswordBytes.Clear(c.block, BlockLength); c.used := 0; c.finished := TRUE;
  RETURN PasswordStatus.Ok
END Final;

PROCEDURE Hash*(IN data: ARRAY OF SHORTCHAR; dataLen: INTEGER; VAR digest: ARRAY OF SHORTCHAR): INTEGER;
VAR c: Context; status: INTEGER;
BEGIN
  IF LEN(digest) < DigestLength THEN PasswordBytes.Clear(digest, LEN(digest)); RETURN PasswordStatus.BufferTooSmall END;
  status := Init(c);
  IF status = PasswordStatus.Ok THEN status := Update(c, data, dataLen) END;
  IF status = PasswordStatus.Ok THEN status := Final(c, digest) ELSE PasswordBytes.Clear(digest, DigestLength) END;
  RETURN status
END Hash;

END Sha256.
