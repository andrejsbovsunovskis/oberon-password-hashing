MODULE HmacSha256;

IMPORT PasswordStatus, PasswordBytes, Sha256;

CONST MacLength* = Sha256.DigestLength;

TYPE Context* = RECORD
  inner, outer: Sha256.Context;
  ready: BOOLEAN
END;

PROCEDURE Clear*(VAR c: Context);
BEGIN
  Sha256.Clear(c.inner); Sha256.Clear(c.outer);
  c.ready := FALSE
END Clear;

PROCEDURE Prepare*(VAR c: Context; IN key: ARRAY OF SHORTCHAR; keyLen: INTEGER): INTEGER;
VAR k, pad: ARRAY Sha256.BlockLength OF SHORTCHAR;
  digest: ARRAY Sha256.DigestLength OF SHORTCHAR;
  i, status: INTEGER;
BEGIN
  c.ready := FALSE;
  IF ~PasswordBytes.Valid(key, keyLen) THEN RETURN PasswordStatus.InvalidArgument END;
  PasswordBytes.Clear(k, LEN(k));
  IF keyLen > Sha256.BlockLength THEN
    status := Sha256.Hash(key, keyLen, digest);
    IF status # PasswordStatus.Ok THEN PasswordBytes.Clear(digest, LEN(digest)); RETURN status END;
    PasswordBytes.Copy(digest, 0, k, 0, LEN(digest));
    PasswordBytes.Clear(digest, LEN(digest))
  ELSE
    PasswordBytes.Copy(key, 0, k, 0, keyLen)
  END;
  i := 0;
  WHILE i < Sha256.BlockLength DO pad[i] := PasswordBytes.XorByte(k[i], 36X); INC(i) END;
  status := Sha256.Init(c.inner);
  IF status = PasswordStatus.Ok THEN status := Sha256.Update(c.inner, pad, LEN(pad)) END;
  i := 0;
  WHILE i < Sha256.BlockLength DO pad[i] := PasswordBytes.XorByte(k[i], 5CX); INC(i) END;
  IF status = PasswordStatus.Ok THEN status := Sha256.Init(c.outer) END;
  IF status = PasswordStatus.Ok THEN status := Sha256.Update(c.outer, pad, LEN(pad)) END;
  PasswordBytes.Clear(k, LEN(k)); PasswordBytes.Clear(pad, LEN(pad));
  IF status = PasswordStatus.Ok THEN c.ready := TRUE END;
  RETURN status
END Prepare;

PROCEDURE ComputePrepared*(IN c: Context; IN data: ARRAY OF SHORTCHAR; dataLen: INTEGER; VAR mac: ARRAY OF SHORTCHAR): INTEGER;
VAR inner, outer: Sha256.Context;
  tmp: ARRAY MacLength OF SHORTCHAR;
  status: INTEGER;
BEGIN
  IF LEN(mac) < MacLength THEN PasswordBytes.Clear(mac, LEN(mac)); RETURN PasswordStatus.BufferTooSmall END;
  IF ~c.ready THEN PasswordBytes.Clear(mac, MacLength); RETURN PasswordStatus.InvalidState END;
  inner := c.inner; outer := c.outer;
  status := Sha256.Update(inner, data, dataLen);
  IF status = PasswordStatus.Ok THEN status := Sha256.Final(inner, tmp) END;
  IF status = PasswordStatus.Ok THEN status := Sha256.Update(outer, tmp, LEN(tmp)) END;
  IF status = PasswordStatus.Ok THEN status := Sha256.Final(outer, mac) ELSE PasswordBytes.Clear(mac, MacLength) END;
  Sha256.Clear(inner); Sha256.Clear(outer);
  PasswordBytes.Clear(tmp, LEN(tmp));
  RETURN status
END ComputePrepared;

PROCEDURE Compute*(IN key: ARRAY OF SHORTCHAR; keyLen: INTEGER; IN data: ARRAY OF SHORTCHAR; dataLen: INTEGER; VAR mac: ARRAY OF SHORTCHAR): INTEGER;
VAR c: Context; status: INTEGER;
BEGIN
  status := Prepare(c, key, keyLen);
  IF status = PasswordStatus.Ok THEN status := ComputePrepared(c, data, dataLen, mac) ELSE PasswordBytes.Clear(mac, LEN(mac)) END;
  Clear(c);
  RETURN status
END Compute;

END HmacSha256.
