MODULE BinaryDigest;

IMPORT Sha256;

(* dataLen is measured in bytes; NUL is ordinary input data. *)
PROCEDURE Hash*(IN data: ARRAY OF SHORTCHAR; dataLen: INTEGER;
                VAR digest: ARRAY OF SHORTCHAR): INTEGER;
BEGIN
  RETURN Sha256.Hash(data, dataLen, digest)
END Hash;

END BinaryDigest.
