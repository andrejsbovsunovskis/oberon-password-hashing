MODULE BinaryDigest;

IMPORT SYSTEM, Sha256;

(* dataLen is measured in bytes; NUL is ordinary input data. *)
PROCEDURE Hash*(data: ARRAY OF SYSTEM.CHAR8; dataLen: INTEGER;
                VAR digest: ARRAY OF SYSTEM.CHAR8): INTEGER;
BEGIN
  RETURN Sha256.Hash(data, dataLen, digest)
END Hash;

END BinaryDigest.
