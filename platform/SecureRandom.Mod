MODULE SecureRandom;

IMPORT Platform, SYSTEM;

(* Unix /dev/urandom is the operating-system CSPRNG interface on the supported targets. *)

PROCEDURE Fill*(VAR buffer: ARRAY OF SHORTCHAR; length: INTEGER): BOOLEAN;
VAR fd, error, got, pos, tries, zeros: INTEGER;
  path: ARRAY 32 OF SHORTCHAR;
BEGIN
  IF (length < 0) OR (length > LEN(buffer)) THEN RETURN FALSE END;
  IF length = 0 THEN RETURN TRUE END;
  path := '/dev/urandom';
  error := Platform.OldRO(path, fd);
  IF error # 0 THEN RETURN FALSE END;
  pos := 0; tries := 0;
  WHILE (pos < length) & (tries < 4) DO
    error := Platform.Read(fd, SYSTEM.ADR(buffer[pos]), length - pos, got);
    IF (error # 0) OR (got <= 0) THEN INC(tries) ELSE pos := pos + got END
  END;
  error := Platform.CloseFile(fd);
  IF (pos # length) OR (error # 0) THEN RETURN FALSE END;
  zeros := 0;
  WHILE zeros < length DO
    IF buffer[zeros] # 0X THEN RETURN TRUE END;
    INC(zeros)
  END;
  RETURN FALSE
END Fill;

END SecureRandom.
