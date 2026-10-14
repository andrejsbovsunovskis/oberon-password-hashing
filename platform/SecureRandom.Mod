MODULE SecureRandom;

IMPORT Platform, SYSTEM;

(* Unix /dev/urandom is the operating-system CSPRNG interface on the supported targets. *)

PROCEDURE Fill*(VAR buffer: ARRAY OF SYSTEM.CHAR8; length: INTEGER): BOOLEAN;
VAR fd, error, got, pos, tries, zeros: INTEGER;
  path: ARRAY 32 OF SYSTEM.CHAR8; ok: BOOLEAN;
BEGIN
  ok := FALSE;
  IF (length >= 0) & (length <= LEN(buffer)) THEN
    IF length = 0 THEN ok := TRUE
    ELSE
      path := '/dev/urandom';
      error := Platform.OldRO(path, fd);
      IF error = 0 THEN
        pos := 0; tries := 0;
        WHILE (pos < length) & (tries < 4) DO
          error := Platform.Read(fd, SYSTEM.ADR(buffer[pos]), length - pos, got);
          IF (error # 0) OR (got <= 0) THEN INC(tries) ELSE pos := pos + got END
        END;
        error := Platform.CloseFile(fd);
        IF (pos = length) & (error = 0) THEN
          zeros := 0;
          WHILE (zeros < length) & (buffer[zeros] = 0X) DO INC(zeros) END;
          ok := zeros < length
        END
      END
    END
  END
  RETURN ok
END Fill;

END SecureRandom.
