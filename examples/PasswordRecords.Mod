MODULE PasswordRecords;

IMPORT SYSTEM, PasswordHash, PasswordStatus, PasswordBytes;

(* Applications store encoded records unchanged and decide what to tell users. *)

PROCEDURE CreateRecord*(password: ARRAY OF SYSTEM.CHAR8; passwordLen: INTEGER;
                        VAR record: ARRAY OF SYSTEM.CHAR8; VAR recordLen: INTEGER): INTEGER;
VAR policy: PasswordHash.Policy;
BEGIN
  PasswordHash.DefaultPolicy(policy);
  RETURN PasswordHash.Create(password, passwordLen, policy, record, recordLen)
END CreateRecord;

PROCEDURE VerifyRecord*(password: ARRAY OF SYSTEM.CHAR8; passwordLen: INTEGER;
                        record: ARRAY OF SYSTEM.CHAR8; recordLen: INTEGER;
                        VAR accepted, replaceRecord: BOOLEAN): INTEGER;
VAR policy: PasswordHash.Policy;
  status: INTEGER;
BEGIN
  accepted := FALSE; replaceRecord := FALSE;
  PasswordHash.DefaultPolicy(policy);
  status := PasswordHash.Verify(password, passwordLen, record, recordLen, policy, accepted, replaceRecord);
  IF status # PasswordStatus.Ok THEN
    (* Treat every parser, policy, and KDF failure as rejected authentication. *)
    accepted := FALSE; replaceRecord := FALSE
  END;
  RETURN status
END VerifyRecord;

PROCEDURE VerifyAndRefresh*(password: ARRAY OF SYSTEM.CHAR8; passwordLen: INTEGER;
                            record: ARRAY OF SYSTEM.CHAR8; recordLen: INTEGER;
                            VAR replacement: ARRAY OF SYSTEM.CHAR8; VAR replacementLen: INTEGER;
                            VAR accepted, replaced: BOOLEAN): INTEGER;
VAR policy: PasswordHash.Policy;
  needsRehash: BOOLEAN;
  status: INTEGER;
BEGIN
  accepted := FALSE; replaced := FALSE; PasswordBytes.Clear(replacement, LEN(replacement)); replacementLen := 0;
  PasswordHash.DefaultPolicy(policy);
  status := PasswordHash.Verify(password, passwordLen, record, recordLen, policy, accepted, needsRehash);
  IF (status = PasswordStatus.Ok) & accepted & needsRehash THEN
    status := PasswordHash.Create(password, passwordLen, policy, replacement, replacementLen);
    IF status = PasswordStatus.Ok THEN replaced := TRUE ELSE accepted := FALSE END
  END;
  IF status # PasswordStatus.Ok THEN accepted := FALSE; replaced := FALSE END;
  RETURN status
END VerifyAndRefresh;

END PasswordRecords.
