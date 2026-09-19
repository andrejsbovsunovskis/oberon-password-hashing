MODULE PasswordRecords;

IMPORT PasswordHash, PasswordStatus;

(* Applications store encoded records unchanged and decide what to tell users. *)

PROCEDURE CreateRecord*(IN password: ARRAY OF SHORTCHAR; passwordLen: INTEGER;
                        VAR record: ARRAY OF SHORTCHAR; VAR recordLen: INTEGER): INTEGER;
VAR policy: PasswordHash.Policy;
BEGIN
  PasswordHash.DefaultPolicy(policy);
  RETURN PasswordHash.Create(password, passwordLen, policy, record, recordLen)
END CreateRecord;

PROCEDURE VerifyRecord*(IN password: ARRAY OF SHORTCHAR; passwordLen: INTEGER;
                        IN record: ARRAY OF SHORTCHAR; recordLen: INTEGER;
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

END PasswordRecords.
