MODULE PasswordStatus;

CONST
  Ok* = 0;
  InvalidArgument* = 1;
  InvalidState* = 2;
  BufferTooSmall* = 3;
  PasswordTooLong* = 4;
  InvalidPolicy* = 5;
  InvalidFormat* = 6;
  UnsupportedVersion* = 7;
  UnsupportedAlgorithm* = 8;
  PolicyRejected* = 9;
  RandomUnavailable* = 10;
  InternalError* = 11;

END PasswordStatus.
