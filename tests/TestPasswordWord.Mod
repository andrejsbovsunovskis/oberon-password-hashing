MODULE TestPasswordWord;

IMPORT PasswordWord;

VAR a, b, got: PasswordWord.Word;

BEGIN
  PasswordWord.Set(a, 0FFFFH, 0FFFFH);
  PasswordWord.Set(b, 0, 1);
  got := PasswordWord.Add(a, b);
  ASSERT(PasswordWord.Hi(got) = 0, 1); ASSERT(PasswordWord.Lo(got) = 0, 2);

  PasswordWord.Set(a, 8000H, 0); got := PasswordWord.Ror(a, 1);
  ASSERT(PasswordWord.Hi(got) = 4000H, 3); ASSERT(PasswordWord.Lo(got) = 0, 4);
  PasswordWord.Set(a, 0, 1); got := PasswordWord.Ror(a, 1);
  ASSERT(PasswordWord.Hi(got) = 8000H, 5); ASSERT(PasswordWord.Lo(got) = 0, 6);
  PasswordWord.Set(a, 8000H, 0); got := PasswordWord.Shr(a, 31);
  ASSERT(PasswordWord.Hi(got) = 0, 7); ASSERT(PasswordWord.Lo(got) = 1, 8)
END TestPasswordWord.
