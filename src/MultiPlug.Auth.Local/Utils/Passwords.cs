using System;
using System.Text;
using System.Security.Cryptography;
using System.Linq;

namespace MultiPlug.Auth.Local.Utils
{
    internal static class Passwords
    {
        private const int c_SaltSize = 32;
        private const string c_AlgorithmOnePrefix = "A%."; // Random Prefix. If the Algorithm is changed, add a New Prefix, keep this one.

        private static byte[] CreateSalt(int size)
        {
            RNGCryptoServiceProvider CryptoService = new RNGCryptoServiceProvider();
            byte[] Buffer = new byte[size];
            CryptoService.GetBytes(Buffer);
            return Buffer;
        }

        private static byte[] GeneratePasswordSaltedHash(byte[] thePlainPasswordText, byte[] theSalt)
        {
            HashAlgorithm HashAlgorithm = new SHA256Managed();

            byte[] PlainTextWithSaltBytes = new byte[thePlainPasswordText.Length + theSalt.Length];
            Array.Copy(thePlainPasswordText, PlainTextWithSaltBytes, thePlainPasswordText.Length);
            Array.Copy(theSalt, 0, PlainTextWithSaltBytes, thePlainPasswordText.Length, theSalt.Length);

            return HashAlgorithm.ComputeHash(PlainTextWithSaltBytes);
        }

        internal static string GenerateSaltedPassword(string thePassword)
        {
            var Salt = CreateSalt(c_SaltSize);
            var SaltedHash = GeneratePasswordSaltedHash(Encoding.UTF8.GetBytes(thePassword), Salt);

            byte[] combined = new byte[Salt.Length + SaltedHash.Length];
            Array.Copy(Salt, combined, Salt.Length);
            Array.Copy(SaltedHash, 0, combined, Salt.Length, SaltedHash.Length);

            return c_AlgorithmOnePrefix + Convert.ToBase64String(combined);
        }

        internal static bool AuthenticatePassword(string thePasswordPlainText, string thePasswordSalted)
        {
            if (thePasswordSalted.StartsWith(c_AlgorithmOnePrefix))
            {
                thePasswordSalted = thePasswordSalted.Substring(c_AlgorithmOnePrefix.Length);

                byte[] SaltAndSaltedPasswordBytes = Convert.FromBase64String(thePasswordSalted);
                byte[] Salt = SaltAndSaltedPasswordBytes.Take(c_SaltSize).ToArray();
                byte[] SaltedPassword = SaltAndSaltedPasswordBytes.Skip(c_SaltSize).Take(SaltAndSaltedPasswordBytes.Length).ToArray();
                byte[] ThisTimeSaltedPassword = GeneratePasswordSaltedHash(Encoding.UTF8.GetBytes(thePasswordPlainText), Salt);

                return SaltedPassword.SequenceEqual(ThisTimeSaltedPassword);
            }
            else
            {
                return thePasswordPlainText.Equals(thePasswordSalted);
            }
        }
    }
}
