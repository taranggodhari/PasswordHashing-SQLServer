using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;

namespace PassHash
{
    public class PasswordHashing
    {
        //define constants
        public const int SALTBYTESIZE = 24;
        public const int HASHBYTESIZE = 20;
        public const int PBKDF2ITERATIONS = 10000;
        public const int ITERATIONINDEX = 0;
        public const int SALTINDEX = 1;
        public const int PBKDF2INDEX = 2;

        //For encrypting password(Use when user register)
        public static string HashPassword(string password)
        {
            var cryptoProvider = new RNGCryptoServiceProvider();
            byte[] salt = new byte[SALTBYTESIZE];
            cryptoProvider.GetBytes(salt);

            var hash = GetPbkdf2Bytes(password, salt, PBKDF2ITERATIONS, HASHBYTESIZE);
            return PBKDF2ITERATIONS + ":" +
                   Convert.ToBase64String(salt) + ":" +
                   Convert.ToBase64String(hash);
        }

        //For validating password( User when user log in)
        public static bool ValidatePassword(string password, string correctHash)
        {
            char[] delimiter = { ':' };
            var split = correctHash.Split(delimiter);
            var iterations = Int32.Parse(split[ITERATIONINDEX]);
            var salt = Convert.FromBase64String(split[SALTINDEX]);
            var hash = Convert.FromBase64String(split[PBKDF2INDEX]);

            var testHash = GetPbkdf2Bytes(password, salt, iterations, hash.Length);
            return SlowEquals(hash, testHash);
        }

        private static bool SlowEquals(byte[] a, byte[] b)
        {
            var diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        private static byte[] GetPbkdf2Bytes(string password, byte[] salt, int iterations, int outputBytes)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt);
            pbkdf2.IterationCount = iterations;
            return pbkdf2.GetBytes(outputBytes);
        }
    }
}