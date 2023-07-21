using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //creating the table
            char[,] table = new char[26, 26];
            for (int row = 0; row < 26; row++)
            {
                for (int col = 0; col < 26; col++)
                {
                    int repeat = row + col;
                    if (repeat >= 26)
                        repeat = repeat - 26;
                    repeat = repeat + 97;
                    char index = (char)repeat;
                    table[row, col] = index;
                }
            }
            // finding the key by the intersection between col&row
            cipherText = cipherText.ToLower();
            string thekey = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int row = 0;
                int col = plainText[i] - 'a';
                for (int j = 0; j < 26; j++)
                {
                    if (table[j, col] == cipherText[i])
                        row = j;
                }
                thekey += (char)('a' + row);
                string check = Encrypt(plainText, thekey);

                if (check.Equals(cipherText.ToUpper()))
                    break;
            }


            return thekey;
        }

        public string Decrypt(string cipherText, string key)
        {
            string result = "";
            key = key.ToUpper();
            string new_key = key;
            int x = 0;
            if (key.Length < cipherText.Length)
                x = cipherText.Length - key.Length;

            for (int i = 0; i < new_key.Length; i++)
                // The encryption equation (E) for a Vigenere plain: Plain text P = D(C, K) = (Ci - Ki) mod 26.
                result += Convert.ToChar((((cipherText[i] - 65) - (new_key[i] - 65) + 26) % 26) + 65);
            for (int i = 0; i < x; i++)
                result += Convert.ToChar((((cipherText[i + new_key.Length] - 65) - (result[i] - 65) + 26) % 26) + 65);
            return result.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string new_key = key;
            string cipherText = "";
            if (plainText.Length < key.Length)
                new_key = new_key.Substring(plainText.Length);

            if (key.Length < plainText.Length)
            {
                int x = plainText.Length - key.Length;
                for (int i = 0; i < x; i++)
                {
                    new_key += plainText[i];
                }

            }
            for (int i = 0; i < new_key.Length; i++)
            {
                // The encryption equation (E) for a Vigenere cipher: Cipher text, C = E (K, P) = (Pi + Ki) mod 26.
                cipherText += Convert.ToChar((((plainText[i] - 97) + (new_key[i] - 97)) % 26) + 97);
            }
            return cipherText.ToUpper();
        }
    }
}
