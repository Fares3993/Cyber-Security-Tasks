using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES Des = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            string TripleDesOutputTxt = Des.Decrypt(cipherText, key[0]);
            TripleDesOutputTxt = Des.Encrypt(TripleDesOutputTxt, key[1]);
            TripleDesOutputTxt = Des.Decrypt(TripleDesOutputTxt, key[0]);
            return TripleDesOutputTxt;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string TripleDesOutputTxt = Des.Encrypt(plainText, key[0]);
            TripleDesOutputTxt = Des.Decrypt(TripleDesOutputTxt, key[1]);
            TripleDesOutputTxt = Des.Encrypt(TripleDesOutputTxt, key[0]);
            return TripleDesOutputTxt;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}