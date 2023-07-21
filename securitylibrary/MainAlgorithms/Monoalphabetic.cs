using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string key, alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[] key_elements = Enumerable.Repeat(' ', 26).ToArray();
            for (int x = 0; x < plainText.Length; x++)
            {
                int j = 0;
                while (j < alphabet.Length)
                {
                    if (plainText[x] == alphabet[j])
                    {
                        key_elements[j] = cipherText[x]; //Store unique characters from cipher text to key list at the same index
                    }
                    j++;
                }
            }

            for (int i = 0; i < key_elements.Length; i++)
            {
                if (key_elements[i] == ' ')
                {
                    for (int j = 0; j < alphabet.Length; j++)
                    {
                        if (!key_elements.Contains(alphabet[j]))
                        {
                            key_elements[i] = alphabet[j];
                        }
                    }
                }
            }
            key = new string(key_elements);
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            cipherText = cipherText.ToLower();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = -1;
                for (int j = 0; j < key.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        index = j;
                        int c = index + 97;

                        plainText += (char)c;
                    }

                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string cipher = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char c = plainText[i];
                int cToi = (int)c;
                int index = cToi - 97;
                cipher += key[index];

            }
            return cipher.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            char[] res = new char[cipher.Length];
            int max = -100;
            List<int> freq = new List<int>();
            char[] letter = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm',
                'f', 'p', 'g','w', 'y', 'b','v','k','x','j', 'q' ,'z'};
            for (int i = 0; i < cipher.Length; i++)
            {
                int count = 0;
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (cipher[i] == cipher[j])
                    {
                        count++;
                    }

                }
                freq.Add(count);

            }
            int index_letter = 0;
            for (int i = 0; i < freq.Count; i++)
            {
                int max_freq = freq.Max();
                if (max_freq == -100000)
                {
                    break;
                }
                int size_freq = freq.Count();

                for (int j = 0; j < size_freq; j++)
                {

                    if (freq[j] == max_freq)
                    {
                        res[j] = letter[index_letter];
                        freq[j] = -100000;
                    }

                }
                index_letter++;
            }

            string x = "";
            for (int i = 0; i < res.Length; i++)
            {
                x += res[i];
            }

            x = x.ToLower();
            return x;
        }
    }
}