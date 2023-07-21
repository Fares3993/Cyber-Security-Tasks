using System;
using System.Collections.Generic;
using System.Linq;


namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            for (int N1=0;N1 < 26; N1++)
            {
                for (int N2 = 0; N2 < 26; N2++)
                {
                    for (int N3 = 0; N3 < 26; N3++)
                    {
                        for (int N4 = 0; N4 < 26; N4++)
                        {
                            List<int> ciphertest =  Encrypt(plainText, new List<int> { N1, N2, N3, N4 });
                            if (ciphertest.SequenceEqual(cipherText)) {
                              return new List<int> { N1, N2, N3, N4 };
                            };
                        }

                    }
                }
            }
            throw new SecurityLibrary.InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int M = (int)Math.Sqrt(key.Count);
            List<int> k_reverse = new List<int>();
            List<int> Rus = new List<int>();
            if (M == 2)
            {
                Double y = ( (key[0] * key[3]) - (key[1] * key[2]));
                double x = 1 / y;
                k_reverse.Add((int)(x * key[3]));
                k_reverse.Add((int)(-1 * x * key[1]));
                k_reverse.Add((int)(-1 * x * key[2]));
                k_reverse.Add((int)(x * key[0]));

            }
            else
            {
                // first step 
                int a = key[0] * ((key[4] * key[8]) - (key[5] * key[7]));
                int b = key[1] * ((key[3] * key[8]) - (key[5] * key[6])) * -1;
                int c = key[2] * ((key[3] * key[7]) - (key[4] * key[6]));
                int determ = a + b + c;
                determ = determ % 26;
                if (determ < 0) determ = determ + 26;
                // second       b x det (k) mod 26 = 1
                if (determ == 25)
                {
                    b = 25;
                }
                else
                {
                    determ = 26 - determ;
                    c = 27;
                    while (true)
                    {
                        if (c % determ == 0)
                        {
                            c = c / determ;
                            break;
                        }
                        c = c + 26;
                    }
                    b = 26 - c;
                }

                // third step

                List<int> k = new List<int>();
                int k0 = b * 1 * ((key[4] * key[8]) - (key[5] * key[7]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);

                k0 = b * -1 * ((key[3] * key[8]) - (key[5] * key[6]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);


                k0 = b * 1 * ((key[3] * key[7]) - (key[4] * key[6]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);


                k0 = b * -1 * ((key[1] * key[8]) - (key[2] * key[7]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);


                k0 = b * 1 * ((key[0] * key[8]) - (key[2] * key[6]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);


                k0 = b * -1 * ((key[0] * key[7]) - (key[1] * key[6]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);


                k0 = b * 1 * ((key[1] * key[5]) - (key[2] * key[4]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);


                k0 = b * -1 * ((key[0] * key[5]) - (key[3] * key[2]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);


                k0 = b * 1 * ((key[0] * key[4]) - (key[1] * key[3]));
                k0 = k0 % 26;
                if (k0 < 0) k0 = k0 + 26;
                k.Add(k0);

                k_reverse = MakeTranspose(k);
            }
            int s = k_reverse.Sum();
            if (s == 0)
            {
                throw new SystemException();
            }
            Console.WriteLine("s");
            return Encrypt(cipherText, k_reverse);
        }

        public List<int> MakeTranspose(List<int> k)
        {
            List<int> k_reverse = new List<int>();
            for (int i = 0; i < k.Count; i++)
            {
                if (i == 1)
                {
                    k_reverse.Add(k[3]);
                }
                else if (i == 2)
                {
                    k_reverse.Add(k[6]);
                }
                else if (i == 3)
                {
                    k_reverse.Add(k[1]);
                }
                else if (i == 5)
                {
                    k_reverse.Add(k[7]);
                }
                else if (i == 6)
                {
                    k_reverse.Add(k[2]);
                }
                else if (i == 7)
                {
                    k_reverse.Add(k[5]);
                }
                else
                {
                    k_reverse.Add(k[i]);
                }
            }

            return k_reverse;
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int M = (int)Math.Sqrt(key.Count);
            List<int> Rus = new List<int>();

            for (int j = 0; j < plainText.Count; j = j + M) /// key    { 1, 10, 0, 0, 20, 1, 2, 15, 2 };
            {
                for (int i = 0; i < key.Count; i = i + M) /// plain   { 5, 21, 2, 5, 2, 16, 19, 14, 1 };
                {
                    int r_M;
                    int r_S = 0;
                    for (int k = 0; k < M; k++)
                    {
                        r_M = key[i + k] * plainText[j + k];
                        r_S += r_M;
                    }
                    r_S = r_S % 26;
                    if (r_S < 0) r_S = r_S + 26;
                    Rus.Add(r_S);
                }

            }

            return Rus;
        }

        public string Encrypt(string plainText, string key)
        {
            int code = -1;
            char c;
            List<int> plainTxt = StrToList(plainText);
            List<int> key_List = StrToList(key);
            List<int> Cipher_List = Encrypt(plainTxt, key_List);

            return ListTOStr(Cipher_List);
        }

        public List<int> StrToList(string Text)
        {
            List<int> List = new List<int>();
            int code = -1;
            Text = Text.ToUpper();
            for (int i = 0; i < Text.Length; i++)
            {
                code = (int)Text[i];
                code = (code - 65);
                List.Add(code);
            }
            return List;
        }

        public String ListTOStr(List<int> List)
        {
            int code = -1;
            char c;
            String ciphertxt = "";
            for (int i = 0; i < List.Count; i++)
            {
                c = (char)code;
                ciphertxt += c;
            }
            return ciphertxt;
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            cipher3 = MakeTranspose(cipher3);
            List<int> k_reverse = Decrypt(cipher3, plain3);
            return k_reverse;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
