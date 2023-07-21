using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{


    public class PlayFair : ICryptographic_Technique<string, string>
    {
        Dictionary<char, bool> letters = new Dictionary<char, bool>();
        public PlayFair()
        {
            for (int i = 97; i <= 122; i++)
            {
                char letter = (char)i;
                letters.Add(letter, true);
            }
        }
        public string Decrypt(string cipherText, string key)
        {
            char[,] mat = _SetupMatrix(key);
            List<String> divided = _Divide(cipherText.ToLower());
            List<String> decryptedPairs = new List<string>();


            foreach (String e in divided)
            {
                List<Tuple<int, int>> indecies = new List<Tuple<int, int>>();

                foreach (char c in e)
                {
                    indecies.Add(_GetIndex(mat, c));
                }

                int x0, y0, x1, y1;

                if (indecies[0].Item1 == indecies[1].Item1) // same row
                {
                    x0 = indecies[0].Item2 - 1;
                    y0 = indecies[0].Item1;
                    x1 = indecies[1].Item2 - 1;
                    y1 = indecies[1].Item1;

                    if (x0 == -1) x0 = 4; // wrap left if needed
                    else if (x1 == -1) x1 = 4;
                }
                else if (indecies[0].Item2 == indecies[1].Item2) // same column
                {
                    x0 = indecies[0].Item2;
                    y0 = indecies[0].Item1 - 1;
                    x1 = indecies[1].Item2;
                    y1 = indecies[1].Item1 - 1;

                    if (y0 == -1) y0 = 4; // wrap up if needed
                    else if (y1 == -1) y1 = 4;
                }
                else
                {
                    x0 = indecies[1].Item2;
                    y0 = indecies[0].Item1;
                    x1 = indecies[0].Item2;
                    y1 = indecies[1].Item1;
                }
                decryptedPairs.Add($"{mat[y0, x0]}{mat[y1, x1]}");
            }

            String r = _RemoveX(decryptedPairs);

            return r;
        }

        public string Encrypt(string plainText, string key)
        {
            String r = "";
            char[,] mat = _SetupMatrix(key);
            List<String> divided = _Divide(plainText);

            foreach (String e in divided)
            {
                List<Tuple<int, int>> indecies = new List<Tuple<int, int>>();

                foreach (char c in e)
                {
                    indecies.Add(_GetIndex(mat, c));
                }

                int x0, y0, x1, y1;

                if (indecies[0].Item1 == indecies[1].Item1) // same row
                {
                    x0 = indecies[0].Item2 + 1;
                    y0 = indecies[0].Item1;
                    x1 = indecies[1].Item2 + 1;
                    y1 = indecies[1].Item1;

                    if (x0 == 5) x0 = 0; // wrap left if needed
                    else if (x1 == 5) x1 = 0;
                }
                else if (indecies[0].Item2 == indecies[1].Item2) // same column
                {
                    x0 = indecies[0].Item2;
                    y0 = indecies[0].Item1 + 1;
                    x1 = indecies[1].Item2;
                    y1 = indecies[1].Item1 + 1;

                    if (y0 == 5) y0 = 0; // wrap up if needed
                    else if (y1 == 5) y1 = 0;
                }
                else
                {
                    x0 = indecies[1].Item2;
                    y0 = indecies[0].Item1;
                    x1 = indecies[0].Item2;
                    y1 = indecies[1].Item1;
                }
                r += $"{mat[y0, x0]}{mat[y1, x1]}";
            }

            return r;
        }
        private char[,] _SetupMatrix(string key)
        {
            char[,] mat = new char[5, 5];
            int ix = 0;
            int iy = 0;

            foreach (char letter in key)
            {
                if (letters[letter])
                {
                    mat[iy, ix] = letter;
                    letters[letter] = false;

                    ix++;
                    if (ix == 5)
                    {
                        ix = 0;
                        iy++;
                    }

                    if (letter.Equals('i') || letter.Equals('j'))
                    {
                        letters['i'] = false;
                        letters['j'] = false;
                    }
                }
            }

            for (int i = 0; i < letters.Count; i++)
            {
                char letter = letters.ElementAt(i).Key;
                if (letters[letter])
                {
                    mat[iy, ix] = letter;
                    letters[letter] = false;

                    ix++;
                    if (ix == 5)
                    {
                        ix = 0;
                        iy++;
                    }

                    if (letter.Equals('i') || letter.Equals('j'))
                    {
                        letters['i'] = false;
                        letters['j'] = false;
                    }
                }
            }

            return mat;
        }
        private List<String> _Divide(String plainText)
        {
            List<String> result = new List<String>();
            for (int i = 0; i < plainText.Length; i += 2)
            {
                bool end = false;
                char f = plainText[i];
                char s;
                try
                {
                    s = plainText[i + 1];
                }
                catch
                {
                    s = 'x';
                    end = true;
                }

                if (f == s)
                {
                    result.Add($"{f}x");
                    i--;
                    if (end) break;
                }
                else
                {
                    result.Add($"{f}{s}");
                }
            }
            return result;
        }
        private Tuple<int, int> _GetIndex(char[,] matrix, char c)
        {
            int Y = matrix.GetLength(0);
            int X = matrix.GetLength(1);

            for (int y = 0; y < Y; ++y)
            {
                for (int x = 0; x < X; ++x)
                {
                    if (matrix[y, x].Equals(c))
                        return Tuple.Create(y, x);
                }
            }

            return Tuple.Create(-1, -1);
        }

        private String _RemoveX(List<String> decryptedPairs)
        {
            String r = "";

            for (int i = 0; i < decryptedPairs.Count; i++)
            {
                try
                {
                    if (decryptedPairs[i][1] == 'x' && decryptedPairs[i + 1][0] == decryptedPairs[i][0])
                    {
                        r += decryptedPairs[i][0];
                    }
                    else
                    {
                        r += decryptedPairs[i];
                    }
                }
                catch (ArgumentOutOfRangeException e)
                {
                    if (decryptedPairs[i][1] == 'x')
                    {
                        r += decryptedPairs[i][0];
                    }
                }
                catch { }
            }

            return r;
        }
    }
}