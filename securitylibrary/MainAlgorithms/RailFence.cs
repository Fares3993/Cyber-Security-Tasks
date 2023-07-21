using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            int key = 0, length = 0;
            while (length < plainText.Length)
            {
                if (cipherText[1] == plainText[length])
                {
                    if (length > 1)
                    {
                        key = length;
                        break;
                    }
                }
                length++;
            }
            return key;

        }

        public string Decrypt(string cipherText, int key)
        {
            double length = (double)cipherText.Length / key;
            int N_columns = (int)Math.Ceiling(length);
            char[,] CT = new char[key, N_columns];
            int cell = 0;
            string PT = "";
            for (int row = 0; row < key; row++)
            {
                int col = 0;
                while (col < N_columns)
                {
                    if (cell < cipherText.Length)
                    {
                        CT[row, col] = cipherText[cell];
                        cell++;
                    }
                    col++;
                }
            }
            for (int col = 0; col < N_columns; col++)
            {
                int row = 0;
                while (row < key)
                {
                    PT += CT[row, col];
                    row++;
                }
            }
            return PT;
        }

        public string Encrypt(string plainText, int key)
        {
            double length = (double)plainText.Length / key;
            int N_columns = (int)Math.Ceiling(length);
            char[,] PT = new char[key, N_columns];
            int cell = 0;
            string CT = "";
            for (int col = 0; col < N_columns; col++)
            {
                int row = 0;
                while (row < key)
                {
                    if (cell < plainText.Length)
                    {
                        PT[row, col] = plainText[cell];
                        cell++;
                    }
                    row++;
                }
            }

            for (int row = 0; row < key; row++)
            {
                int col = 0;
                while (col < N_columns)
                {
                    CT += PT[row, col];
                    col++;
                }
            }
            return CT;
        }
    }
}
