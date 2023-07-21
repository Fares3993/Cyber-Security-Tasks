using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int row, col = 0, counter = 0;
            int check = 0;
            for (int i = 2; i < 8; i++)
            {
                if (plainText.Length % i == 0)
                {
                    col = i;
                }
            }
            row = plainText.Length / col;
            char[,] plainMat = new char[row, col];
            char[,] cipherMat = new char[row, col];
            List<int> key = new List<int>();
            for (int i = 0; i < 7; i++)
            {
                key.Add(0);
            }

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (counter < plainText.Length)
                    {
                        plainMat[i, j] = plainText[counter];
                        counter++;
                    }
                }
            }
            counter = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    if (counter < plainText.Length)
                    {
                        cipherMat[j, i] = cipherText[counter];
                        counter++;
                    }
                }
            }
            int count = 0;
            for (int i = 0; i < col; i++)
            {
                for (int k = 0; k < col; k++)
                {
                    for (int j = 0; j < row; j++)
                    {
                        if (plainMat[j, i] == cipherMat[j, k])
                        {
                            check++;
                        }
                        if (check == row)
                        {
                            key[count] =(k + 1);
                            count++;
                        }
                    }
                    check = 0;
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int row, counter = 0, iterator = 1;
            int col = key.Count;
            string PT = "";
            if (cipherText.Length % col == 0)
            {
                row = cipherText.Length / col;
            }
            else
            {
                row = cipherText.Length / col + 1;
            }
            int cellFree = (row * col) - cipherText.Length;
            char[,] mat = new char[row, col];
            for (int i = 0; i < col; i++)
            {
                int index = key.IndexOf(iterator);
                iterator++;
                for (int j = 0; j < row; j++)
                {
                    if (j != row - 1)
                    {
                        mat[j, index] = cipherText[counter];
                        counter++;
                    }
                    else if ((j == row - 1) && !(((i + 1) + cellFree) > col))
                    {
                        mat[j, index] = cipherText[counter];
                        counter++;
                    }
                }
            }
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (mat[i, j] != '\0')
                    {
                        PT += mat[i, j];
                    }
                }
            }
            return PT;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int no_of_col = key.Count;
            int no_of_row, counter = 0;
            int ptlen = plainText.Length;
            string CT = "";
            if (plainText.Length % no_of_col == 0)
            {
                no_of_row = plainText.Length / no_of_col;
            }
            else
            {
                no_of_row = plainText.Length / no_of_col + 1;
            }
            char[,] mat = new char[no_of_row, no_of_col];
            for (int i = 0; i < no_of_row; i++)
            {
                for (int j = 0; j < no_of_col && counter < ptlen; j++)
                {
                    mat[i, j] = plainText[counter];
                    counter++;
                }
            }
            for (int i = 1; i <= no_of_col; i++)
            {
                int index = key.IndexOf(i);
                for (int j = 0; j < no_of_row; j++)
                {
                    if (mat[j, index] != '\0')
                    {
                        CT += mat[j, index];
                    }
                }
            }
            return CT;
        }
    }
}
