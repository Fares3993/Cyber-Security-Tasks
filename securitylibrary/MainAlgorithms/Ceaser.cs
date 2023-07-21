using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            int code = -1;
            char c ;
            String ciphertxt = "";
            plainText = plainText.ToUpper();
            for(int i =0; i < plainText.Length; i++)
            {
                code = (int) plainText[i];
                code = (code - 65);
                code = (code + key);
                code = code % 26;
                code = (code + 65);
                c = (char) code;
                ciphertxt += c;
            }
            return ciphertxt;

        }

        public string Decrypt(string cipherText, int key)
        {
            //   throw new NotImplementedException();
            int code = -1;
            char c;
            String plaintxt = "";
        
            for (int i = 0; i < cipherText.Length; i++)
            {
                code = (int)cipherText[i];
                code = (code - 65);  //2
                code = (code - key); //-6
                if(code < 0)
                    code = code + 26;  //20
                Console.WriteLine(code);
                code = (code + 65);   //85
                c = (char)code;
                Console.WriteLine(c);
                plaintxt += c;
            }
            return plaintxt.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            int p = (int)plainText[0];
            int c = (int)cipherText[0];
            int key = c - p;
            if (key < 0)
            {
                key = key + 26;
            }
            return key;
        }
    }
}