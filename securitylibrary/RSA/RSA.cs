using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int C = 1;
            for (int i = 0; i < e; i++)
            {
                C = (C * M) % n;
            }
            return C;
        }
        public static int Mod_Power(int num, int pow, int mod)
        {
            int result = 1;
            for (int i = 0; i < pow; i++)
            {
                result = (result * num) % mod;
            }
            return result;
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int eul = (p - 1) * (q - 1);
            int d = new ExtendedEuclid().GetMultiplicativeInverse(e, (int)eul);
            int M = Mod_Power(C, d, n);
            return M;
        }
    }
}
