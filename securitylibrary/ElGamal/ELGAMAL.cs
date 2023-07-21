using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            BigInteger c1 = BigInteger.ModPow(alpha, k, q);
            
            BigInteger K = BigInteger.Pow(y, k);
            BigInteger c2 = K * m % q;

            return new List<long> { (long)c1, (long)c2 };
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            BigInteger K;
            K = BigInteger.ModPow(c1, x, q);
            K = BigInteger.ModPow(K, q - 2, q);  
            
            BigInteger M = c2 * K % q;
            return (int)M;
        }
    }
}
