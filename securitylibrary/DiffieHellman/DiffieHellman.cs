using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            BigInteger ya = BigInteger.Pow(alpha, xa) % q;
            BigInteger yb = BigInteger.Pow(alpha, xb) % q;

            BigInteger k1 = BigInteger.Pow(yb, xa) % q;
            BigInteger k2 = BigInteger.Pow(ya, xb) % q;

            return new List<int> { (int)k1, (int)k2 };
        }
    }
}                           