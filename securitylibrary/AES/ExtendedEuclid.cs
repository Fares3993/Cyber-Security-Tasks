using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            int q;
            int a1 = 1;
            int a2 = 0;
            int a3 = baseN;
            int b1 = 0;
            int b2= 1;
            int b3= number;
            int inv;
            int result=-1;

            while (true)
            {
                int a1tmp = a1;
                int a2tmp = a2;
                int a3tmp = a3;
                int b1tmp = b1;
                int b2tmp = b2;
                int b3tmp = b3;


                
                if (b3 == 1)
                {
                    inv = b2;
                    while (true)
                    {
                        if (inv < 0)
                        {
                            inv += baseN;
                        }
                        else
                        {
                            break;
                        }

                    }
                  
                    result = inv % baseN;
                    break;
                }
                if (b3 == 0)
                {
                    break;
                }

                q = a3tmp / b3tmp;
                a1 = b1tmp;
                a2 = b2tmp;
                a3 = b3tmp;
                b1 = a1tmp - (q * b1tmp);
                b2 = a2tmp - (q * b2tmp);
                b3 = a3tmp - (q * b3tmp);


            }
            return result;
        }
    }
}