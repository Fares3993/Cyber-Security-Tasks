using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {


        string[,] sBox = new string[16, 16]
{
                {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
                {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
                {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
                {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
                {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
                {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
                {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
                {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
                {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
                {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
                {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
                {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
                {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
                {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
                {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
                {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
};
        public string[,] rCon = new string[,]{
        {"01","02","04","08","10","20","40","80","1b","36"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"}};
        string[,] inv_sbox = new string[16, 16] {
            {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" },
            {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb" },
            {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e" },
            {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25" },
            {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92" },
            {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" },
            {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" },
            {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" },
            {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" },
            {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" },
            {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" },
            {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" },
            {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" },
            {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" },
            {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61" },
            {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d" } 
        
      };


        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            string[,] cipher_state = makeState(cipherText);
            string[,] orignalKey = makeState(key);
            string[,] mainKey = makeState(key);
            string[,] Round_Key = new string[4, 4];

            for (int i = 0; i < 10; i++)
            {
                //string[] arr_round_key = new string[10];
                Round_Key = roundKey(mainKey, i);
                mainKey = Round_Key;

            }

            string[,] afterShifted = addRoundKey(cipher_state, Round_Key);

            string[,] afterSubBytes = invShiftRows(afterShifted);

            string[,] RoundInput = subBytes(afterSubBytes, 1);

            for (int i = 9; i > 0; i--)
            {
                for(int j = 0; j < i; j++)
                {
                    if (j == 0)
                    {
                        Round_Key = roundKey(orignalKey, j);
                    }
                    else
                    {
                        Round_Key = roundKey(mainKey, j);
                    }
                    mainKey = Round_Key;


                }

                string[,] afterMixColumns = addRoundKey(RoundInput, Round_Key);
                afterShifted = inv_mix_columns(afterMixColumns);
                afterSubBytes = invShiftRows(afterShifted);
                RoundInput = subBytes(afterSubBytes, 1);


            }


            string[,] output = addRoundKey(RoundInput, orignalKey);

            string plaintxt = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plaintxt += output[j, i];
                }
            }


            return plaintxt;
        }

        public override string Encrypt(string plainText, string key)

        {


            
            string[,] state = makeState(plainText);
            string[,] mainKey = makeState(key);
            string[,] input = makeInput(state, mainKey);

            string[,] outputSubByte = new string[4, 4];
            string[,] outputShiftRow = new string[4, 4];
            string[,] outputMixColumns = new string[4, 4];
            string[,] roundKeyMat = new string[4, 4];
            string[,] outputRound = new string[4, 4];


            for (int i = 0; i < 9; i++)
            {
                outputSubByte = subBytes(input,0);
                outputShiftRow = shiftRow(outputSubByte);
                outputMixColumns = mixColumns(outputShiftRow);
                roundKeyMat = roundKey(mainKey,i);
                outputRound = addRoundKey(outputMixColumns, roundKeyMat);
                input = outputRound;
                mainKey = roundKeyMat;
               
            }

            outputSubByte = subBytes(input,0);
            outputShiftRow = shiftRow(outputSubByte);
            roundKeyMat = roundKey(mainKey, 9);
            outputRound = addRoundKey(outputShiftRow, roundKeyMat);

            string output = "0x";
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    output += outputRound[j, i];
                }
            }




            return output;
            //throw new NotImplementedException();
        }
        string[,] makeState(string txt)
        {
            string[,] arr = new string[4, 4];
            int c = 2;
            string tmp = "";
            int ch = 0;

            for (int i = 0; i < 4; i++)

            {

                for (int j = 0; j < 4; j++)
                {

                    ch = 0;
                    tmp = "";

                    while (ch < 2)
                    {
                        tmp += txt[c];
                        ch++;
                        if (c < txt.Length)
                        {
                            c++;
                        }
                        else
                        {
                            break;
                        }


                    }

                    arr[j, i] = tmp;

                }

            }
            return arr;

        }

        string[,] makeInput(string[,] p, string[,] k)
        {
            string[,] input = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    string hex1 = p[i, j];
                    string hex2 = k[i, j];
                    int dechex1 = Convert.ToInt32(hex1, 16);
                    int dechex2 = Convert.ToInt32(hex2, 16);

                    int res = dechex1 ^ dechex2;
                    string hexRes = Convert.ToString(res, 16);
                    if (hexRes.Length < 2)
                    {
                        input[i, j] = "0" + hexRes;
                    }
                    else
                    {
                        input[i, j] = hexRes;
                    }


                }

            }
            return input;

        }


        string[,] subBytes(string[,] state , int ch)
        {
            string[,] output = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string value = state[i, j];
                    output[i,j] = getIndex(value,ch);
                }
            }

            return output;
        }

        string getIndex(string x , int ch)
        {
            string value ="";
            string row = "";
            string col = "";
            row += x[0];
            col += x[1];
            int rowInt = -1;
            int colInt = -1;
            if (row != "a" && row != "b" && row !="c"  && row != "d" && row != "e" && row != "f")  //row number

            {
                if(col != "a" && col != "b" && col != "c" && col != "d" && col != "e" && col != "f") //col number
                {
                     rowInt = Int32.Parse(row);
                     colInt = Int32.Parse(col);
                    if (ch == 0)
                    {
                        value = sBox[rowInt, colInt];
                    }
                    else
                    {
                        value = inv_sbox[rowInt, colInt];
                    }

                }
                else // col not number
                {
                    

                    if (col == "a")
                        colInt = 10;
                    else if (col == "b")
                        colInt = 11;
                    else if (col == "c")
                        colInt = 12;
                    else if (col == "d")
                        colInt = 13;
                    else if (col == "e")
                        colInt = 14;
                    else if (col == "f")
                        colInt = 15;

                    rowInt = Int32.Parse(row);
                    if (ch == 0)
                    {
                        value = sBox[rowInt, colInt];
                    }
                    else
                    {
                        value = inv_sbox[rowInt, colInt];
                    }

                }

                

            }
            else  //row not number
            {


                if (row == "a")
                    rowInt = 10;
                else if (row == "b")
                    rowInt = 11;
                else if (row == "c")
                    rowInt = 12;
                else if (row == "d")
                    rowInt = 13;
                else if (row == "e")
                    rowInt = 14;
                else if (row == "f")
                    rowInt = 15;


                if (col != "a" && col != "b" && col != "c" && col != "d" && col != "e" && col != "f") //number
                {
                    
                    colInt = Int32.Parse(col);
                    if (ch == 0)
                    {
                        value = sBox[rowInt, colInt];
                    }
                    else
                    {
                        value = inv_sbox[rowInt, colInt];
                    }

                }
                else //col not number
                {
                    if (col == "a")
                        colInt = 10;
                    else if (col == "b")
                        colInt = 11;
                    else if (col == "c")
                        colInt = 12;
                    else if (col == "d")
                        colInt = 13;
                    else if (col == "e")
                        colInt = 14;
                    else if (col == "f")
                        colInt = 15;



                    if (ch == 0)
                    {
                        value = sBox[rowInt, colInt];
                    }
                    else
                    {
                        value = inv_sbox[rowInt, colInt];
                    }

                }

            }

            return value;
        }

        string[,] shiftRow(string[,] x)
        {
            string[,] output = new string[4, 4];
            
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    if (i == 0)
                    {
                        output[i, j] = x[i, j];
                        continue;
                    }
                    else if (i == 1)
                    {
                        string tmp = x[i,0]; //27
                        int index = 1;
                        for(int h = 0; h < 3; h++)
                        {

                            output[i, h] = x[i, index];
                            index++;
                        }
                        output[i, 3] = tmp;

                        output[i, j] = tmp;
                    }
                    else if (i == 2)
                    {
                        int round = 0;
                        while (round < 2)
                        {
                            string tmp = "";
                            int index = 1;
                            if (round < 1)
                            {
                                 tmp = x[i, 0];
                                for (int h = 0; h < 3; h++)
                                {

                                    output[i, h] = x[i, index];
                                    index++;
                                }
                            }
                            else
                            {
                                 tmp = output[i, 0];
                                for (int h = 0; h < 3; h++)
                                {

                                    output[i, h] = output[i, index];
                                    index++;
                                }
                            }
                            
                          
                            output[i, 3] = tmp;

                          

                            round++;
                        }
                        

                    }
                    else if (i == 3)
                    {

                        int round = 0;
                        while (round < 3)
                        {
                            string tmp = "";
                            int index = 1;
                            if (round < 1)
                            {
                                tmp = x[i, 0];
                                for (int h = 0; h < 3; h++)
                                {

                                    output[i, h] = x[i, index];
                                    index++;
                                }
                            }
                            else
                            {
                                tmp = output[i, 0];
                                for (int h = 0; h < 3; h++)
                                {

                                    output[i, h] = output[i, index];
                                    index++;
                                }
                            }


                            output[i, 3] = tmp;



                            round++;
                        }


                    }
                }
            }
            return output;
        }

        string[,] mixColumns(string[,] input)
        {
            string[,] output = new string[4, 4];
            string txtMat = "0x02010103030201010103020101010302";
            string[,] mat = makeState(txtMat);

            //string x = input[0, 0];
            // string x = "87";
            // int dechex1 = Convert.ToInt32(x, 2);


            int e = 0;
            for (int i = 0; i < 4; i++)
            {

                string res1 ="";
                string res2 = "";
                string finalRes = "";
                string res4 = "";

                string[] arr = new string[4];

                for (int j = 0; j < 4; j++)
                {
                  

                    for (int m = 0; m < 4; m++)
                    {
                        string value = "";
                        string shiftValue = ""; //shifted
                        value = Convert.ToString(Convert.ToInt32(input[m, i].ToString(), 16), 2);

                        while (value.Length < 8)
                        {
                            value = "0" + value;
                            
                        }
                        

                        if (mat[j,m] == "02")
                        {
                            string tmp = "0";


                            for (int h = 0; h < 7; h++)
                            {

                                shiftValue += value[h + 1];

                            }
                            shiftValue += tmp;

                            if (value[0] == '1')
                            {
                                int dechex1 = Convert.ToInt32(shiftValue, 2);
                                int dechex2 = Convert.ToInt32("00011011", 2);

                                int res = dechex1 ^ dechex2;
                                string hexRes = Convert.ToString(res, 16);
                                res1 = hexRes;
                            }
                            else
                            {
                                //res1 = shiftValue;

                                int s = Convert.ToInt32(shiftValue, 2);
                                string hexRes = Convert.ToString(s, 16);
                                res1 = hexRes;

                            }

                            finalRes = res1;

                        }
                        else if (mat[j,m] == "01")
                        {
                            res1 = value; //bin
                            int r = Convert.ToInt32(res1, 2);
                            string hexRes = Convert.ToString(r, 16);
                            finalRes = hexRes;

                        }

                        else if (mat[j,m] == "03")
                        {



                            string tmp = "0";


                            for (int h = 0; h < 7; h++)
                            {

                                shiftValue += value[h + 1];

                            }
                            shiftValue += tmp;

                            if (value[0] == '1')
                            {
                                int dechex1 = Convert.ToInt32(shiftValue, 2);
                                int dechex2 = Convert.ToInt32("00011011", 2);

                                int res = dechex1 ^ dechex2;
                                string hexRes = Convert.ToString(res, 16);
                                res1 = hexRes;
                            }
                            else
                            {
                                int s = Convert.ToInt32(shiftValue, 2);
                                string hexRes = Convert.ToString(s, 16);
                                res1 = hexRes;
                            }

                            int decres1 = Convert.ToInt32(res1, 16);
                            int decValue = Convert.ToInt32(value, 2);
                            int result2 = decres1 ^ decValue;
                            res2 = Convert.ToString(result2, 16);
                            finalRes = res2;


                        }

                        arr[m] = finalRes;

                    }



                    int decval1 = Convert.ToInt32(arr[0], 16);
                    int decval2 = Convert.ToInt32(arr[1], 16);
                    int rr = decval1 ^ decval2;
                    string rrString = Convert.ToString(rr, 16);

                    decval1 = Convert.ToInt32(rrString, 16);
                    decval2 = Convert.ToInt32(arr[2], 16);
                    rr = decval1 ^ decval2;
                    rrString = Convert.ToString(rr, 16);

                    decval1 = Convert.ToInt32(rrString, 16);
                    decval2 = Convert.ToInt32(arr[3], 16);
                    rr = decval1 ^ decval2;
                    rrString = Convert.ToString(rr, 16);

                    if (e == 4)
                    {
                        e = 0;
                    }
                    if (rrString.Length < 2)
                    {
                        rrString = "0" + rrString;
                    }
                  
                    output[e, i] = rrString;
                    e++;




                }

              
              






            }




            return output;
        }

        string[,] roundKey(string[,] input , int indexRound)
        {
            string[,] output =new string[4,4];
            string[] arrOfsBox = new string[4];
            string tmp = input[0, 3];
            string value ="";
            for (int i = 0; i < 3; i++)
            {
               // input[i, 3] = input[i + 1, 3];

                value = input[i+1, 3];
                value = value.ToLower();
                arrOfsBox[i] = getIndex(value,0);

            }
            value = tmp.ToLower();

            arrOfsBox[3] = getIndex(value,0);

            for(int i = 0; i < 4; i++)
            {
                string h = input[i, 0].ToLower();
                int dec1 = Convert.ToInt32(h,16);
                int dec2 = Convert.ToInt32(arrOfsBox[i].ToLower(),16);
                int dec3 = Convert.ToInt32(rCon[i, indexRound].ToLower(),16);

                int res1 = dec1 ^ dec2;
                int res2 = res1 ^ dec3;
                output[i, 0] = Convert.ToString(res2, 16);
            }
           
            int j = 0;
            int d = 0;
            while (j<3)
            {
                int dec1 = Convert.ToInt32(output[d, j], 16);
                int dec2 = Convert.ToInt32(input[d, j + 1].ToLower(), 16);
                int res = dec1 ^ dec2;
                string hexres = Convert.ToString(res, 16);

                if (hexres.Length < 2)
                {
                    hexres = "0" + hexres;
                }
                output[d, j + 1] = hexres;

                if (d == 3)
                {
                    j++;
                    d = 0;
                }
                else
                {
                    d++;
                }
            }
               
            


            return output;
        }

        string[,] addRoundKey(string[,]x , string[,] y)
        {
            string[,] output = new string[4, 4];
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    int dec1= Convert.ToInt32(x[i, j], 16);
                    int dec2 = Convert.ToInt32(y[i, j], 16);
                    int res = dec1 ^ dec2;
                    string hexRes = Convert.ToString(res, 16);
                    if (hexRes.Length < 2)
                    {
                        hexRes = "0" + hexRes;
                    }
                    output[i, j] = hexRes;

                }
            }
            return output;
        }

        /////dec
        string[,] invShiftRows(string[,] x)
        {
            string[,] output = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (i == 0)
                    {
                        output[i, j] = x[i, j];
                        continue;
                    }
                    else if (i == 1)
                    {
                        string tmp = x[i, 3]; //09
                        int index = 2;
                        for (int h = 3; h > 0; h--)
                        {

                            output[i, h] = x[i, index];
                            index--;
                        }
                        output[i, 0] = tmp;
                        break;

                       // output[i, j] = tmp;
                    }
                    else if (i == 2)
                    {
                        int round = 0;
                        while (round < 2)
                        {
                            string tmp = "";
                            int index = 1;
                            if (round < 1)
                            {
                                tmp = x[i, 0];
                                for (int h = 0; h < 3; h++)
                                {

                                    output[i, h] = x[i, index];
                                    index++;
                                }
                            }
                            else
                            {
                                tmp = output[i, 0];
                                for (int h = 0; h < 3; h++)
                                {

                                    output[i, h] = output[i, index];
                                    index++;
                                }
                            }


                            output[i, 3] = tmp;



                            round++;
                        }
                        break;


                    }
                    else if (i == 3)
                    {

                        string tmp = x[i, 0];
                        int index = 1;
                        for (int h = 0; h < 3; h++)
                        {

                            output[i, h] = x[i, index];
                            index++;
                        }
                        output[i, 3] = tmp;

                        output[i, j] = tmp;




                    }
                }
            }
            return output;

        }
      
        string[,] inv_mix_columns(string[,] input)
        {
            string[,] output = new string[4, 4];
            string txtMat = "0x0e090d0b0b0e090d0d0b0e09090d0b0e";
            string[,] mat = makeState(txtMat);


            int e = 0;
            for (int i = 0; i < 4; i++)
            {

                string res1 = "";
                string res2 = "";
                string finalRes = "";
                string res4 = "";

                string[] arr = new string[4];

                for (int j = 0; j < 4; j++)
                {


                    for (int m = 0; m < 4; m++)
                    {
                        string value = "";
                        string shiftValue = ""; //shifted
                        value = Convert.ToString(Convert.ToInt32(input[m, i].ToString(), 16), 2);

                        while (value.Length < 8)
                        {
                            value = "0" + value;

                        }


                        if (mat[j, m] == "09")
                        {

                           int round = 0;
                           string orginal_value = value;
                            shiftValue = "";
                            while (round <3)
                            {
                                shiftValue = "";
                                string tmp = "0";

                                for (int h = 0; h < 7; h++)
                                {

                                    shiftValue += value[h + 1];

                                }
                                shiftValue += tmp;

                                if (value[0] == '1')
                                {
                                    int dechex1 = Convert.ToInt32(shiftValue, 2);
                                    int dechex2 = Convert.ToInt32("00011011", 2);

                                    int res = dechex1 ^ dechex2;
                                    string hexRes = Convert.ToString(res, 16);
                                    res1 = hexRes;
                                }
                                else
                                {
                                    //res1 = shiftValue;

                                    int s = Convert.ToInt32(shiftValue, 2);
                                    string hexRes = Convert.ToString(s, 16);
                                    res1 = hexRes;

                                }
                                value = res1;
                                value = Convert.ToString(Convert.ToInt32(value.ToString(), 16), 2);

                                while (value.Length < 8)
                                {
                                    value = "0" + value;
                                }


                                round++;
                            }

                            int x1 = Convert.ToInt32(res1, 16);
                            int x2 = Convert.ToInt32(orginal_value, 2);

                            int f_res = x1 ^ x2;
                            string hex_f_Res = Convert.ToString(f_res, 16);
                            res1 = hex_f_Res;



                            finalRes = res1;



                        }


                        else if (mat[j, m] == "0b")
                        {
                            int round = 0;
                            string tmp;

                            string orginal_value = value;

                            shiftValue = "";

                            tmp = "0";

                            for (int h = 0; h < 7; h++)
                            {

                                shiftValue += value[h + 1];

                            }
                            shiftValue += tmp;

                            if (value[0] == '1')
                            {
                                int dechex1 = Convert.ToInt32(shiftValue, 2);
                                int dechex2 = Convert.ToInt32("00011011", 2);

                                int res = dechex1 ^ dechex2;
                                string hexRes = Convert.ToString(res, 16);
                                res1 = hexRes;
                            }
                            else
                            {
                                //res1 = shiftValue;

                                int s = Convert.ToInt32(shiftValue, 2);
                                string hexRes = Convert.ToString(s, 16);
                                res1 = hexRes;

                            }
                            value = res1;
                            value = Convert.ToString(Convert.ToInt32(value.ToString(), 16), 2);
                            while (value.Length < 8)
                            {
                                value = "0" + value;
                            }

                            while (round < 2)
                            {
                                shiftValue = "";

                                tmp = "0";

                                for (int h = 0; h < 7; h++)
                                {

                                    shiftValue += value[h + 1];

                                }
                                shiftValue += tmp;

                                if (value[0] == '1')
                                {
                                    int dechex1 = Convert.ToInt32(shiftValue, 2);
                                    int dechex2 = Convert.ToInt32("00011011", 2);

                                    int res = dechex1 ^ dechex2;
                                    string hexRes = Convert.ToString(res, 16);
                                    res1 = hexRes;
                                }
                                else
                                {
                                    //res1 = shiftValue;

                                    int s = Convert.ToInt32(shiftValue, 2);
                                    string hexRes = Convert.ToString(s, 16);
                                    res1 = hexRes;

                                }




                                int x1 = Convert.ToInt32(res1, 16);
                                int x2 = Convert.ToInt32(orginal_value, 2);

                                int f_res = x1 ^ x2;
                                string hex_f_Res = Convert.ToString(f_res, 16);
                                res1 = hex_f_Res;

                                value = res1;
                                value = Convert.ToString(Convert.ToInt32(value.ToString(), 16), 2);

                                round++;

                                while (value.Length < 8)
                                {
                                    value = "0" + value;
                                }

                            }


                            finalRes = res1;
                        }

                        else if (mat[j, m] == "0d")
                        {

                            string tmp;

                            string orginal_value = value;
                            shiftValue = "";

                            tmp = "0";

                            for (int h = 0; h < 7; h++)
                            {

                                shiftValue += value[h + 1];

                            }
                            shiftValue += tmp;

                            if (value[0] == '1')
                            {
                                int dechex1 = Convert.ToInt32(shiftValue, 2);
                                int dechex2 = Convert.ToInt32("00011011", 2);

                                int res = dechex1 ^ dechex2;
                                string hexRes = Convert.ToString(res, 16);
                                res1 = hexRes;
                            }
                            else
                            {
                                //res1 = shiftValue;

                                int s = Convert.ToInt32(shiftValue, 2);
                                string hexRes = Convert.ToString(s, 16);
                                res1 = hexRes;

                            }




                            int x1 = Convert.ToInt32(res1, 16);
                            int x2 = Convert.ToInt32(orginal_value, 2);

                            int f_res = x1 ^ x2;
                            string hex_f_Res = Convert.ToString(f_res, 16);
                            res1 = hex_f_Res;

                            value = res1;
                            value = Convert.ToString(Convert.ToInt32(value.ToString(), 16), 2);

                            while(value.Length < 8)
                            {
                                value ="0"+value;
                            }

                            int round = 0;
                            while (round < 2)
                            {
                                while (value.Length < 8)
                                {
                                    value = "0" + value;
                                }
                                shiftValue = "";
                                for (int h = 0; h < 7; h++)
                                {

                                    shiftValue += value[h + 1];

                                }
                                shiftValue += tmp;

                                if (value[0] == '1')
                                {
                                    int dechex1 = Convert.ToInt32(shiftValue, 2);
                                    int dechex2 = Convert.ToInt32("00011011", 2);

                                    int res = dechex1 ^ dechex2;
                                    string hexRes = Convert.ToString(res, 16);
                                    res1 = hexRes;
                                }
                                else
                                {
                                    //res1 = shiftValue;

                                    int s = Convert.ToInt32(shiftValue, 2);
                                    string hexRes = Convert.ToString(s, 16);
                                    res1 = hexRes;
                                    

                                }
                                value = res1;
                                value = Convert.ToString(Convert.ToInt32(value.ToString(), 16), 2);

                                round++;
                            }

                            x1 = Convert.ToInt32(res1, 16);
                            x2 = Convert.ToInt32(orginal_value, 2);

                            f_res = x1 ^ x2;
                            hex_f_Res = Convert.ToString(f_res, 16);
                            res1 = hex_f_Res;

                            value = res1;
                            value = Convert.ToString(Convert.ToInt32(value.ToString(), 16), 2);

                            finalRes = res1;








                        }

                        else
                        {
                            //e
                            int round = 0;
                            string tmp;

                            string orginal_value = value;

                            while (round < 2)
                            {
                                shiftValue = "";

                                tmp = "0";

                                for (int h = 0; h < 7; h++)
                                {

                                    shiftValue += value[h + 1];

                                }
                                shiftValue += tmp;

                                if (value[0] == '1')
                                {
                                    int dechex1 = Convert.ToInt32(shiftValue, 2);
                                    int dechex2 = Convert.ToInt32("00011011", 2);

                                    int res = dechex1 ^ dechex2;
                                    string hexRes = Convert.ToString(res, 16);
                                    res1 = hexRes;
                                }
                                else
                                {
                                    //res1 = shiftValue;

                                    int s = Convert.ToInt32(shiftValue, 2);
                                    string hexRes = Convert.ToString(s, 16);
                                    res1 = hexRes;

                                }

                               


                                int x1 = Convert.ToInt32(res1, 16);
                                int x2 = Convert.ToInt32(orginal_value, 2);

                                int f_res = x1 ^ x2;
                                string hex_f_Res = Convert.ToString(f_res, 16);
                                res1 = hex_f_Res;

                                value = res1;
                                value = Convert.ToString(Convert.ToInt32(value.ToString(), 16), 2);


                                while (value.Length<8)
                                {
                                    value = "0" + value;
                                }
                                round++;

                            }

                            tmp = "0";
                            shiftValue = "";
                            for (int h = 0; h < 7; h++)
                            {

                                shiftValue += value[h + 1];

                            }
                            shiftValue += tmp;

                            if (value[0] == '1')
                            {
                                int dechex1 = Convert.ToInt32(shiftValue, 2);
                                int dechex2 = Convert.ToInt32("00011011", 2);

                                int res = dechex1 ^ dechex2;
                                string hexRes = Convert.ToString(res, 16);
                                res1 = hexRes;
                            }
                            else
                            {
                                //res1 = shiftValue;

                                int s = Convert.ToInt32(shiftValue, 2);
                                string hexRes = Convert.ToString(s, 16);
                                res1 = hexRes;

                            }


                            finalRes = res1;


                        }


                        arr[m] = finalRes;

                    }



                    int decval1 = Convert.ToInt32(arr[0], 16);
                    int decval2 = Convert.ToInt32(arr[1], 16);
                    int rr = decval1 ^ decval2;
                    string rrString = Convert.ToString(rr, 16);

                    decval1 = Convert.ToInt32(rrString, 16);
                    decval2 = Convert.ToInt32(arr[2], 16);
                    rr = decval1 ^ decval2;
                    rrString = Convert.ToString(rr, 16);

                    decval1 = Convert.ToInt32(rrString, 16);
                    decval2 = Convert.ToInt32(arr[3], 16);
                    rr = decval1 ^ decval2;
                    rrString = Convert.ToString(rr, 16);

                    if (e == 4)
                    {
                        e = 0;
                    }
                    if (rrString.Length < 2)
                    {
                        rrString = "0" + rrString;
                    }

                    output[e, i] = rrString;
                    e++;




                }




            }





            return output;
        }
    }
}