using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            string Final_txt =Run_DES(cipherText,key,false);
            return Final_txt;
        }
        public override string Encrypt(string plainText, string key)
        {
            string Final_txt = Run_DES(plainText, key, true);
            return Final_txt;
        }
        public static int[] Main_Function(List<int[]> LiftList, List<int[]> RightList, List<int[]> KeysShifted, Dictionary<string, int[]> Permution_Tables)
        {
            // S boxex 
            Dictionary<string, int[]> S_boxes_Tables = S_boxes_Table_Creator();
            int[] FinalArr = new int[64];

            // Start War 
            for (int RoundNum = 0; RoundNum < 16; RoundNum++)
            {
                // expand 
                int[] NewRight48Bit = Permutation(RightList[RoundNum], Permution_Tables["E SELECTION Permutation"]);
                // XOr key with right
                int[] XOR_Value = Xor_Function(KeysShifted[RoundNum], NewRight48Bit);
                // reduce bits
                int[] Substitution_Values = Substitution_Boxes(XOR_Value, S_boxes_Tables); 
                //  
                int[] final_permutation_values = Permutation(Substitution_Values, Permution_Tables["Final Permutation"]);
                //  XOR final permutation with lfet
                int[] FinalRightXOR = Xor_Function(final_permutation_values, LiftList[RoundNum]);
                LiftList.Add(RightList[RoundNum]);
                RightList.Add(FinalRightXOR);
            }
            RightList[RightList.Count - 1].CopyTo(FinalArr, 0);
            LiftList[LiftList.Count - 1].CopyTo(FinalArr, 32);
            int[,] FinalMatrix = Matrix_Creator(FinalArr, 8, 8);

            return FinalArr;
        }
        public static List<int[]> get_shifted_all_keys(int[] C, int[] D, Dictionary<string, int[]> Permution_Tables)
        {
            List<int[]> Shifted_Keys = new List<int[]>();

            for(int x =1; x < 17; x++)
            {
                int[] FinalKey = new int[48];
                int[] Last_key = new int[C.Length + D.Length];
                int[,] KeyTxtMatrix_perm2 = new int[8, 6];
                if (x == 1 || x == 2 || x == 9 || x == 16)
                {
                    Shift_Left_bit(1,C);
                    Shift_Left_bit(1,D);
                }
                else
                {
                    Shift_Left_bit(2, C);
                    Shift_Left_bit(2, D);
                }
                C.CopyTo(Last_key, 0);
                D.CopyTo(Last_key, 28);
                FinalKey = Permutation(Last_key, Permution_Tables["PC 2 Key"]);
                Shifted_Keys.Add(FinalKey);
            }

            return Shifted_Keys;
        }
        public static void convert_from_text_to_binary(int[] BinaryArray, string text, Dictionary<string, char> Binary)
        {
            int count = 0;
            for (int i = 2; i < text.Length; i++)
            {
                var myKey = Binary.FirstOrDefault(x => x.Value == text[i]).Key;
                for (int j = 0; j < myKey.Length; j++)
                {
                    BinaryArray[count] = (myKey[j] - 48);
                    count++;
                }
            }
        }
        public static void Shift_Left_bit(int count, int[] arr)
        {
            if (count == 0) return;

            int x = arr[0];
            for (int i = 0; i < arr.Length - 1; i++)
            {
                arr[i] = arr[i + 1];
            }
            arr[arr.Length - 1] = x;
            Shift_Left_bit(--count, arr);
        }
        public static int[] Xor_Function(int[] Left, int[] Right)
        {
            int[] FinalList = new int[Left.Length];
            for (int i = 0; i < Left.Length; i++)
            {
                if (Left[i] == Right[i])
                {
                    FinalList[i] = 0;
                }
                else
                {
                    FinalList[i] = 1;
                }
            }
            return FinalList;
        }
        public static List<int[]> Substitution_Boxes_input(int[] XOR_Value)
        {
            List<int[]> value_div = new List<int[]>();
            int valCount = 2;
            int counter_for_value = 0;
            for (int i = 0; i < 8; i++)
            {
                int[] tmp = new int[6];
                for (int h = 0; h < 6; h++)
                {
                    tmp[h] = XOR_Value[counter_for_value + h];
                }
                value_div.Add(tmp);
                counter_for_value = counter_for_value + 6;
                valCount = valCount * 2;
            }
            return value_div;
        }
        public static int get_Curr_indx(int row, int col)
        {
            int index = -1;
            return col + 16 * row;
        }
        public static int[] S_box(int[] BoxInput, int[] S_Box_Table_layer)
        {
            int[] BoxOutput = new int[4];

            string s1 = BoxInput[0].ToString() + BoxInput[5].ToString();
            string s2 = BoxInput[1].ToString() + BoxInput[2].ToString() + BoxInput[3].ToString() + BoxInput[4].ToString();

            int row = int.Parse(Convert.ToInt32(s1, 2).ToString());
            int col = int.Parse(Convert.ToInt32(s2, 2).ToString());


            int x = S_Box_Table_layer[get_Curr_indx(row, col)];

            string FinalOutputStr = Convert.ToString(x, 2).PadLeft(4, '0');

            for (int i = 0; i < 4; i++)
            {
                BoxOutput[i] = FinalOutputStr[i];
            }
            return BoxOutput;
        }
        public static int[] Substitution_Boxes(int[] XOR_Value, Dictionary<string, int[]> S_boxes_Tables)
        {
            int[] FinalList32Bit = new int[32];
            int count = 0;
            List<int[]> BoxesInputLits = Substitution_Boxes_input(XOR_Value);

            for (int i = 0; i < 8; i++)
            {
                int[] tmp = S_box(BoxesInputLits[i], S_boxes_Tables[$"S{i + 1}"]);

                for (int h = 0; h < 4; h++)
                {
                    FinalList32Bit[count + h] = tmp[h] - 48;
                }
                count = count + 4;
            }
            return FinalList32Bit;
        }
        public static int[] Permutation(int[] Old_Values, int[] permutation_table)
        {

            int[] permutation_output = new int[permutation_table.Length];

            for (int i = 0; i < permutation_table.Length; i++)
            {
                int newIndex = permutation_table[i] - 1;
                permutation_output[i] = Old_Values[newIndex];
            }
            return permutation_output;

        }
        public static string convert_from_binary_to_text(int[] inverseOutputArr)
        {
            Dictionary<string, char> Binary = get_binary_Dic();
            string str = "0x";
            for (int i = 0; i < inverseOutputArr.Length; i += 4)
            {
                str += Binary[inverseOutputArr[i].ToString() + inverseOutputArr[i + 1].ToString() + inverseOutputArr[i + 2].ToString() + inverseOutputArr[i + 3].ToString()];
            }
            return str;
        }
        public static Dictionary<string, int[]> Permutation_Table_Creator()
        {

            Dictionary<string, int[]> Permutation_Tables = new Dictionary<string, int[]>();

            Permutation_Tables["Inverse Permutation"] = new int[64] {
                                                        40, 8, 48 ,16, 56, 24, 64, 32,
                                                        39, 7, 47, 15, 55, 23, 63, 31,
                                                        38, 6, 46, 14, 54, 22, 62, 30,
                                                        37, 5, 45, 13, 53, 21, 61, 29,
                                                        36, 4, 44, 12, 52, 20, 60, 28,
                                                        35, 3, 43, 11, 51, 19, 59, 27,
                                                        34, 2, 42, 10, 50, 18, 58, 26,
                                                        33, 1, 41, 9, 49, 17, 57,25
            };
            Permutation_Tables["Final Permutation"] = new int[32]{
                                                        16, 7 ,20, 21,
                                                        29, 12 ,28, 17,
                                                        1,15, 23, 26,5,
                                                        18 ,31, 10,2 ,8 ,
                                                        24, 14,32, 27, 3,
                                                        9, 19, 13, 30, 6,
                                                        22, 11, 4, 25
            };
            Permutation_Tables["E SELECTION Permutation"] = new int[48] {
                                                        32, 1, 2 ,3 ,4 ,5,
                                                        4 ,5 ,6, 7 ,8, 9,
                                                        8 ,9 ,10 ,11, 12, 13,
                                                        12 ,13 ,14, 15, 16, 17,
                                                        16, 17, 18, 19, 20, 21,
                                                        20 ,21 ,22 ,23, 24, 25,
                                                        24, 25 ,26 ,27 ,28, 29,
                                                        28, 29, 30, 31, 32, 1
            };
            Permutation_Tables["PC 1 Key"] =  new int[56] {
                                                            57,49,41,33,25,17,9,1 ,
                                                            58 ,50, 42, 34 ,26, 18,
                                                            10, 2, 59, 51, 43, 35 ,
                                                            27,19 ,11 ,3 ,60, 52,44,
                                                            36,63, 55, 47, 39, 31, 23,
                                                            15,7, 62, 54, 46, 38, 30,
                                                            22,14, 6, 61, 53, 45 ,37,
                                                            29,21, 13, 5, 28, 20, 12, 4
                                            };
            Permutation_Tables["PC 2 Key"] = new int[48] {
                                                14, 17, 11, 24, 1, 5,
                                                3, 28, 15, 6, 21, 10,
                                                23, 19, 12, 4, 26, 8,
                                                16, 7, 27, 20, 13, 2,
                                                41, 52, 31, 37, 47, 55,
                                                30, 40, 51, 45, 33, 48,
                                                44, 49, 39, 56, 34, 53,
                                                46, 42, 50, 36, 29, 32
            };
            Permutation_Tables["Initial Permutation"] = new int[64] {   58,50,42, 34, 26 ,18, 10, 2,
                                                60, 52, 44, 36, 28, 20, 12, 4,
                                                62, 54, 46, 38, 30, 22, 14, 6,
                                                64, 56, 48, 40, 32, 24, 16, 8,
                                                57, 49, 41, 33, 25, 17, 9, 1,
                                                59, 51, 43, 35, 27, 19, 11, 3,
                                                61, 53, 45, 37, 29, 21, 13, 5,
                                                63, 55, 47, 39, 31, 23, 15, 7
                                            };
            return Permutation_Tables;
        }
        public static int[,] Matrix_Creator(int[] IntialArray,int row,int col)
        {
            int[,] FinalMatrix = new int [row,col];
            int currIndx = 0;
            for (int i = 0; i < row; i++)
            {
                for (int h = 0; h < col; h++)
                {
                    FinalMatrix[i, h] = IntialArray[currIndx];
                    currIndx++;
                }
            }
            return FinalMatrix;
        }
        public static Dictionary<string, int[]> S_boxes_Table_Creator()
        { 
            Dictionary<string, int[]> S_boxes_Tables = new Dictionary<string, int[]>();

            S_boxes_Tables["S1"] = new int[64] {    14 ,4 ,13, 1, 2 ,15, 11, 8 ,3, 10 ,6 ,12 ,5, 9, 0, 7,
                                                    0, 15 ,7, 4 ,14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                                                    4, 1, 14 ,8, 13, 6 ,2 ,11, 15, 12, 9 ,7, 3, 10, 5, 0,
                                                    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0 ,6 ,13
            };
            S_boxes_Tables["S2"] = new int[64] { 15 ,1 ,8 ,14, 6, 11, 3 ,4, 9, 7, 2, 13, 12, 0, 5, 10,
                                                 3, 13, 4 ,7 ,15, 2 ,8 ,14, 12, 0, 1, 10, 6, 9, 11, 5,
                                                 0, 14, 7 ,11, 10, 4 ,13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                                                 13, 8, 10, 1, 3, 15, 4, 2, 11, 6 ,7 ,12, 0, 5, 14, 9
            };
            S_boxes_Tables["S3"] = new int[64] {    10, 0 ,9 ,14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                                                    13, 7 ,0 ,9 ,3 ,4 ,6 ,10 ,2, 8, 5, 14, 12, 11, 15, 1,
                                                    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5 ,10, 14, 7,
                                                    1, 10, 13, 0, 6, 9, 8, 7 ,4 ,15, 14, 3, 11, 5, 2, 12
            };
            S_boxes_Tables["S4"] = new int[64] {    7, 13, 14, 3 ,0 ,6 ,9 ,10 ,1 ,2 ,8, 5, 11, 12, 4, 15,
                                                     13, 8 ,11 ,5 ,6 ,15, 0 ,3 ,4 ,7 ,2 ,12, 1, 10, 14, 9,
                                                     10 ,6 ,9 ,0 ,12 ,11, 7 ,13 ,15, 1, 3, 14, 5, 2, 8, 4,
                                                     3, 15, 0 ,6 ,10, 1, 13, 8 ,9 ,4, 5, 11, 12, 7, 2, 14
            };
            S_boxes_Tables["S5"] = new int[64] {    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                                                    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                                                     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                                                    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            };
            S_boxes_Tables["S6"] = new int[64] {    12 ,1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                                                    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                                                    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                                                    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            };
            S_boxes_Tables["S7"] = new int[64] {    4 ,11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                                                    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                                                    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                                                    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            };
            S_boxes_Tables["S8"] = new int[64] {    13 ,2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                                                    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                                                    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                                                    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            };
            return S_boxes_Tables;
        }
        public static Dictionary<string, char> get_binary_Dic()
        {
            Dictionary<string, char> Binary = new Dictionary<string, char>();
            Binary["0000"] = '0';
            Binary["0001"] = '1';
            Binary["0010"] = '2';
            Binary["0011"] = '3';
            Binary["0100"] = '4';
            Binary["0101"] = '5';
            Binary["0110"] = '6';
            Binary["0111"] = '7';
            Binary["1000"] = '8';
            Binary["1001"] = '9';
            Binary["1010"] = 'A';
            Binary["1011"] = 'B';
            Binary["1100"] = 'C';
            Binary["1101"] = 'D';
            Binary["1110"] = 'E';
            Binary["1111"] = 'F';

            return Binary;
        }
        public static Tuple<int[], int[]> Create_C_D_Arr(int[] KeyTxtArray)
        {
            int[] C = new int[KeyTxtArray.Length / 2];
            int[] D = new int[KeyTxtArray.Length / 2];
            for (int i = 0; i < KeyTxtArray.Length; i++)
            {
                if (i < KeyTxtArray.Length / 2)
                {
                    C[i] = KeyTxtArray[i];
                }
                else
                {
                    D[i - KeyTxtArray.Length / 2] = KeyTxtArray[i];
                }
            }

            return Tuple.Create(C, D);
        }
        public static Tuple<List<int[]>, List<int[]>> Create_L_R_Arr(Dictionary<string, char> Binary, string cipherText, Dictionary<string, int[]> Permution_Tables)
        {
            // initial permution for plain text
            int[] InitialPermutationARR = Target_Txt_Preprocessing(Binary, cipherText, Permution_Tables);

            // LEFT and RIGHT from Initial Permutation Txt for plain txt
            int [,] InaiaMatrix = Matrix_Creator(InitialPermutationARR,8,8);
            List<int[]> LiftList = new List<int[]>();
            List<int[]> RightList = new List<int[]>();
            int[] Left = new int[InitialPermutationARR.Length / 2];
            int[] L = new int[InitialPermutationARR.Length / 2];
            int[] R = new int[InitialPermutationARR.Length / 2];
            int[] Right = new int[InitialPermutationARR.Length / 2];

            for (int i = 0; i < InitialPermutationARR.Length; i++)
            {
                if (i < InitialPermutationARR.Length / 2)
                {
                    Left[i] = InitialPermutationARR[i];
                }
                else
                {
                    Right[i - InitialPermutationARR.Length / 2] = InitialPermutationARR[i] ;
                }
            }
            LiftList.Add(Left);
            RightList.Add(Right);

            return Tuple.Create(LiftList, RightList);
        }
        public static List<int[]> Keys_Preprocessing(Dictionary<string, char> Binary, string key, Dictionary<string, int[]> Permution_Tables)
        {
            int[] KeyBit64 = new int[64];
            convert_from_text_to_binary(KeyBit64, key, Binary);

            int[] KeyTxtArray = Permutation(KeyBit64, Permution_Tables["PC 1 Key"]);

            Tuple<int[], int[]> tuple = Create_C_D_Arr(KeyTxtArray);
            int[] C = tuple.Item1;
            int[] D = tuple.Item2;

            // GEt All Shifted Keys in 16 round
            List<int[]> KeysShifted = get_shifted_all_keys(C, D, Permution_Tables);

            return KeysShifted;
        }
        public static int[] Target_Txt_Preprocessing(Dictionary<string, char> Binary, string cipherText, Dictionary<string, int[]> Permution_Tables)
        {
            // initial permution for plain text
            int[] PlainBit64 = new int[64];
            convert_from_text_to_binary(PlainBit64, cipherText, Binary);
            int[] InitialPermutationARR = Permutation(PlainBit64, Permution_Tables["Initial Permutation"]);
            return InitialPermutationARR;
        }
        public static string Run_DES(string cipherText, string key, bool type)
        {
            Dictionary<string, char> Binary = get_binary_Dic();
            Dictionary<string, int[]> S_boxes_Tables = S_boxes_Table_Creator();
            Dictionary<string, int[]> Permution_Tables = Permutation_Table_Creator();

            List<int[]> KeysShifted = Keys_Preprocessing(Binary, key, Permution_Tables);

            // LEFT and RIGHT from Initial Permutation Txt for plain txt
            Tuple<List<int[]>, List<int[]>> tuple = Create_L_R_Arr(Binary, cipherText,Permution_Tables);

            List<int[]> LiftList = tuple.Item1;
            List<int[]> RightList = tuple.Item2;

            if (!type) KeysShifted.Reverse();

            int[] FinalArr = Main_Function(LiftList, RightList, KeysShifted, Permution_Tables);
            int[] inverse_Initial_permutation_output = Permutation(FinalArr, Permution_Tables["Inverse Permutation"]);
            int[,] InversMatrix = Matrix_Creator(inverse_Initial_permutation_output, 8, 8);
            string Final_txt = convert_from_binary_to_text(inverse_Initial_permutation_output);
            return Final_txt;
        }
    }
}