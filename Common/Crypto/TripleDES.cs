using System.Text;
using Common.Converter;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Common.Crypto
{
    public sealed class TdesCryptoUtil
    {
        public static int TripleDesEcb(int decryptFlag, string key, string data, out string result)
        {
            try
            {
                byte[] keyBytes =  ConvertHelper.StringToHexbyte(key);

                byte[] plain =  ConvertHelper.StringToHexbyte(data);
                byte[]? byRst = null;
                if (decryptFlag == 0)
                    byRst = TdesECB(true, keyBytes, plain);
                else
                    byRst = TdesECB(false, keyBytes, plain);

                if (byRst == null)
                {
                    result = "Tdes ECB出错";
                    return -1;
                }

                result = ConvertHelper.HexbyteToString(byRst);
                return 0;
            }
            catch (Exception ex)
            {
                result = ex.Message;
                return -1;
            }
        }



        static byte[] TdesECB(bool encryptFlag, byte[] keyBytes, byte[] cipher, string algo = "DESede/ECB/NoPadding")
        {
            if (keyBytes.Length != 16) throw new ArgumentException("err key length");
            if (cipher.Length % 16 != 0) throw new ArgumentException("err data length");

            KeyParameter key = ParameterUtilities.CreateKeyParameter("DESede", keyBytes);
            IBufferedCipher c = CipherUtilities.GetCipher(algo);
            c.Init(encryptFlag, key);
            return c.DoFinal(cipher);
        }

    }

    sealed class TdesMac
    {


        private static int[] iSelePM1 = { // 置换选择1的矩阵
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43,
            35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,
            62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28,
            20, 12, 4 };

        private static int[] iSelePM2 = { // 置换选择2的矩阵
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7,
            27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44,
            49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

        private static int[] iROLtime = { // 循环左移位数表
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        private static int[] iInitPM = { // 初始置换IP
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46,
            38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33,
            25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29,
            21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

        private static int[] iInvInitPM = { // 初始逆置换
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46,
            14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12,
            52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50,
            18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

        private static int[] iEPM = { // 选择运算E
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15,
            16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26,
            27, 28, 29, 28, 29, 30, 31, 32, 1 };

        private static int[] iPPM = { // 置换运算P
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14,
            32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
        // 8个S盒

        private static int[][] iSPM = new int[8][];

        public TdesMac()
        {
            iSPM[0] = new int[]{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7,
                   4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8,
                  13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4,
                  9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 };

            iSPM[1] = new int[]{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4,
                        7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11,
                        10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3,
                        15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9};
            iSPM[2] = new int[] { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0,
                        9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8,
                        15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9,
                        8, 7, 4, 15, 14, 3, 11, 5, 2, 12};
            iSPM[3] = new int[] {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11,
                        5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12,
                        11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
                        13, 8, 9, 4, 5, 11, 12, 7, 2, 14 };
            iSPM[4] = new int[] {  2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2,
                        12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10,
                        13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
                        2, 13, 6, 15, 0, 9, 10, 4, 5, 3};
            iSPM[5] = new int[] {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4,
                        2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2,
                        8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15,
                        10, 11, 14, 1, 7, 6, 0, 8, 13 };
            iSPM[6] = new int[] {  4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11,
                        7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13,
                        12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
                        10, 7, 9, 5, 0, 15, 14, 2, 3, 12};
            iSPM[7] = new int[] {  13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13,
                        8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9,
                        12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
                        8, 13, 15, 12, 9, 0, 3, 5, 6, 11};

        }


        private int[] iCipherKey = new int[64];
        private int[] iCKTemp = new int[56];
        private int[] iPlaintext = new int[64];
        private int[] iCiphertext = new int[64];
        private int[] iPKTemp = new int[64];
        private int[] iL = new int[32];
        private int[] iR = new int[32];

        // 数组置换
        // iSource与iDest的大小不一定相等

        private void permu(int[] iSource, int[] iDest, int[] iPM)
        {
            if (iDest == null) iDest = new int[iPM.Length];

            for (int i = 0; i < iPM.Length; i++)
                iDest[i] = iSource[iPM[i] - 1];
        }

        // 将字节数组进行 位-〉整数 压缩
        // 例如：{0x35,0xf3}->{0,0,1,1,0,1,0,1,1,1,1,1,0,0,1,1}, bArray->iArray
        private void arrayBitToI(byte[] bArray, int[] iArray)
        {
            for (int i = 0; i < iArray.Length; i++)
            {
                iArray[i] = (int)(bArray[i / 8] >> (7 - i % 8) & 0x01);
            }
        }

        // 将整形数组进行 整数-〉位 压缩
        // arrayBitToI的逆变换,iArray->bArray
        private void arrayIToBit(byte[] bArray, int[] iArray)
        {
            for (int i = 0; i < bArray.Length; i++)
            {
                bArray[i] = (byte)iArray[8 * i];
                for (int j = 1; j < 8; j++)
                {
                    bArray[i] = (byte)(bArray[i] << 1);
                    bArray[i] += (byte)iArray[8 * i + j];
                }
            }
        }

        // 数组的逐项模2加
        // array1[i]=array1[i]^array2[i]
        private void arrayM2Add(int[] array1, int[] array2)
        {
            for (int i = 0; i < array2.Length; i++)
            {
                array1[i] ^= array2[i];
            }
        }

        // 一个数组等分成两个数组-数组切割
        private void arrayCut(int[] iSource, int[] iDest1, int[] iDest2)
        {
            int k = iSource.Length;
            for (int i = 0; i < k / 2; i++)
            {
                iDest1[i] = iSource[i];
                iDest2[i] = iSource[i + k / 2];
            }
        }

        // 两个等大的数组拼接成一个
        // arrayCut的逆变换
        private void arrayComb(int[] iDest, int[] iSource1, int[] iSource2)
        {
            int k = iSource1.Length;
            for (int i = 0; i < k; i++)
            {
                iDest[i] = iSource1[i];
                iDest[i + k] = iSource2[i];
            }
        }

        // 子密钥产生算法中的循环左移
        private void ROL(int[] array)
        {
            int temp = array[0];
            for (int i = 0; i < 27; i++)
            {
                array[i] = array[i + 1];
            }
            array[27] = temp;

            temp = array[28];
            for (int i = 0; i < 27; i++)
            {
                array[28 + i] = array[28 + i + 1];
            }
            array[55] = temp;


        }

        // 16个子密钥完全倒置
        private int[][] invSubKeys(int[][] iSubKeys)
        {
            int[][] iInvSubKeys = new int[16][];
            for (int i = 0; i < 16; i++)
            {
                iInvSubKeys[i] = new int[48];
                for (int j = 0; j < 48; j++)
                    iInvSubKeys[i][j] = iSubKeys[15 - i][j];
            }
            return iInvSubKeys;
        }

        // S盒代替
        // 输入输出皆为部分数组，因此带偏移量
        private void Sbox(int[] iInput, int iOffI, int[] iOutput, int iOffO,
                int[] iSPM)
        {
            int iRow = iInput[iOffI] * 2 + iInput[iOffI + 5]; // S盒中的行号
            int iCol = iInput[iOffI + 1] * 8 + iInput[iOffI + 2] * 4
                    + iInput[iOffI + 3] * 2 + iInput[iOffI + 4];
            // S盒中的列号
            int x = iSPM[16 * iRow + iCol];
            iOutput[iOffO] = x >> 3 & 0x01;
            iOutput[iOffO + 1] = x >> 2 & 0x01;
            iOutput[iOffO + 2] = x >> 1 & 0x01;
            iOutput[iOffO + 3] = x & 0x01;
        }

        // 加密函数f
        private int[] encFunc(int[] iInput, int[] iSubKey)
        {
            int[] iTemp1 = new int[48];
            int[] iTemp2 = new int[32];
            int[] iOutput = new int[32];
            permu(iInput, iTemp1, iEPM);
            arrayM2Add(iTemp1, iSubKey);
            for (int i = 0; i < 8; i++)
                Sbox(iTemp1, i * 6, iTemp2, i * 4, iSPM[i]);
            permu(iTemp2, iOutput, iPPM);
            return iOutput;
        }

        // 子密钥生成
        private int[][] makeSubKeys(byte[] bCipherKey)
        {
            int[][] iSubKeys = new int[16][];
            arrayBitToI(bCipherKey, iCipherKey);
            // int[] tmp = iCipherKey;
            permu(iCipherKey, iCKTemp, iSelePM1);
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < iROLtime[i]; j++)
                    ROL(iCKTemp);
                iSubKeys[i] = new int[48];
                permu(iCKTemp, iSubKeys[i], iSelePM2);
            }
            return iSubKeys;
        }

        // 加密
        private byte[] encrypt(byte[] bPlaintext, int[][] iSubKeys)
        {
            byte[] bCiphertext = new byte[8];
            arrayBitToI(bPlaintext, iPlaintext);
            permu(iPlaintext, iPKTemp, iInitPM);
            arrayCut(iPKTemp, iL, iR);
            for (int i = 0; i < 16; i++)
            {
                if (i % 2 == 0)
                {
                    arrayM2Add(iL, encFunc(iR, iSubKeys[i]));
                }
                else
                {
                    arrayM2Add(iR, encFunc(iL, iSubKeys[i]));
                }
            }
            arrayComb(iPKTemp, iR, iL);
            permu(iPKTemp, iCiphertext, iInvInitPM);
            arrayIToBit(bCiphertext, iCiphertext);
            return bCiphertext;
        }

        // 解密
        private byte[] decrypt(byte[] bCiphertext, int[][] iSubKeys)
        {
            int[][] iInvSubKeys = invSubKeys(iSubKeys);
            return encrypt(bCiphertext, iInvSubKeys);
        }

        // Bit XOR
        private byte[] BitXor(byte[] Data1, byte[] Data2, int Len)
        {
            int i;
            byte[] Dest = new byte[Len];

            for (i = 0; i < Len; i++)
                Dest[i] = (byte)(Data1[i] ^ Data2[i]);

            return Dest;
        }

        // 3DesMac
        private byte[] MAC16(int[][] iSubKeys1, int[][] iSubKeys2, byte[] bInit,
                byte[] bCiphertext)
        {
            byte[] pbySrcTemp = new byte[8];
            byte[] pbyInitData = new byte[8];
            byte[] pbyDeaSrc = new byte[8];
            byte[] pbyMac = new byte[4];
            int i, j, n, iAppend;
            int nCur = 0;
            int iSrcLen = bCiphertext.Length;
            n = iSrcLen / 8 + 1;
            iAppend = 8 - (n * 8 - iSrcLen);

            for (nCur = 0; nCur < 8; nCur++)
                pbyInitData[nCur] = bInit[nCur];

            for (i = 0; i < n; i++)
            {
                for (nCur = 0; nCur < 8; nCur++)
                    pbySrcTemp[0] = 0x00;
                if (i == (n - 1))
                {
                    for (nCur = 0; nCur < iAppend; nCur++)
                        pbySrcTemp[nCur] = bCiphertext[i * 8 + nCur];
                    pbySrcTemp[iAppend] = (byte)0x80;
                    for (j = iAppend + 1; j < 8; j++)
                        pbySrcTemp[j] = 0x00;
                }
                else
                {
                    for (nCur = 0; nCur < 8; nCur++)
                        pbySrcTemp[nCur] = bCiphertext[i * 8 + nCur];
                }

                pbyDeaSrc = BitXor(pbySrcTemp, pbyInitData, 8);

                pbyInitData = encrypt(pbyDeaSrc, iSubKeys1);
            }
            pbyDeaSrc = decrypt(pbyInitData, iSubKeys2);
            pbyInitData = encrypt(pbyDeaSrc, iSubKeys1);

            for (nCur = 0; nCur < 4; nCur++)
                pbyMac[nCur] = pbyInitData[nCur];
            return pbyMac;
        }

        //private string byte2hex(byte[] b)
        //{ // 一个字节的数，
        //    // 转成16进制字符串
        //    string hs = "";
        //    string stmp = "";
        //    for (int n = 0; n < b.Length; n++)
        //    {
        //        // 整数转成十六进制表示
        //        stmp = string.Format("{0:X2}", b[n] & 0XFF);// (java.lang.Integer.toHexString(b[n] & 0XFF));
        //        if (stmp.Length == 1)
        //            hs = hs + "0" + stmp;
        //        else
        //            hs = hs + stmp;
        //    }
        //    return hs.ToUpper(); // 转成大写
        //}

        private byte[] hex2byte(byte[] b)
        {
            if ((b.Length % 2) != 0)
                throw new Exception("长度不是偶数");
            byte[] b2 = new byte[b.Length / 2];
            for (int n = 0; n < b.Length; n += 2)
            {
                byte[] bs = new byte[2];
                Array.Copy(b, n, bs, 0, 2);
                string item = System.Text.Encoding.Default.GetString(bs);
                b2[n / 2] = (byte)Convert.ToInt16(item, 16);
            }
            return b2;
        }

        /*
         * strKey:密钥,Hex字符串,如:78B49F4BF5B16A17DF4AF5A36E49F4A0.长度必须为32
         * strInitData:初始因子.长度必须为16,一般为:0000000000000000 strMacData:MAC数据,长度必须为偶数
         */
        public string Str3MAC(string strKey, string strInitData, string strMacData)
        {
            string strKey1;
            string strKey2;
            if ((strKey.Length) != 32)
            {
                throw new Exception("密钥长度不正确,必须为32");
            }
            if ((strInitData.Length) != 16)
            {
                throw new Exception("初始因子长度不正确,必须为16");
            }
            if ((strMacData.Length % 2) != 0)
            {
                throw new Exception("MAC Data长度不是偶数");
            }

            strKey1 = strKey.Substring(0, 16);
            strKey2 = strKey.Substring(16, 16);

            byte[] cipherKey1 = hex2byte(Encoding.Default.GetBytes(strKey1)); // 3DES的密钥K1
            byte[] cipherKey2 = hex2byte(Encoding.Default.GetBytes(strKey2)); // 3DES的密钥K2
            byte[] bInit = hex2byte(Encoding.Default.GetBytes(strInitData)); // 初始因子
            byte[] bCiphertext = hex2byte(Encoding.Default.GetBytes(strMacData)); // MAC数据

            int[][] subKeys1 = new int[16][]; // 用于存放K1产生的子密钥
            int[][] subKeys2 = new int[16][]; // 用于存放K2产生的子密钥
            subKeys1 = makeSubKeys(cipherKey1);
            subKeys2 = makeSubKeys(cipherKey2);

            byte[] byMac = MAC16(subKeys1, subKeys2, bInit, bCiphertext);

            string sRet = byte2hex(byMac);
            //System.out.println("strKey:" + strKey + " strInitData:" + strInitData
            //        + " strMacData:" + strMacData);
            //System.out.println("sRet:" + sRet);
            return sRet;
        }

        public string calculatorMac(string communicationKey, string strData)
        {
            //System.out.println(strData);
            return this.Str3MAC(communicationKey, "0000000000000000", strData);
        }

        public string StrDe3DES(string strKey, string strEncData)
        {
            string strKey1;
            string strKey2;
            string strTemp1;
            string strTemp2;

            if ((strKey.Length) != 32)
            {
                throw new Exception("密钥长度不正确,必须为32");
            }
            if ((strEncData.Length) != 32)
            {
                throw new Exception("数据密文长度不正确,必须为32");
            }

            strKey1 = strKey.Substring(0, 16);
            strKey2 = strKey.Substring(16, 32);
            strTemp1 = strEncData.Substring(0, 16);
            strTemp2 = strEncData.Substring(16, 32);

            byte[] cipherKey1 = hex2byte(Encoding.Default.GetBytes(strKey1)); // 3DES的密钥K1
            byte[] cipherKey2 = hex2byte(Encoding.Default.GetBytes(strKey2)); // 3DES的密钥K2

            byte[] bCiphertext1 = hex2byte(Encoding.Default.GetBytes(strTemp1)); // 数据1
            byte[] bCiphertext2 = hex2byte(Encoding.Default.GetBytes(strTemp2)); // 数据1

            int[][] subKeys1 = new int[16][]; // 用于存放K1产生的子密钥
            int[][] subKeys2 = new int[16][]; // 用于存放K2产生的子密钥
            subKeys1 = makeSubKeys(cipherKey1);
            subKeys2 = makeSubKeys(cipherKey2);

            byte[] bTemp11 = decrypt(bCiphertext1, subKeys1);
            byte[] bTemp21 = encrypt(bTemp11, subKeys2);
            byte[] bPlaintext11 = decrypt(bTemp21, subKeys1);

            byte[] bTemp12 = decrypt(bCiphertext2, subKeys1);
            byte[] bTemp22 = encrypt(bTemp12, subKeys2);
            byte[] bPlaintext12 = decrypt(bTemp22, subKeys1);

            return byte2hex(bPlaintext11) + byte2hex(bPlaintext12);
        }

        private static byte[] hex2byte(string hexStr)
        {

            if ((hexStr.Length % 2) != 0)
                throw new Exception("长度不是偶数");

            int ilen = hexStr.Length / 2;
            byte[] b2 = new byte[ilen];
            for (int n = 0; n < hexStr.Length; n += 2)
            {
                string item = hexStr.Substring(n, 2);
                b2[n / 2] = (byte)Convert.ToInt16(item, 16);
            }
            return b2;
        }

        private static string byte2hex(byte[] b)
        { // 一个字节的数，
            // 转成16进制字符串
            string hs = "";
            string stmp = "";
            for (int n = 0; n < b.Length; n++)
            {
                // 整数转成十六进制表示
                stmp = string.Format("{0:X2}", b[n] & 0XFF);// (java.lang.Integer.toHexString(b[n] & 0XFF));
                if (stmp.Length == 1)
                    hs = hs + "0" + stmp;
                else
                    hs = hs + stmp;
            }
            return hs.ToUpper(); // 转成大写
        }

        //public static string DES3Encrypt(string strString, string strKey)
        //{
        //    TripleDESCryptoServiceProvider DES = new TripleDESCryptoServiceProvider();
        //    MD5CryptoServiceProvider hashMD5 = new MD5CryptoServiceProvider();
        //    DES.Key = hashMD5.ComputeHash(hex2byte(strKey));
        //    DES.Mode = CipherMode.ECB;
        //    ICryptoTransform DESEncrypt = DES.CreateEncryptor();
        //    byte[] Buffer = hex2byte(strKey);
        //    return byte2hex(DESEncrypt.TransformFinalBlock(Buffer, 0, Buffer.Length));

        //}
    }
}
