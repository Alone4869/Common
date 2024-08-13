using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;


namespace Common.Crypto
{
    public sealed class SM4CryptoUtil
    {

        public static int SM4_ECB(int decryptFlag, string key, string data, out string result)
        {
            try
            {
                byte[] keyBytes = StringToHexbyte(key);

                byte[] plain = StringToHexbyte(data);
                byte[]? byRst = null;
                if (decryptFlag == 0)
                    byRst = Sm4ECB(true, keyBytes, plain);
                else
                    byRst = Sm4ECB(false, keyBytes, plain);

                if (byRst == null)
                {
                    result = "SM4 ECB出错";
                    return -1;
                }

                result = HexbyteToString(byRst);
                return 0;
            }
            catch (Exception ex)
            {
                result = ex.Message;
                return -1;
            }
        }


        /// <summary>
        /// 把字符串转换为16进制数组
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        static byte[] StringToHexbyte(string str)
        {
            str = str.Replace(" ", "");
            if ((str.Length % 2) != 0)
                str += "";
            byte[] bytes = new byte[str.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(str.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        static string HexbyteToString(byte[] data)
        {
            StringBuilder res = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                res.Append(data[i].ToString("X2"));
            }
            return res.ToString();
        }



        static byte[] Sm4ECB(bool encryptFlag, byte[] keyBytes, byte[] cipher, string algo = "SM4/ECB/NoPadding")
        {
            if (keyBytes.Length != 16) throw new ArgumentException("err key length");
            if (cipher.Length % 16 != 0) throw new ArgumentException("err data length");


            KeyParameter key = ParameterUtilities.CreateKeyParameter("SM4", keyBytes);
            IBufferedCipher c = CipherUtilities.GetCipher(algo);
            c.Init(encryptFlag, key);
            return c.DoFinal(cipher);
        }
    }
}
