using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Text;
using Common.Converter;

namespace Common.Crypto
{
    public sealed class SM4CryptoUtil
    {

        /// <summary>
        /// SM4 ECB加解密 填充方式 NoPadding
        /// </summary>
        /// <param name="encryptFlag">true:加密, false:解密</param>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static int SM4_ECB(bool encryptFlag, string key, string data, out string result)
        {
            try
            {
                byte[] keyBytes = ConvertHelper.StringToHexbyte(key);

                byte[] plain = ConvertHelper.StringToHexbyte(data);
                byte[]? byRst = null;

                byRst = Sm4ECB(encryptFlag, keyBytes, plain);
                
                if (byRst == null)
                {
                    result = "SM4 ECB出错";
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


       


        /// <summary>
        /// SM4 ECB加解密
        /// </summary>
        /// <param name="encryptFlag"></param>
        /// <param name="keyBytes"></param>
        /// <param name="cipher"></param>
        /// <param name="algo"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
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
