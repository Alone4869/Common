using System.Text;
using System.Security.Cryptography;

namespace Common.Crypto
{
    [Obsolete("方法已过时")]
    public sealed class AESCryptoUtil_old
    {
        /// <summary>
        /// AES加密 128bit ECB Zero_padding
        /// </summary>
        /// <param name="str"></param>
        /// <param name="key"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static int Encrypt(string str, string key, out string result)
        {
            try
            {
                if (key.Length > 16)
                {
                    result = "128bit 密钥不可以16位!";
                    return -1;
                }

                if (key.Length < 16)
                {
                    key = key.PadRight(16, '\0');
                }

                byte[] keyArray = System.Text.Encoding.GetEncoding("GB2312").GetBytes(key);  //UTF-8 -->GB2312
                byte[] toEncryptArray = System.Text.Encoding.GetEncoding("GB2312").GetBytes(str);
                var rijndael = new System.Security.Cryptography.RijndaelManaged();
                rijndael.Key = keyArray;
                rijndael.Mode = System.Security.Cryptography.CipherMode.ECB;
                rijndael.Padding = System.Security.Cryptography.PaddingMode.Zeros;
                System.Security.Cryptography.ICryptoTransform cTransform = rijndael.CreateEncryptor();

                byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                //return Convert.ToBase64String(resultArray, 0, resultArray.Length);
                result = Convert.ToBase64String(resultArray);

                return 0;
            }
            catch(Exception ex)
            {
                result = ex.Message;
                return -1;
            }
        }


        /// <summary>
        /// AES解密 128bit ECB Zero_padding
        /// </summary>
        /// <param name="encdata"></param>
        /// <param name="key"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static int Decrypt(string encdata, string key, out string result)
        {
            try
            {
                if (key.Length > 16)
                {
                    result = "128bit 密钥不可以16位!";
                    return -1;
                }

                if (key.Length < 16)
                {
                    key = key.PadRight(16, '\0');
                }

                byte[] keyArray = System.Text.Encoding.GetEncoding("GBK").GetBytes(key);
                byte[] toEncryptArray = Convert.FromBase64String(encdata);
                var rijndael = new System.Security.Cryptography.RijndaelManaged();
                rijndael.Key = keyArray;
                rijndael.Mode = System.Security.Cryptography.CipherMode.ECB;
                rijndael.Padding = System.Security.Cryptography.PaddingMode.Zeros;
                //rijndael.IV = System.Text.Encoding.UTF8.GetBytes(Iv);
                System.Security.Cryptography.ICryptoTransform cTransform = rijndael.CreateDecryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                //return System.Text.Encoding.GetEncoding("GB2312").GetString(resultArray);
                result = Encoding.UTF8.GetString(resultArray);
                return 0;
            }
            catch (Exception ex)
            {
                result = ex.Message;
                return -1;
            }
        }
    
    
        
    }


    public sealed class AESCryptoUtil
    {
        /// <summary>
        /// AES加密 128bit ECB Zero_padding
        /// </summary>
        /// <param name="str"></param>
        /// <param name="key"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static int Encrypt(string str, string key, out string result)
        {
            try
            {
                if (key.Length > 16)
                {
                    result = "128bit 密钥不可以16位!";
                    return -1;
                }

                if (key.Length < 16)
                {
                    key = key.PadRight(16, '\0');
                }

                byte[] keyArray = System.Text.Encoding.GetEncoding("GB2312").GetBytes(key);  //UTF-8 -->GB2312
                byte[] toEncryptArray = System.Text.Encoding.GetEncoding("GB2312").GetBytes(str);

                using(Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = keyArray;
                    aesAlg.Mode = CipherMode.ECB;
                    aesAlg.Padding = PaddingMode.Zeros;

                    ICryptoTransform cTransform = aesAlg.CreateEncryptor();
                    byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                    result = Convert.ToBase64String(resultArray);
                }

                return 0;
            }
            catch (Exception ex)
            {
                result = ex.Message;
                return -1;
            }
        }


        /// <summary>
        /// AES解密 128bit ECB Zero_padding
        /// </summary>
        /// <param name="encdata"></param>
        /// <param name="key"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static int Decrypt(string encdata, string key, out string result)
        {
            try
            {
                if (key.Length > 16)
                {
                    result = "128bit 密钥不可以16位!";
                    return -1;
                }

                if (key.Length < 16)
                {
                    key = key.PadRight(16, '\0');
                }

                byte[] keyArray = System.Text.Encoding.GetEncoding("GBK").GetBytes(key);
                byte[] toEncryptArray = Convert.FromBase64String(encdata);

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = keyArray;
                    aesAlg.Mode = CipherMode.ECB;
                    aesAlg.Padding = PaddingMode.Zeros;

                    ICryptoTransform cTransform = aesAlg.CreateDecryptor();
                    byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                    result = Encoding.UTF8.GetString(resultArray);
                }

                return 0;
            }
            catch (Exception ex)
            {
                result = ex.Message;
                return -1;
            }
        }



    }
}
