using System.Text;

namespace Common.Encode
{
    public sealed class base64CryptoUtil
    {
        /// <summary>
        /// base64编码
        /// </summary>
        /// <param name="encoding"></param>
        /// <param name="data"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static int EncodeBase64(Encoding encoding,string data, out string result)
        {
            try
            {
                byte[] bytes = encoding.GetBytes(data);

                result = Convert.ToBase64String(bytes);
                return 0;
            }
            catch (Exception ex)
            {
                result = $"base64编码出错-{ex.Message}";
                return -1;
            }
        }
        /// <summary>
        /// base64解码
        /// </summary>
        /// <param name="encoding"></param>
        /// <param name="data"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static int DecodeBase64(Encoding encoding, string data, out string result)
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(data);

                result = encoding.GetString(bytes);
                return 0;
            }
            catch (Exception ex)
            {
                result = $"base64解码出错-{ex.Message}";
                return -1;
            }
        }


        /// <summary>
        /// 是否是base64字符串
        /// </summary>
        /// <param name="base64Str"></param>
        /// <returns></returns>
        public static bool IsBase64(string base64Str)
        {
            // 如果字符串为空，或者长度不是4的倍数，则不是有效的Base64编码  
            if (string.IsNullOrEmpty(base64Str) || base64Str.Length % 4 != 0)
            {
                return false;
            }

            try
            {
                // 尝试将字符串解码为字节数组  
                byte[] decodedBytes = Convert.FromBase64String(base64Str);
                // 如果解码成功，则说明字符串是有效的Base64编码  
                return true;
            }
            catch (FormatException)
            {
                // 如果解码失败（抛出FormatException异常），则说明字符串不是有效的Base64编码  
                return false;
            }
        }
    }
}
