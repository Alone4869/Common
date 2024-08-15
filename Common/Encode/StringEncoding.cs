using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Utilities;
using System.Text;
using System.Xml;


namespace Common.Encode
{
    public sealed class StringEncoding
    {
        /// <summary>
        /// Hex 转 String
        /// </summary>
        /// <param name="hexstring"></param>
        /// <param name="encoding"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        public static int HexToString(string hexstring, Encoding encoding, out string result)
        {
            try
            {
                string data_tranfered = hexstring.Replace(" ", "");
                if (data_tranfered.Length % 2 != 0)
                {
                    result = "hex字符串长度不是2的倍数";
                    return -1;
                }
                byte[] bytes = new byte[data_tranfered.Length / 2];
                for (int i = 0; i < data_tranfered.Length; i += 2)
                {
                    bytes[i / 2] = Convert.ToByte(data_tranfered.Substring(i, 2), 16);
                }

                result = encoding.GetString(bytes);
                return 0;
            }
            catch (Exception ex)
            {
                result = ex.Message;
                return -1;
            }
        }


        public static int StringToHex(string srcString, Encoding encoding, out string result)
        {
            try
            {
                string data_tranfered = srcString.Replace(" ", "");
                string hexstring = string.Empty;
                byte[] data_b = encoding.GetBytes(data_tranfered);
                for (int i = 0; i < data_b.Length; i++)
                {
                    int asciicode = (int)(data_b[i]);
                    hexstring += asciicode.ToString("X2");
                }
                result = hexstring;
                return 0;
            }
            catch (Exception ex)
            {
                result = ex.Message;
                return -1;
            }
        }


        /// <summary>
        /// 格式化xml输出
        /// </summary>
        /// <param name="xmlString"></param>
        /// <returns></returns>
        public static int FormatXml(string xmlString, out string result)
        {
            XmlTextWriter xmlTxtWriter = null;
            int ret = -1;
            result = string.Empty;
            try
            {
                StringBuilder sb = new StringBuilder();
                StringWriter writer = new StringWriter(sb);
                XmlDocument xd = new XmlDocument();
                xd.LoadXml(xmlString);

                xmlTxtWriter = new XmlTextWriter(writer);
                xmlTxtWriter.Formatting = Formatting.Indented;
                xmlTxtWriter.Indentation = 1;
                xmlTxtWriter.IndentChar = '\t';
                xd.WriteTo(xmlTxtWriter);
                result = sb.ToString();
                ret = 0;
            }
            catch(Exception ex)
            {
                result = ex.Message;
                ret = -1;
            }
            finally
            {
                if (xmlTxtWriter != null)
                    xmlTxtWriter.Close();  
            }
            return ret;
        }
    }
}
