using System.Text;
namespace Common.Converter;

public class ConvertHelper
{
    /// <summary>
    /// 把字符串转换为16进制数组
    /// </summary>
    /// <param name="str"></param>
    /// <returns></returns>
    public static byte[] StringToHexbyte(string str)
    {
        str = str.Replace(" ", "");
        if ((str.Length % 2) != 0)
            str += "0";
        byte[] bytes = new byte[str.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(str.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    public static string HexbyteToString(byte[] data)
    {
        StringBuilder res = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            res.Append(data[i].ToString("X2"));
        }
        return res.ToString();
    }
}