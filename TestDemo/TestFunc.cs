using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;

namespace TestDemo;

public class TestFunc
{
    public static void TestEncoding()
    {
        {
            var data = "123";

            Encoding encoding = Encoding.ASCII;

            var ret = Common.Encode.Encodings.StringToHex(data, encoding, out var hexString);
            if (ret == 0)
            {
                Console.WriteLine(hexString);
                ret = Common.Encode.Encodings.HexToString(hexString, encoding, out var str);
                Console.WriteLine(str);
            }
        }

        {
            var data = "李明";
            
            //.net core无法直接使用编码GB2312,需按以下方法使用,同理 GBK、GB18030等也一样
            //在NuGet包中安装包System.Text.Encoding.CodePages
            //在使用编码方法 Encoding.GetEncoding("GB2312") 之前，对编码进行注册
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Encoding encoding = Encoding.GetEncoding("GB2312");

            var ret = Common.Encode.Encodings.StringToHex(data, encoding, out var hexString);
            if (ret == 0)
            {
                Console.WriteLine(hexString);
                ret = Common.Encode.Encodings.HexToString(hexString, encoding, out var str);
                Console.WriteLine(str);
            }
        }

        
    }


    public static void TestBase64()
    {
        var data = "abc123";
        Encoding encoding = Encoding.UTF8;
        var ret = Common.Encode.base64CryptoUtil.EncodeBase64(encoding,data, out var base64String);
        if (ret == 0)
        {
            Console.WriteLine(base64String);
            ret = Common.Encode.base64CryptoUtil.DecodeBase64(encoding,base64String, out var str);
            Console.WriteLine(str);
        }
    }

    public static void TestAES()
    {
        var data = "abc123";
        var key = "1234567890123456";
        var ret = Common.Crypto.AESCryptoUtil.Encrypt(data, key, out var encData);
        if (ret == 0)
        {
            Console.WriteLine(encData);
            ret = Common.Crypto.AESCryptoUtil.Decrypt(encData, key, out var str);
            Console.WriteLine(str);
        }
    }
}