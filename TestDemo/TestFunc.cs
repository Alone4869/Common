using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using Common.Crypto;
using Common.Encode;
namespace TestDemo;

public class TestFunc
{
    public static void TestEncoding()
    {
        {
            var data = "123";

            Encoding encoding = Encoding.ASCII;

            var ret = Encodings.StringToHex(data, encoding, out var hexString);
            if (ret == 0)
            {
                Console.WriteLine(hexString);
                ret = Encodings.HexToString(hexString, encoding, out var str);
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

            var ret = Encodings.StringToHex(data, encoding, out var hexString);
            if (ret == 0)
            {
                Console.WriteLine(hexString);
                ret = Encodings.HexToString(hexString, encoding, out var str);
                Console.WriteLine(str);
            }
        }


    }


    public static void TestBase64()
    {
        var data = "abc123";
        Encoding encoding = Encoding.UTF8;
        var ret = base64CryptoUtil.EncodeBase64(encoding, data, out var base64String);
        if (ret == 0)
        {
            Console.WriteLine(base64String);
            ret = base64CryptoUtil.DecodeBase64(encoding, base64String, out var str);
            Console.WriteLine(str);
        }
    }

    public static void TestAES()
    {
        var data = "abc123";
        var key = "1234567890123456";
        var ret = AESCryptoUtil.Encrypt(data, key, out var encData);
        if (ret == 0)
        {
            Console.WriteLine(encData);
            ret = AESCryptoUtil.Decrypt(encData, key, out var str);
            Console.WriteLine(str);
        }
    }

    public static void TestSM4()
    {
        var ret = SM4CryptoUtil.SM4_ECB(true, "AFC68DEB6CB923A863E087083904749E",
            "00000000000000000000000000000000", out var result);
        if (ret == 0)
        {
            Console.WriteLine(result);
            ret = SM4CryptoUtil.SM4_ECB(false, "AFC68DEB6CB923A863E087083904749E", result, out var str);
            Console.WriteLine(str);
        }
    }

    public static void TestTDesMac()
    {
        var tdesMac = new TdesMac();
        var dataMac = tdesMac.Str3MAC("6AA56A069343BB33422D1CF05D54BC01", "713AF1CEEE6B42C4", "04DC0EF4340E2E00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        Console.WriteLine(dataMac.Substring(0,8));
    }

    public static void TestTDes()
    {
        var ret = TdesCryptoUtil.TripleDesEcb(true,"AFC68DEB6CB923A863E087083904749E","00000000000000000000000000000000",out var result);
        if (ret == 0)
        {
            Console.WriteLine(result);
            ret = TdesCryptoUtil.TripleDesEcb(false,"AFC68DEB6CB923A863E087083904749E",result,out var str);
            Console.WriteLine(str);
        }
    }

}