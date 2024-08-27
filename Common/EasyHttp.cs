using System.Net;
using System.Text;
using Newtonsoft.Json;

namespace Common
{
    /// <summary>
    /// HTTP 请求类
    /// </summary>
    public sealed class EasyHttp
    {
        /// <summary>
        /// HTTP POST 请求
        /// </summary>
        /// <param name="requestUrl"></param>
        /// <param name="headers"></param>
        /// <param name="body"></param>
        /// <param name="contentType"></param>
        /// <returns></returns>
        public static async Task<Dictionary<string, object>> Post(string requestUrl, Dictionary<string, object> headers,
            Dictionary<string, object>? body, string contentType = "application/json")
        {
            using var client = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);

            if (body != null)
            {
                request.Content = new StringContent(JsonConvert.SerializeObject(body), Encoding.UTF8, contentType);
            }

            foreach (var header in headers.Where(header =>
                         !header.Key.Equals("content-type", StringComparison.CurrentCultureIgnoreCase)))
            {
                request.Headers.Add(header.Key, header.Value.ToString());
            }


            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return new Dictionary<string, object>
                {
                    { "code", response.StatusCode },
                    { "result", responseBody },
                };
            }
            else
            {
                return new Dictionary<string, object>()
                {
                    { "code", response.StatusCode },
                    { "result", "" },
                };
            }
        }

        /// <summary>
        /// HTTP POST 请求
        /// </summary>
        /// <param name="requestUrl"></param>
        /// <param name="headers"></param>
        /// <param name="jsonBody"></param>
        /// <returns></returns>
        public static async Task<Dictionary<string, object>> Post(string requestUrl, Dictionary<string, object> headers,
            string? jsonBody)
        {
            using var client = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);

            if (jsonBody != null)
            {
                request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
            }

            foreach (var header in headers.Where(header =>
                         !header.Key.Equals("content-type", StringComparison.CurrentCultureIgnoreCase)))
            {
                request.Headers.Add(header.Key, header.Value.ToString());
            }


            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return new Dictionary<string, object>
                {
                    { "code", response.StatusCode },
                    { "result", responseBody },
                };
            }

            return new Dictionary<string, object>()
            {
                { "code", response.StatusCode },
                { "result", "" },
            };
        }

        /// <summary>
        /// HTTP GET 请求
        /// </summary>
        /// <param name="requestUrl"></param>
        /// <param name="headers"></param>
        /// <returns></returns>
        public static async Task<Dictionary<string, object>> Get(string requestUrl, Dictionary<string, object> headers)
        {
            using var client = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            foreach (var header in headers)
            {
                request.Headers.Add(header.Key, header.Value.ToString());
            }

            var response = await client.SendAsync(request);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return new Dictionary<string, object>
                {
                    { "code", response.StatusCode },
                    { "result", responseBody },
                };
            }
            else
            {
                return new Dictionary<string, object>()
                {
                    { "code", response.StatusCode },
                    { "result", "" },
                };
            }
        }


        /// <summary>
        /// HTTP PUT 请求
        /// </summary>
        /// <param name="requestUrl"></param>
        /// <param name="headers"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        public static async Task<Dictionary<string, object>> Put(string requestUrl, Dictionary<string, object> headers,
            string? body = null)
        {
            using var client = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Put, requestUrl);

            if (body != null)
            {
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            foreach (var header in headers.Where(header =>
                         !header.Key.Equals("content-type", StringComparison.CurrentCultureIgnoreCase)))
            {
                request.Headers.Add(header.Key, header.Value.ToString());
            }


            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return new Dictionary<string, object>
                {
                    { "code", response.StatusCode },
                    { "result", responseBody },
                };
            }

            return new Dictionary<string, object>()
            {
                { "code", response.StatusCode },
                { "result", "" },
            };
        }


        /// <summary>
        /// Http DELETE 请求
        /// </summary>
        /// <param name="requestUrl"></param>
        /// <param name="headers"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        public static async Task<Dictionary<string, object>> Delete(string requestUrl,
            Dictionary<string, object> headers, string? body = null)
        {
            using var client = new HttpClient();

            var request = new HttpRequestMessage(HttpMethod.Delete, requestUrl);

            if (body != null)
            {
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            foreach (var header in headers.Where(header =>
                         !header.Key.Equals("content-type", StringComparison.CurrentCultureIgnoreCase)))
            {
                request.Headers.Add(header.Key, header.Value.ToString());
            }


            var response = await client.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var responseBody = await response.Content.ReadAsStringAsync();

                return new Dictionary<string, object>
                {
                    { "code", response.StatusCode },
                    { "result", responseBody },
                };
            }

            return new Dictionary<string, object>()
            {
                { "code", response.StatusCode },
                { "result", "" },
            };
        }

        /// <summary>
        /// 获取重定向链接
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        public static async Task<string?> GetRedirectUrl(string url)
        {
            try
            {
                using var client = new HttpClient();
                var resp = await client.GetAsync(url);
                if (resp.RequestMessage == null) return null;

                var location = "";
                var referer = "";
                if (resp.StatusCode == System.Net.HttpStatusCode.Redirect)
                {
                    location = resp.Headers.Location?.ToString();
                }

                if (resp.RequestMessage.Headers.Contains("Referer"))
                {
                    referer = resp.RequestMessage.Headers.GetValues("Referer").FirstOrDefault();
                }

                return location ?? referer;
            }
            catch (Exception ex)
            {
                // Console.WriteLine(ex.ToString());
                return null;
            }
        }
    }
}