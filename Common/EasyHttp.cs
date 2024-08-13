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

		public static async Task<Dictionary<string,object>> Post(string requestUrl,Dictionary<string,object> headers, Dictionary<string,object> body, string contentType = "application/json")
		{
			using (var client = new HttpClient())
			{
				var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);

				if (body != null)
				{
					request.Content = new StringContent(JsonConvert.SerializeObject(body), Encoding.UTF8, contentType);
				}

				foreach (var header in headers)
				{
					if (header.Key.ToLower() == "content-type")
						continue;
					request.Headers.Add(header.Key, header.Value.ToString());
				}


				var response = await client.SendAsync(request);

				if (response.StatusCode == HttpStatusCode.OK)
				{
					string responseBody = await response.Content.ReadAsStringAsync();

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
								{ "code", response.StatusCode},
								{ "result", ""},
							};
				}
			}
		}


		public static async Task<Dictionary<string,object>> Get(string requestUrl, Dictionary<string, object> headers)
		{
			using (var client = new HttpClient())
			{
				var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
				foreach(var header in headers)
				{
					request.Headers.Add(header.Key, header.Value.ToString());
				}

				var response = await client.SendAsync(request);
				if(response.StatusCode == HttpStatusCode.OK)
				{
					string responseBody = await response.Content.ReadAsStringAsync();

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
								{ "code", response.StatusCode},
								{ "result", ""},
							};
				}

			}
		}
	}
}
