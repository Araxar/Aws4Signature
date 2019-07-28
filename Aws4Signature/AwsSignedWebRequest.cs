using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Aws4Signature
{
    public class AwsSignedWebRequest
    {
        private const string DEFAULT_SERVICE = "execute-api";
        private const string DEFAULT_REGION = "eu-west-1";
        private const string SIGNING_ALGORITHM = "AWS4-HMAC-SHA256";

        private readonly string _hostname;
        private readonly string _path;
        private readonly string _queryString;
        private MemoryStream _requestStream;
        private HttpWebRequest _webRequest;

        private AwsSignedWebRequest(Uri uri)
        {
            if (uri.Scheme != "https")
            {
                throw new InvalidOperationException("Unsupported scheme: " + uri.Scheme);
            }

            ExplodeUri(uri, out _hostname, out _path, out _queryString);
            _webRequest = (HttpWebRequest)WebRequest.Create(uri);
            Service = DEFAULT_SERVICE;
            Region = DEFAULT_REGION;
        }

        public string Service { get; set; }

        public string Region { get; set; }

        public string Method
        {
            get { return _webRequest.Method; }
            set { _webRequest.Method = value; }
        }

        public string Accept
        {
            get { return _webRequest.Accept; }
            set { _webRequest.Accept = value; }
        }

        public string ContentType
        {
            get { return _webRequest.ContentType; }
            set { _webRequest.ContentType = value; }
        }

        public long ContentLength
        {
            get { return _webRequest.ContentLength; }
            set { _webRequest.ContentLength = value; }
        }

        public IWebProxy Proxy
        {
            get { return _webRequest.Proxy; }
            set { _webRequest.Proxy = value; }
        }

        public WebHeaderCollection Headers
        {
            get { return _webRequest.Headers; }
        }

        public static AwsSignedWebRequest Create(string url)
        {
            return new AwsSignedWebRequest(new Uri(url));
        }

        public Stream GetRequestStream()
        {
            if (_requestStream != null)
            {
                return _requestStream;
            }

            _requestStream = new MemoryStream();
            return _requestStream;
        }

        public HttpWebRequest GetUnderlyingRequest()
        {
            return _webRequest;
        }

        public HttpWebResponse GetResponse(SecurityCredentials credentials)
        {
            DateTime currentDate = DateTime.UtcNow;
            string requestDate = currentDate.ToString("yyyyMMddTHHmmss") + "Z";
            string dateStamp = requestDate.Substring(0, 8);
            string credentialScope = dateStamp + "/" + Region + "/" + Service + "/" + "aws4_request";

            string payload = GetPayloadAsString();
            string canonicalHeaders;
            string signedHeaders;
            ComputeHeaders(credentials, requestDate, out canonicalHeaders, out signedHeaders);

            string canonicalRequest = GetCanonicalRequest(credentials, requestDate, payload, canonicalHeaders, signedHeaders);
            string stringToSign = GetStringToSign(requestDate, credentialScope, canonicalRequest);
            string authorizationHeader = GetAuthorizationHeader(credentials, dateStamp, credentialScope, signedHeaders, stringToSign);

            _webRequest.Headers.Add("Authorization", authorizationHeader);
            _webRequest.Headers.Add("X-Amz-Date", requestDate);
            if (!string.IsNullOrEmpty(credentials.Token))
            {
                _webRequest.Headers.Add("X-Amz-Security-Token", credentials.Token);
            }

            if ((payload != null) && (Method != "GET"))
            {
                using (StreamWriter requestWriter = new StreamWriter(_webRequest.GetRequestStream()))
                {
                    requestWriter.Write(payload);
                }
            }

            return (HttpWebResponse)_webRequest.GetResponse();
        }

        private string GetAuthorizationHeader(SecurityCredentials credentials, string dateStamp, string credentialScope, string signedHeaders, string stringToSign)
        {
            byte[] signingKey = GetSignatureKey(credentials.SecretAccessKey, dateStamp, Region, Service);
            string signature;
            using (HMACSHA256 hmac = new HMACSHA256(signingKey))
            {
                signature = Hex(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
            }

            string authorizationHeader = SIGNING_ALGORITHM + " "
              + "Credential=" + credentials.AccessKeyId + "/" + credentialScope + ", "
              + "SignedHeaders=" + signedHeaders + ", "
              + "Signature=" + signature;

            return authorizationHeader;
        }

        private string GetStringToSign(string requestDate, string credentialScope, string canonicalRequest)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                string stringToSign = SIGNING_ALGORITHM + "\n"
                  + requestDate + '\n'
                  + credentialScope + '\n'
                  + Hex(sha256.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest)));

                return stringToSign;
            }
        }

        private string GetCanonicalRequest(SecurityCredentials credentials, string requestDate, string payload, string canonicalHeaders, string signedHeaders)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                string payloadHash = Hex(sha256.ComputeHash(Encoding.UTF8.GetBytes(payload ?? "")));
                string canonicalRequest = Method + "\n" + _path + "\n" + (_queryString ?? "") + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;

                return canonicalRequest;
            }
        }

        private string GetPayloadAsString()
        {
            string payload = null;

            if (_requestStream != null)
            {
                _requestStream.Seek(0, SeekOrigin.Begin);
                using (StreamReader reader = new StreamReader(_requestStream))
                {
                    payload = reader.ReadToEnd();
                }

                _requestStream.Dispose();
                _requestStream = null;
            }

            return payload;
        }

        private void ComputeHeaders(SecurityCredentials credentials, string requestDate, out string canonicalHeaders, out string signedHeaders)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["host"] = _hostname;
            headers["x-amz-date"] = requestDate;

            if (!string.IsNullOrEmpty(ContentType))
            {
                headers["content-type"] = ContentType;
            }

            if (!string.IsNullOrEmpty(credentials.Token))
            {
                headers["x-amz-security-token"] = credentials.Token;
            }

            canonicalHeaders = string.Join("", headers.OrderBy(p => p.Key).Select(p => string.Format("{0}:{1}\n", p.Key.ToLower(), p.Value.Trim())).ToArray());
            signedHeaders = string.Join(";", headers.OrderBy(p => p.Key).Select(p => p.Key.ToLower()).ToArray());
        }

        private static byte[] Sign(byte[] key, string message)
        {
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            }
        }

        private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            byte[] kDate = Sign(Encoding.UTF8.GetBytes("AWS4" + key), dateStamp);
            byte[] kRegion = Sign(kDate, regionName);
            byte[] kService = Sign(kRegion, serviceName);
            byte[] kSigning = Sign(kService, "aws4_request");
            return kSigning;
        }

        private static string Hex(byte[] bytes)
        {
            const string hexChars = "0123456789abcdef";
            StringBuilder buffer = new StringBuilder();
            foreach (byte b in bytes)
            {
                buffer.Append(hexChars[(b >> 4) & 15]).Append(hexChars[b & 15]);
            }

            return buffer.ToString();
        }

        private static void ExplodeUri(Uri uri, out string hostname, out string path, out string queryString)
        {
            hostname = uri.Host;
            string pathAndQuery = uri.PathAndQuery;
            if (pathAndQuery == "")
            {
                pathAndQuery = "/";
            }

            int queryStringIndex = pathAndQuery.IndexOf('?');
            if (queryStringIndex >= 0)
            {
                path = pathAndQuery.Substring(0, queryStringIndex);
                queryString = pathAndQuery.Substring(queryStringIndex + 1);
            }
            else
            {
                path = pathAndQuery;
                queryString = "";
            }
        }
    }
}