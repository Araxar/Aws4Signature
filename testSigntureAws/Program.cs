using System;
using System.IO;
using System.Net;
using System.Text;

using Aws4Signature;

namespace AppelApi
{
    public class Program
    {

        private static readonly string _awsAccessKeyID = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
        private static readonly string _awsSecretAccessKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
        private static readonly string _awsRegionName = Environment.GetEnvironmentVariable("AWS_REGION_NAME");
        private static readonly string _awsSecretToken = Environment.GetEnvironmentVariable("AWS_SECRET_TOKEN");

        private static readonly string _myUri = "YOUR_AWS_URI"; 


        public static void Main(string[] args)
        {
            Program appel = new Program();

            SecurityCredentials credentials = new SecurityCredentials()
            {
                AccessKeyId = _awsAccessKeyID,
                SecretAccessKey = _awsSecretAccessKey,
                Token = _awsSecretToken
            };

            AwsSignedWebRequest request = AwsSignedWebRequest.Create(_myUri);
            request.Region = _awsRegionName;
            request.Method = "POST"; 
            request.ContentType = "application/json";
            String jsonPayload =  "SOME_PAYLOAD";
            
            var sw = new StreamWriter(request.GetRequestStream(), new ASCIIEncoding());               
            sw.Write(jsonPayload);
                
            //WebProxy proxy = new WebProxy();
            //proxy.Address = new Uri("http://185.132.178.204:8080"); // Public proxy
            //request.Proxy = proxy;

            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse(credentials);
                Console.WriteLine("{0} {1}", (int)response.StatusCode, response.StatusDescription);
                Console.WriteLine();

                using (StreamReader responseReader = new StreamReader(response.GetResponseStream()))
                {
                    Console.WriteLine(responseReader.ReadToEnd());
                }
            }
            catch (WebException e)
            {
                Console.WriteLine(e.Message);
                using (StreamReader responseReader = new StreamReader(e.Response.GetResponseStream()))
                {
                    Console.WriteLine(responseReader.ReadToEnd());
                }
            }
        }
    }
}