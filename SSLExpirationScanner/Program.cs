using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SslExpirationScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter the full path to your text file of domain names. Example: C:\\Users\\bob\\Desktop\\domains.txt");
            Console.WriteLine("One domain per line, like this:");
            Console.WriteLine("domain1.com");
            Console.WriteLine("domain2.com");
            Console.WriteLine("Please do not close the program until you see: Done!");
            string userInput = Console.ReadLine();
            string[] listOfDomains = File.ReadAllLines(userInput);
            Console.WriteLine(listOfDomains.Length);
            var csv = new StringBuilder();
            var firstLine = string.Format("Domain,Response URL,CA,Organization,Serial,Begins,Expires,IP");
            csv.AppendLine(firstLine);
            string ipAddress = "0";
            string countryFromIp = "None";
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            Parallel.ForEach(listOfDomains, new ParallelOptions { MaxDegreeOfParallelism = 12 }, item =>
            {
                string domain = item;

                try
                {
                    HttpWebRequest request;
                    string responseUrl;
                    try
                    {
                        request = (HttpWebRequest)WebRequest.Create("https://" + domain);
                        request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36";
                        request.AllowAutoRedirect = true;
                        request.Timeout = 5000;
                        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                        responseUrl = response.ResponseUri.ToString();
                        response.Close();
                    }
                    catch (Exception)
                    {
                        request = (HttpWebRequest)WebRequest.Create("https://www." + domain);
                        request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36";
                        request.AllowAutoRedirect = true;
                        request.Timeout = 5000;
                        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                        responseUrl = response.ResponseUri.ToString();
                        response.Close();
                    }
       
                    char httpVsS = responseUrl[4];
                    if (httpVsS == 's')
                    {
                        // get certificate
                        X509Certificate2 cert = new X509Certificate2(request.ServicePoint.Certificate);
                        string organization;
                        string issuerName;

                        // parse out Issuer name
                        string croppedBeforeIssuer = cert.Issuer.Substring(cert.Issuer.IndexOf("O=") + 2);
                        // check if name is enclosed in quote marks
                        if (croppedBeforeIssuer[0] == '"')
                        {
                            //if enclosed in quotes, remove them
                            croppedBeforeIssuer = croppedBeforeIssuer.Substring(1);
                            issuerName = croppedBeforeIssuer.Substring(0, croppedBeforeIssuer.IndexOf("\""));
                        }
                        else
                        {
                            issuerName = croppedBeforeIssuer.Substring(0, croppedBeforeIssuer.IndexOf(","));
                        }

                        // get rid of commas (they mess up csv)
                        issuerName = issuerName.Replace(",", string.Empty);

                        // check if Organization is specified for domain (if not it's a DV)
                        if ((Regex.Matches(Regex.Escape(cert.Subject), "O=").Count) > 0)
                        {
                            string croppedBeforeOrg = cert.Subject.Substring(cert.Subject.IndexOf("O=") + 2);
                            // check if name is enclosed in quote marks
                            if (croppedBeforeOrg[0] == '"')
                            {
                                //if enclosed in quotes, remove them
                                croppedBeforeOrg = croppedBeforeOrg.Substring(1);
                                organization = croppedBeforeOrg.Substring(0, croppedBeforeOrg.IndexOf("\""));
                            }
                            else
                            {
                                organization = croppedBeforeOrg.Substring(0, croppedBeforeOrg.IndexOf(","));
                            }
                        }
                        else
                        {
                            organization = "None";
                        }
                        // get rid of commas (they mess up csv)
                        organization = organization.Replace(",", string.Empty);
                        Console.WriteLine("Checked " + responseUrl);
                        var newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", domain, responseUrl, issuerName, organization, cert.SerialNumber, cert.NotBefore, cert.NotAfter, ipAddress);
                        csv.AppendLine(newLine);
                    }
                    else
                    {
                        Console.WriteLine("Checked " + responseUrl);
                        var newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", domain, responseUrl, "NA", "NA", "NA", "NA", "NA", ipAddress);
                        csv.AppendLine(newLine);
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("Error checking " + domain);
                    var newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", domain, "Error", "Error", "Error", "Error", "Error", "Error", ipAddress);
                    csv.AppendLine(newLine);
                }
            });

            File.WriteAllText("ssl-checker-output.csv", csv.ToString());
            Console.WriteLine("Done!");
            Console.WriteLine("Open the file ssl-checker-output.csv in the directory the program file is running from.");
            Console.WriteLine("");
            stopwatch.Stop();
            Console.WriteLine("Time elapsed: {0}", stopwatch.Elapsed);
            Console.ReadLine();
        }
    }
}
