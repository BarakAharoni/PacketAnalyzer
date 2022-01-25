using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;

namespace ScannerWPF
{
    class ClientWork
    {
        private const int BUFSIZE = 64; // Size of received buffer
        private string serverIP;
        private ShowUI show = null;
        private string mac;

        public ClientWork(ShowUI show, string serverIP, string mac)
        {
            this.show = show;
            Debug.WriteLine(serverIP);
            this.serverIP = serverIP;
            this.mac = mac;
            Thread thread = new Thread(SendAndRecive);
            thread.Start();
        }

        public ClientWork(string serverIP)
        {
            this.show = null;
            Debug.WriteLine(serverIP);
            this.serverIP = serverIP;

        }

        public void Send(string msg)
        {
            ParameterizedThreadStart pts = new ParameterizedThreadStart(SendAndReciveWithParam);
            Thread thread = new Thread(SendAndReciveWithParam);
            thread.Start(msg);

        }

        private void SendAndReciveWithParam(object msg)
        {

            byte[] byteBuffer = Encoding.ASCII.GetBytes(msg.ToString()); //encode string

            // write ip of computer that u want to send messege 
            int serverPort = 7;

            string trueMac = mac; // My Gateway in the first situation;
            string nowIP = mac;


            TcpClient client = null;
            NetworkStream netStream = null;
            while (true)
            {
                try
                {
                    client = new TcpClient(this.serverIP, serverPort);

                    Debug.WriteLine("Connected to server... sending echo stream");

                    netStream = client.GetStream();
                    netStream.Write(byteBuffer, 0, byteBuffer.Length); //send encoded string to server

                    byte[] receiveBuffer = new byte[BUFSIZE];
                    int receiveCount = netStream.Read(receiveBuffer, 0, receiveBuffer.Length);

                    byte[] resolte = new byte[receiveCount];
                    for (int i = 0; i < receiveCount; i++)
                    {
                        resolte[i] = receiveBuffer[i];
                    }

                    string received = ByteArrayToString(resolte);
                    nowIP = received;

                    netStream.Close();
                    client.Close();
                }
                catch (Exception e)
                {
                    // No connection
                    Debug.WriteLine("Ex:     " + e.Message);
                }
                Thread.Sleep(400);
            }
        }

        private void SendAndRecive()
        {

            string echoString = "LIOr";
            byte[] byteBuffer = Encoding.ASCII.GetBytes(echoString); //encode string

            // write ip of computer that u want to send messege 
            int serverPort = 7;

            string trueMac = mac; // My Gateway in the first situation;
            string nowIP = mac;

            TcpClient client = null;
            NetworkStream netStream = null;
            while (true)
            {
                try
                {
                    client = new TcpClient(this.serverIP, serverPort);

                    // have connecterd, he have my server file in his computer 
                    Debug.WriteLine("Connected to server... sending echo stream");

                    // Insert to list of all the computers with my server file
                    this.show.ShowComputerWithFile(serverIP, true);

                    netStream = client.GetStream();
                    netStream.Write(byteBuffer, 0, byteBuffer.Length); //send encoded string to server

                    byte[] receiveBuffer = new byte[BUFSIZE];
                    int receiveCount = netStream.Read(receiveBuffer, 0, receiveBuffer.Length);
                    byte[] resolte = new byte[receiveCount];
                    for (int i = 0; i < receiveCount; i++)
                    {
                        resolte[i] = receiveBuffer[i];
                    }
                    string received = Encoding.ASCII.GetString(resolte);
                    this.show.ShowClientWork("IP: " + serverIP + " GateWay: " + received);

                    string[] parts = received.Split('&');
                    string gatewayMacNow = parts[0];
                    string statusNow = parts[1];

                    if (statusNow.Equals("attack") || statusNow.Equals("safe"))
                    {
                        this.show.ShowAttacksData(serverIP, gatewayMacNow, statusNow); // true = not equals threfore the list will insert line  
                    }
                    nowIP = received;

                    netStream.Close();
                    client.Close();
                }
                catch (Exception e)
                {
                    // No connection
                    Debug.WriteLine("Ex:     " + e.Message);
                    this.show.ShowComputerWithFile(serverIP, false);
                }

                Thread.Sleep(4000);
            }
        }
        private string ByteArrayToString(byte[] mac)
        {
            string hex = BitConverter.ToString(mac);
            return hex.Replace("-", ":");
        }

        public void ServerChet()
        {
            string name = "Server: ";
            int recv;
            byte[] data = new byte[1024];
            string input;
            IPEndPoint ipep = new IPEndPoint(IPAddress.Any, 9050);

            Socket newsock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            newsock.Bind(ipep);
            newsock.Listen(10);
            Console.WriteLine("Waiting for a Client...");
            Socket client = newsock.Accept();
            IPEndPoint clientep = (IPEndPoint)client.RemoteEndPoint;
            Console.WriteLine("Connected with{0} at  port {1}", clientep.Address, clientep.Port);

            string welcome = "Welcome to my test Server";
            data = Encoding.ASCII.GetBytes(welcome);
            client.Send(data, data.Length, SocketFlags.None);

            while (true)
            {
                try
                {
                    data = new byte[1024];
                    recv = client.Receive(data);
                    if (recv == 0)
                        break;

                    Console.WriteLine(Encoding.ASCII.GetString(data, 0, recv));
                    input = Console.ReadLine();
                    input = name + input;
                    data = Encoding.ASCII.GetBytes(input);
                }
                catch
                {
                    input = Console.ReadLine();
                    input = name + input;
                    data = Encoding.ASCII.GetBytes(input);
                }
                client.Send(data, data.Length, SocketFlags.None);
            }

            Console.WriteLine("Disconected from {0} ", clientep.Address);
            client.Close();
            newsock.Close();
        }

        private static string WMI()
        {
            ManagementObjectSearcher query = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = 'TRUE' ");
            ManagementObjectCollection queryCollection = query.Get();
            foreach (ManagementObject mo in queryCollection)
            {
                //string[] ipAddresses = (string[])mo["IPAddress"];
                string[] defaultgateways = (string[])mo["DefaultIPGateway"];

                //ipAddress = ipAddresses[0];
                //string ipGateway = defaultgateways[0];
                return defaultgateways[0];

            }
            return null;
        }
    }
}