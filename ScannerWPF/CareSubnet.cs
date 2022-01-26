using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.Management.Instrumentation;
using System.Threading;
using PcapDotNet.Core;
using System.Net.NetworkInformation;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Base;
using System.Diagnostics;

namespace ScannerWPF
{
    class CareSubnet
    {
        private ShowUI show;
        private WMIcard wmi;
        private Dictionary<string, string> useIP;
        private PacketCommunicator communicator1;
        private PacketCommunicator communicator2;
        private int count;
        private PacketDevice selectedDevice;

        public CareSubnet(PacketDevice selectedDevice, WMIcard wmi, ShowUI show, Dictionary<string, string> dictionary)
        {
            useIP = new Dictionary<string, string>();
            this.selectedDevice = selectedDevice;
            this.wmi = wmi;
            this.show = show;
            this.useIP = dictionary;

            Thread thread1 = new Thread(ListenToReply);
            thread1.Start();
            Thread thread2 = new Thread(Sub);
            thread2.Start();
            Thread thread3 = new Thread(StartTheThread);
            thread3.Start();
        }

        public void StartTheThread()
        {
            while (true)
            {
                this.show.ShowSubnet(this.useIP);
                Thread.Sleep(5000);
            }
        }

        public int GetCount
        {
            get { return this.count; }
        }

        public void Sub()
        {
            // Open the device
            using (communicator1 =
                 selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                             // 65536 guarantees that the whole packet will be captured on all the link layers
                                     PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                     1000))                                  // read timeout
            {
                if (wmi.SubnetMask == null || wmi.Computer.Ip == null)
                {
                    Debug.WriteLine("No Arp Entry");
                }
                else
                {
                    int[] ipAddrSplit = ConvertIPtoInt(wmi.Computer.Ip);

                    for (int i = 0; i < 256; i++)
                    {
                        for (int j = 1; j < 255; j++)
                        {
                            communicator1.SendPacket(BuildArpRequestPacket(wmi.Computer.Mac, wmi.Computer.Ip, ipAddrSplit[0] + "." + ipAddrSplit[1] + "." + i + "." + j));
                        }
                    }
                }
            }
        }

        public void ListenToReply()
        {

            // Open the device
            using (communicator2 =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                //Need Check
                using (BerkeleyPacketFilter filter = communicator2.CreateFilter("arp dst " + wmi.Computer.Ip + " and ether dst " + wmi.Computer.Mac + " and (not ether src " + wmi.Gateway.Mac + ")"))
                {
                    // Set the filter
                    communicator2.SetFilter(filter);
                }

                // Start the capture
                communicator2.ReceivePackets(0, HundleReply);

            }
        }

        public void HundleReply(Packet packet) // maybe, an use me for deffenses
        {
            EthernetDatagram etherD = packet.Ethernet;
            string mac = etherD.Source.ToString();
            ArpDatagram arpD = etherD.Arp;
            string ip = arpD.SenderProtocolIpV4Address.ToString();
            lock (useIP)
            {
                Debug.WriteLine("get Arp reply");
                if (!useIP.ContainsKey(ip))
                {
                    useIP.Add(ip, mac);
                    this.count = useIP.Count;
                    ClientWork cw = new ClientWork(show, ip, wmi.Gateway.Mac);
                }
            }
        }

        private Packet BuildArpRequestPacket(string senderHardware, string senderIP, string targetIP)
        {
            string[] src = ConvertIPtoString(senderIP);
            string[] destination = ConvertIPtoString(targetIP);
            EthernetLayer ethernetLayer =
                new EthernetLayer()
                {
                    // mine
                    Source = new MacAddress(senderHardware),
                    // victim
                    Destination = new MacAddress("FF:FF:FF:FF:FF:FF"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            ArpLayer arpLayer =
                new ArpLayer()
                {
                    ProtocolType = EthernetType.IpV4,
                    Operation = ArpOperation.Request,
                    //computer (mine)
                    SenderHardwareAddress = StringToByteArray(RemoveDots(senderHardware)).AsReadOnly(),
                    SenderProtocolAddress = new byte[] { byte.Parse(src[0]), byte.Parse(src[1]), byte.Parse(src[2]), byte.Parse(src[3]) }.AsReadOnly(),
                    // victim
                    TargetHardwareAddress = StringToByteArray("ffffffffffff").AsReadOnly(),
                    TargetProtocolAddress = new byte[] { byte.Parse(destination[0]), byte.Parse(destination[1]), byte.Parse(destination[2]), byte.Parse(destination[3]) }.AsReadOnly(),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer);
            return builder.Build(DateTime.Now);
        }

        private byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                     .ToArray();
        }

        private static int[] ConvertIPtoInt(string ip)
        {
            string[] s = ip.Split('.');
            int[] n = new int[s.Length];
            for (int i = 0; i < s.Length; i++)
            {
                n[i] = int.Parse(s[i]);
            }
            return n;

        }

        private static string[] ConvertIPtoString(string ip)
        {
            string[] s = ip.Split('.');
            return s;
        }

        private static string RemoveDots(string srcMac) //edits mac to work with object
        {
            string[] s = srcMac.Split(':');
            return String.Join("", s);
        }


        private static string ChangeMacToPysicalAddress(string mac)
        {
            string[] s = mac.Split(':');
            return String.Join("-", s);
        }



        public string Str()
        {
            // Print strings that contains the addresses
            lock (useIP)
            {
                string str = "";
                Debug.WriteLine("IP in Subnet : ");
                foreach (string key in useIP.Keys)
                {

                    //Console.WriteLine(key + " , " + useIP[key]);
                    str += key + " , " + useIP[key] + "                  ";
                }
                return str;
            }

        }

        public static int SubnetMaskBit(string subnetIP)
        {
            int bits = 0;
            int[] subnetMaskInt = ConvertIPtoInt(subnetIP);
            for (int i = 0; i < 4; i++)
            {
                if (subnetMaskInt[i] != 255)
                {
                    bits += 8;
                }
            }
            return bits;
        }
    }
}

