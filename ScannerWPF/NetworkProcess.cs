using PcapDotNet.Core;
using PcapDotNet.Base;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace ScannerWPF
{
    class NetworkProcess
    {
        public string AttackerIP { get; set; }
        public string AttackerMac { get; set; }
        public string VictimIP { get; set; }
        public string VictimMac { get; set; }
        public string Deffense { get; set; }
        public string Status { get; set; }


        public void SendDeffense(WMIcard prop, PacketDevice selectedDevice)
        {//בעלת פרטים נכונים על כתובת הנתב ובכך מחזירה את מצב המחשב להיות תקין Arp-Reply שולח פקטת
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                // Start the capture
                // ,  AttackerIP AttackerMac
                communicator.SendPacket(BuildArpPacketReply(prop.Gateway.Ip, VictimIP, prop.Gateway.Mac, VictimMac));//attacker instead victim

            }
        }

        private Packet BuildArpPacketReply(string ipSrc, string ipDst, string macSrc, string macDst)
        {
            //senderIP: Gateway ,targetIP: victim , senderMac: mine Computer, targetMac: victim
            string[] dstIP = ConvertIPtoString(ipDst);
            string[] srcIP = ConvertIPtoString(ipSrc);
            EthernetLayer ethernetLayer =
                 new EthernetLayer
                 {
                     Source = new MacAddress(macSrc),              // mine
                     Destination = new MacAddress(macDst),//attacker         // victim
                     EtherType = EthernetType.None, // Will be filled automatically.
                 };
            ArpLayer arpLayer =
                new ArpLayer
                {
                    ProtocolType = EthernetType.IpV4,
                    Operation = ArpOperation.Reply,
                    //computer (mine)
                    SenderHardwareAddress = StringToByteArray(RemoveDots(macSrc)).AsReadOnly(),
                    SenderProtocolAddress = new byte[] { byte.Parse(srcIP[0]), byte.Parse(srcIP[1]), byte.Parse(srcIP[2]), byte.Parse(srcIP[3]) }.AsReadOnly(),
                    // victim//attacker
                    TargetHardwareAddress = StringToByteArray(RemoveDots(macDst)).AsReadOnly(),
                    TargetProtocolAddress = new byte[] { byte.Parse(dstIP[0]), byte.Parse(dstIP[1]), byte.Parse(dstIP[2]), byte.Parse(dstIP[3]) }.AsReadOnly(),
                };
            PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer);
            return builder.Build(DateTime.Now);
        }
        private string RemoveDots(string srcMac) //edits mac to work with object
        {
            string[] s = srcMac.Split(':');
            return String.Join("", s);
        }
        private byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                     .ToArray();
        }
        private static string[] ConvertIPtoString(string ip)
        {
            string[] s = ip.Split('.');
            return s;
        }
    }
}
