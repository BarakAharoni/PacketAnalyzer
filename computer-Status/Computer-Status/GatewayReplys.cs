using PcapDotNet.Packets;
using PcapDotNet.Core;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace ComputerStatus
{
    class GatewayReplys
    {
        private static PacketCommunicator communicator;
        private static string SniffGateway = null; 
        private static bool wasAttack;
        private WMIcard wmi;

        public GatewayReplys(WMIcard wmi)
        {
            this.wmi = wmi;
            wasAttack = false;
            Thread th1 = new Thread(CheckReplys);
            th1.Start();
        }

        private void CheckReplys()
        {
            // Sniff all ARP Packets
            int deviceNumber = 0;
            PacketDevice selectedDevice = LivePacketDevice.AllLocalMachine[deviceNumber];

            // Open the device
            using (communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                //Need Check
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("arp and ether dst " + wmi.Computer.Mac))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                // Start the capture
                communicator.ReceivePackets(0, HundleReply);
            }

        }


        private void HundleReply(Packet packet) // maybe, an use me for deffenses
        {
            // Checks if packet sender is the Gateway - save his MAC Address
            
            EthernetDatagram etherD = packet.Ethernet;
            string macSrc = etherD.Source.ToString();
            ArpDatagram arpD = etherD.Arp;
            string ipSender = arpD.SenderProtocolIpV4Address.ToString();

            if (ipSender.Equals(wmi.Gateway.Ip))
            {
                SniffGateway = macSrc;
            }
            else
            {
                Console.WriteLine("not from Gatway --- " + macSrc);
            }
        }
               
        public string Status()
        {
            // Return the computer status - Attacked/Safe/Not Attacked yet
            // with the same MAC Address that saved every time before it changed
            // and compared to the Gateway
            if (SniffGateway != null)
            {
                if (!SniffGateway.Equals(wmi.Gateway.Mac))
                {
                    wasAttack = true;
                    return SniffGateway + "&attack";
                }
                else
                {
                    if (wasAttack)
                    {
                        return SniffGateway + "&safe";
                    }
                    else
                    {
                        return SniffGateway + "&not attack me never";
                    }
                }
            }
            return wmi.Gateway.Mac + "&NOP";
        }
    }
}
