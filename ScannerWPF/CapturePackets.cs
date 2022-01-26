using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Http;
using System.Net;
using System.IO;
using System.Net.Mail;
using System.Threading;
using System.Net.NetworkInformation;
using System.Windows;

namespace ScannerWPF
{
    class CapturePackets
    {
        private PacketDevice selectedDevice;
        private ShowUI displayInfo = null;
        private PacketCommunicator communicator;
        private Thread thread;
        private string filter;

        public CapturePackets(ShowUI shower, PacketDevice selectedDevice, string filter)
        {
            this.selectedDevice = selectedDevice;
            this.displayInfo = shower;
            this.filter = filter;
        }

        public bool ThreadAlive
        {
            get { return this.thread.IsAlive; }
        }

        public void Start()
        {
            thread = new Thread(CaptureStarter);
            thread.Start();
        }

        public void Stop()
        {
            communicator.Break();

        }

        //Capture thread
        public void CaptureStarter()
        {
            try
            {
                // Open the device
                using (communicator =
                    selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                                        PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                        1000))                                  // read timeout
                {
                    using (BerkeleyPacketFilter BPFilter = communicator.CreateFilter(filter))
                    {
                        // Set the filter
                        communicator.SetFilter(BPFilter);
                    }
                    // Start the capture
                    communicator.ReceivePackets(0, PacketHandler);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("your filter is no corrent");
                MessageBox.Show("Worng " + ex.Message);
            }
        }

        // Callback function invoked by Pcap.Net for every incoming packet
        private void PacketHandler(Packet packet)
        {
            this.displayInfo.ShowData(packet);
        }
    }
}
