using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ScannerWPF
{
    public class Address
    {
        private string mac;
        private string ip;

        public Address(string ip, string mac)
        {
            this.ip = ip;
            this.mac = mac;
        }

        public string Ip
        {
            get { return this.ip; }
            set { this.ip = value; }
        }

        public string Mac
        {
            get { return this.mac; }
            set { this.mac = value; }
        }

        public override string ToString()
        {
            return "IP: " + this.ip + "------> MAC: " + this.mac;
        }
    }
}
