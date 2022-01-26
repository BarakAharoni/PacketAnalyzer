using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Security;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Http;
using PcapDotNet.Core;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Base;
using System.Management;
using System.Net.NetworkInformation;
using System.Diagnostics;
//using Microsoft.Win32;
using System.Globalization;

namespace ScannerWPF
{
    public partial class MainWindow : Window, ShowUI
    {


        ControlBuilder buildF = new ControlBuilder();
        private WMIcard prop = new WMIcard();
        private int deviceNumber;
        private Dictionary<string, string> dictionaryIPMac = new Dictionary<string, string>();
        private CapturePackets cp;
        private Grid starterGrid;
        private Label bigTitle;
        private TabControl tab;
        private ComboBox comboFilter;
        private TextBox txtFilter;
        private ListBox lbEthernet;
        private ListBox lbIP;
        private ListBox lbTCP;
        private ListBox lbHTTP;
        private Button btStart;
        private Button btStop;
        private Button btReStart;
        private TabItem tabSubject1;
        private TabItem tabSubject2;
        private TabItem tabSubject3;
        private Grid tab2Grid;
        private Grid tab3Grid;
        private List<Packet> lstPackets = new List<Packet>();
        private ListBox arpTable;
        private ListBox clientListener; // show mac gateway that we get from another computers in the Network -- Show all the processes
        private ListView discribeStatusAttacksAtNetwork; // show the status of the Network if have attack by posning or not;
        //Yes - show data about the attack ;
        //else(No) - show empty list    
        private List<string> computersWithFile = new List<string>();
        private Button exit;
        private TabItem tabSubject4;
        private Grid tab4Grid;
        private ListBox serversComputer;
        private Filters fil;
        private PacketDevice selectedDevice;

        private Button kill;
        private Button protect;
        private Thread t;
        private string command;
        private string pass;
        private PerformanceCounter cpuCounter;
        private PerformanceCounter ramCounter;


        public MainWindow()
        {
            InitializeComponent();
            Random rnd = new Random();
            this.pass += (char)rnd.Next(97, 123);
            this.pass += (char)rnd.Next(97, 123);
            this.pass += (char)rnd.Next(97, 123);
            this.pass += (char)rnd.Next(97, 123);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Title = "ScannerWPF/>Admin Console";
            Console.WriteLine("Hello Admin, welcome to the Console Line");
            Thread t1 = new Thread(StartCommands);
            t1.Start();
            deviceNumber = GetDeviceNumber(prop.Computer.Ip); //Global integer to pass on between threads 
            selectedDevice = LivePacketDevice.AllLocalMachine[deviceNumber]; // Take the selected adapter
            SetUI();
            CareSubnet cs = new CareSubnet(selectedDevice, prop, this, dictionaryIPMac);
        }

        public static int GetDeviceNumber(string computerIP)
        {
            //Global integer to pass on between threads
            int devNum = -1;
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine; // global list of all deivices

            for (int i = 0; i < allDevices.Count; i++)
            {
                for (int j = 0; j < allDevices[i].Addresses.Count; j++)
                {
                    if (allDevices[i].Addresses[j].Address.ToString().Equals("Internet " + computerIP))
                    {
                        devNum = i;
                        return devNum;
                    }
                }
            }
            MessageBox.Show("Dont find any Device in computer");
            return devNum;
        }

        private void SetUI()
        {
            // MainWindow:
            Application.Current.MainWindow.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Application.Current.MainWindow.Height = 700;
            Application.Current.MainWindow.Width = 1150;
            Application.Current.MainWindow.Title = "Scanner-Programing";
            this.ResizeMode = ResizeMode.NoResize;
            this.ResizeMode = ResizeMode.CanMinimize;

            // Big Title: Local Scanner Program
            bigTitle = new Label();
            bigTitle.Content = "Local Scanner Program";
            bigTitle.FontSize = 50;
            bigTitle.FontFamily = new FontFamily("Arial");
            bigTitle.HorizontalAlignment = HorizontalAlignment.Center;
            bigTitle.VerticalAlignment = VerticalAlignment.Top;

            // Add TextBlock
            TextBlock txtBlock1 = new TextBlock();
            txtBlock1.Text = "Author Name";
            txtBlock1.FontSize = 14;
            txtBlock1.FontWeight = FontWeights.Bold;
            txtBlock1.Foreground = new SolidColorBrush(Colors.Green);
            txtBlock1.VerticalAlignment = VerticalAlignment.Top;

            // Create TabCotrol:
            tab = new TabControl();
            tab.HorizontalAlignment = HorizontalAlignment.Center;
            tab.VerticalAlignment = VerticalAlignment.Top;
            tab.Height = 400;
            tab.Width = 800;

            tabSubject1 = new TabItem();
            tabSubject2 = new TabItem();
            tabSubject3 = new TabItem();
            tabSubject4 = new TabItem();

            // Start Tab 1 

            // Create Grid for the Tab:
            Grid tabGrid = new Grid();
            buildF.CreateLittleGrid(tabGrid, 2, 5);
            tabGrid.RowDefinitions[2].Height = GridLength.Auto;
            tabGrid.RowDefinitions[4].Height = GridLength.Auto;

            // Buttons:
            btStart = new Button();
            buildF.CreateButton(btStart, tabGrid, 1, 0, HorizontalAlignment.Left, VerticalAlignment.Top);
            btStart.Content = "Start Scanner";
            btStart.Click += btStart_Click;

            btStop = new Button();
            buildF.CreateButton(btStop, tabGrid, 1, 0, HorizontalAlignment.Left, VerticalAlignment.Top);
            btStop.Content = "Stop";
            btStop.Visibility = Visibility.Hidden;
            btStop.Click += btStop_Click;

            btReStart = new Button();
            buildF.CreateButton(btReStart, tabGrid, 1, 0, HorizontalAlignment.Right, VerticalAlignment.Top);
            btReStart.Content = "ReStart";
            btReStart.Visibility = Visibility.Hidden;
            btReStart.Click += btReStart_Click;

            //ComboFilter
            comboFilter = new ComboBox();
            comboFilter.HorizontalAlignment = HorizontalAlignment.Left;
            comboFilter.VerticalAlignment = VerticalAlignment.Top;
            comboFilter.Width = 150;
            comboFilter.MaxDropDownHeight = 150;

            tabGrid.Children.Add(comboFilter);
            Grid.SetRow(comboFilter, 0);
            Grid.SetColumn(comboFilter, 0);

            // Fiter TextBox
            txtFilter = new TextBox();
            txtFilter.HorizontalAlignment = HorizontalAlignment.Right;
            txtFilter.VerticalAlignment = VerticalAlignment.Top;
            txtFilter.Width = 180;
            txtFilter.Visibility = Visibility.Hidden;
            tabGrid.Children.Add(txtFilter);
            Grid.SetRow(txtFilter, 0);
            Grid.SetColumn(txtFilter, 0);

            // initialization the ListBox
            lbEthernet = new ListBox();
            lbIP = new ListBox();
            lbTCP = new ListBox();
            lbHTTP = new ListBox();

            // Creates the ListBox and show him on Tab's Grid
            buildF.CreateListBox(lbEthernet, tabGrid, 0, 2, 100, 400);
            buildF.CreateListBox(lbIP, tabGrid, 0, 4, 100, 400);
            buildF.CreateListBox(lbTCP, tabGrid, 1, 2, 100, 400);
            buildF.CreateListBox(lbHTTP, tabGrid, 1, 4, 100, 400);

            lbEthernet.SelectionChanged += lbEthernet_SelectionChanged;

            //CreateLabel();
            Label labelEther = new Label();
            buildF.CreateLabel(labelEther, tabGrid, "Ethernet", 0, 1);
            Label labelIP = new Label();
            buildF.CreateLabel(labelIP, tabGrid, "IP", 0, 3);
            Label labelTCP = new Label();
            buildF.CreateLabel(labelTCP, tabGrid, "TCP", 1, 1);
            Label labelHTTP = new Label();
            buildF.CreateLabel(labelEther, tabGrid, "HTTP", 1, 3);

            // Finish Tab 1;

            // Start Tab 2

            // Create Grid for the Tab:
            tab2Grid = new Grid();
            buildF.CreateLittleGrid(tab2Grid, 2, 2);

            tab2Grid.ColumnDefinitions[0].Width = GridLength.Auto;                                  //new GridLength(1, GridUnitType.Star);         // Using Star(*)
            tab2Grid.ColumnDefinitions[1].Width = new GridLength(1, GridUnitType.Star);

            arpTable = new ListBox();

            // Creates the ListBox and show him on Tab's Grid
            buildF.CreateListBox(arpTable, tab2Grid, 1, 0, 185, 600);
            buildF.AddObjectToLIstBox("This IP :", arpTable);

            // Finish Tab 2;

            // Start Tab 3
            tab3Grid = new Grid();
            buildF.CreateLittleGrid(tab3Grid, 1, 3);

            clientListener = new ListBox();
            discribeStatusAttacksAtNetwork = new ListView();

            buildF.CreateListBox(clientListener, tab3Grid, 0, 0, 150, 800);
            buildF.CreateLabel(new Label(), tab3Grid, "Show Network Processes: ", 0, 1);
            CreateListView(discribeStatusAttacksAtNetwork, tab3Grid, 0, 2);

            tab3Grid.RowDefinitions[0].Height = new GridLength(5, GridUnitType.Star);
            tab3Grid.RowDefinitions[1].Height = GridLength.Auto;
            tab3Grid.RowDefinitions[2].Height = new GridLength(2, GridUnitType.Star);

            // Finish Tab 3;

            // Start Tab 4

            tab4Grid = new Grid();
            buildF.CreateLittleGrid(tab4Grid, 0, 0);
            serversComputer = new ListBox();
            buildF.CreateListBox(serversComputer, tab4Grid, 0, 0, 200, 800);

            // Finish Tab 4

            tabSubject1.Header = "Sniffer"; // the title
            tabSubject1.Content = tabGrid; // the window

            tabSubject2.Header = "IP in the Subnet";
            tabSubject2.Content = tab2Grid; // the window

            tabSubject3.Header = "Network Process";
            tabSubject3.Content = tab3Grid;

            tabSubject4.Header = "Connected computers";
            tabSubject4.Content = tab4Grid;

            tab.Items.Add(tabSubject1);
            tab.Items.Add(tabSubject2);
            tab.Items.Add(tabSubject3);
            tab.Items.Add(tabSubject4);

            // Create Main Grid:
            starterGrid = new Grid();
            starterGrid.HorizontalAlignment = HorizontalAlignment.Left;
            starterGrid.VerticalAlignment = VerticalAlignment.Top;
            starterGrid.Height = Application.Current.MainWindow.Height; // like at start open
            starterGrid.Width = Application.Current.MainWindow.Width; // like at start open          
            starterGrid.Background = new SolidColorBrush(Colors.SeaGreen);

            // Create Columns
            ColumnDefinition gridCol1 = new ColumnDefinition();
            starterGrid.ColumnDefinitions.Add(gridCol1);

            // Create Rows
            RowDefinition gridRow1 = new RowDefinition();
            RowDefinition gridRow2 = new RowDefinition();
            RowDefinition gridRow3 = new RowDefinition();
            gridRow1.Height = GridLength.Auto;                  // create Grid's rows by Auto; 
            starterGrid.RowDefinitions.Add(gridRow1);
            starterGrid.RowDefinitions.Add(gridRow2);
            starterGrid.RowDefinitions.Add(gridRow3);

            // Places the Values in the Grid:
            starterGrid.Children.Add(bigTitle);
            Grid.SetRow(bigTitle, 0);
            Grid.SetColumn(bigTitle, 0);

            starterGrid.Children.Add(tab);
            Grid.SetRow(tab, 1);
            Grid.SetColumn(tab, 0);

            // Exit-Button
            exit = new Button();
            buildF.CreateButton(exit, starterGrid, 0, 2, HorizontalAlignment.Center, VerticalAlignment.Center);
            exit.Width = 200;
            exit.Height = 30;
            exit.Content = "Exit";
            exit.Click += exit_Click;

            //attack button
            kill = new Button();
            buildF.CreateButton(kill, starterGrid, 0, 3, HorizontalAlignment.Left, VerticalAlignment.Center);
            kill.Width = 150;
            kill.Height = 30;
            kill.Content = "Close Connections";
            kill.Click += kill_Click;

            //protect button
            protect = new Button();
            buildF.CreateButton(protect, starterGrid, 0, 3, HorizontalAlignment.Right, VerticalAlignment.Center);
            protect.Width = 150;
            protect.Height = 30;
            protect.Content = "Open Connections";
            protect.Click += protect_Click;


            // Window-Content
            Application.Current.MainWindow.Content = starterGrid;

            //  Add filters to ComboBox
            fil = new Filters(comboFilter, txtFilter);

        }

        public static void StartCmd()
        {
            System.Diagnostics.ProcessStartInfo myProcessInfo = new System.Diagnostics.ProcessStartInfo(); //Initializes a new ProcessStartInfo of name myProcessInfo
            myProcessInfo.FileName = Environment.ExpandEnvironmentVariables("%SystemRoot%") + @"\System32\cmd.exe"; //Sets the FileName property of myProcessInfo to %SystemRoot%\System32\cmd.exe where %SystemRoot% is a system variable which is expanded using Environment.ExpandEnvironmentVariables
            myProcessInfo.Arguments = "cd C/"; //Sets the arguments to cd..
            myProcessInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Normal; //Sets the WindowStyle of myProcessInfo which indicates the window state to use when the process is started to Hidden
            System.Diagnostics.Process.Start(myProcessInfo);
        }

        public static string GetIPbyHostName(string s)
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            IPAddress[] ip = Dns.GetHostAddresses(s);
            string ipstr = "";
            for (int i = 0; i < ip.Length; i++)
                ipstr += ip[i].ToString();
            Console.WriteLine(ipstr);
            return ipstr;
        }
        public static void SendDOS()
        {
            System.Diagnostics.Process proc;

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("IP or DNS ?");
            string ans = Console.ReadLine();
            if (ans == "IP" || ans == "ip")
            {
                Console.WriteLine("Enter IP to attack: ");
                string s = Console.ReadLine();
                Console.WriteLine("Starting DOS Attack!");

                string cmd = "/C ping " + s + " -t -l 65000";
                proc = new System.Diagnostics.Process();
                proc.EnableRaisingEvents = false;
                proc.StartInfo.FileName = "cmd";
                proc.StartInfo.Arguments = cmd;
                proc.Start();

                //}
            }
            else if (ans == "DNS" || ans == "dns")
            {
                Console.WriteLine("Enter web name to attack: ");
                string s = Console.ReadLine();
                Console.WriteLine("Starting DOS Attack!");
                string ipstr = GetIPbyHostName(s);
                string cmd = "/C ping " + s + " -t -l 65000";

                proc = new System.Diagnostics.Process();
                proc.EnableRaisingEvents = false;
                proc.StartInfo.FileName = "cmd";
                proc.StartInfo.Arguments = cmd;
                proc.Start();

            }
        }

        void protect_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Protect");
            SelectQuery wmiQuery = new SelectQuery("SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionId != NULL");
            ManagementObjectSearcher searchProcedure = new ManagementObjectSearcher(wmiQuery);
            foreach (ManagementObject item in searchProcedure.Get())
            {

                MessageBox.Show(((string)item["NetConnectionId"]) + " Enable");
                item.InvokeMethod("Enable", null);
                Enable(((string)item["NetConnectionId"]));

            }
        }

        void kill_Click(object sender, RoutedEventArgs e)
        {
            Thread t1 = new Thread(KillTread);
            t1.Start();
            DisableConnection();
        }
        void KillTread()
        {
            MessageBox.Show("Disconnect");
            SelectQuery wmiQuery = new SelectQuery("SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionId != NULL");
            ManagementObjectSearcher searchProcedure = new ManagementObjectSearcher(wmiQuery);
            foreach (ManagementObject item in searchProcedure.Get())
            {

                MessageBox.Show(((string)item["NetConnectionId"]) + " Disable");
                item.InvokeMethod("Disable", null);
                Disable(((string)item["NetConnectionId"]));

                //}
            }
        }

        void Disable(string interfaceName)
        {
            System.Diagnostics.ProcessStartInfo psi =
                new System.Diagnostics.ProcessStartInfo("netsh", "interface set interface \"" + interfaceName + "\" disable");
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo = psi;
            p.Start();
        }

        void Enable(string interfaceName)
        {
            System.Diagnostics.ProcessStartInfo psi =
               new System.Diagnostics.ProcessStartInfo("netsh", "interface set interface \"" + interfaceName + "\" enable");
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo = psi;
            p.Start();
        }
        void exit_Click(object sender, RoutedEventArgs e)
        {
            Environment.Exit(Environment.ExitCode);
        }

        void btStart_Click(object sender, RoutedEventArgs e)
        {
            // Start to sniff

            cp = new CapturePackets(this, selectedDevice, fil.GetFilter());
            cp.Start();

            btStart.Visibility = Visibility.Hidden;
            btStop.Visibility = Visibility.Visible;
            btReStart.Visibility = Visibility.Visible;
            btReStart.IsEnabled = false;
            txtFilter.IsEnabled = false;
            comboFilter.IsEnabled = false;
        }

        void btStop_Click(object sender, RoutedEventArgs e)
        {
            if (btStop.Content.Equals("Stop"))
            {
                cp.Stop();
                btReStart.IsEnabled = true;
                btStop.Content = "Continue";
            }
            else
            {
                btStart_Click(sender, e);
                btReStart.IsEnabled = false;
                btStop.Content = "Stop";
            }
        }

        void btReStart_Click(object sender, RoutedEventArgs e)
        {
            lstPackets.Clear();
            lbEthernet.Items.Clear();
            lbIP.Items.Clear();
            lbTCP.Items.Clear();
            lbHTTP.Items.Clear();
            comboFilter.Text = "None";
            txtFilter.Clear();
            txtFilter.Visibility = Visibility.Hidden;
            txtFilter.IsEnabled = true;
            comboFilter.IsEnabled = true;

        }

        void lbEthernet_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

            lock (lstPackets)
            {
                if (!this.cp.ThreadAlive && lstPackets.Count > 0)
                {
                    int ethernetIndex = this.lbEthernet.SelectedIndex;
                    Packet packet = this.lstPackets[ethernetIndex];
                    //// IP Layer:
                    this.lbIP.Items.Clear();
                    IpV4Datagram ip = packet.Ethernet.IpV4;
                    string formatIP = string.Format("Header Length: {0},TotalLength: {1},Time To Live: {2},Protocol: {3},Source: {4} ,Dest: {5}", ip.HeaderLength, ip.TotalLength, ip.Ttl, ip.Protocol, ip.Source, ip.Destination);
                    InsertDataWithSplit(formatIP, lbIP, ",");
                    // TCP Layer:
                    this.lbTCP.Items.Clear();
                    if (ip.Protocol.ToString().Equals("Tcp"))
                    {
                        TcpDatagram tcp = ip.Tcp;
                        string formatTCP = string.Format("Source Port: {0},Destination Port: {1},Sequence Number {2},Acknowledgment Number: {3},Header Length: {4},Window: {5},Checksum: {6} ", tcp.SourcePort, tcp.DestinationPort, tcp.SequenceNumber, tcp.AcknowledgmentNumber, tcp.HeaderLength, tcp.Window, tcp.Checksum);
                        InsertDataWithSplit(formatTCP, lbTCP, ",");

                        // HTTP Layer:
                        this.lbHTTP.Items.Clear();
                        if (ip.Tcp.Http != null && ip.Tcp.Http.Length > 0)
                        {
                            HttpDatagram http = ip.Tcp.Http;
                            if (http.IsRequest)
                            {

                                HttpRequestLayer hr = (HttpRequestLayer)http.ExtractLayer();
                                if (hr.Method != null && hr.Uri != null)
                                {
                                    lbHTTP.Items.Add("Request:");
                                    string formatHTTP = string.Format("Length: {0},Method: {1},Uri: {2}"
                                        , http.Length, hr.Method.Method, hr.Uri);
                                    InsertDataWithSplit(formatHTTP, lbHTTP, ",");
                                    //Http Head:
                                    if (http.Header != null)
                                    {
                                        lbHTTP.Items.Add("Header:");
                                        InsertDataWithSplit(http.Header.ToString(), lbHTTP, "\r\n");
                                    }
                                    if (hr.Method.Method.Equals("POST"))
                                    {
                                        //Http body:
                                        MemoryStream ms = http.Body.ToMemoryStream();
                                        StreamReader sr = new StreamReader(ms, System.Text.Encoding.UTF8,
                                                                   true);
                                        byte[] bytes = new byte[ms.Length];
                                        string body = sr.ReadToEnd();

                                        lbHTTP.Items.Add("Body: Logs Parameters:");
                                        InsertDataWithSplit(body.ToString(), lbHTTP, "&");
                                    }
                                }
                            }
                            else if (http.IsResponse)
                            {
                                lbHTTP.Items.Add("Response:");
                                HttpResponseLayer hr = (HttpResponseLayer)http.ExtractLayer();
                                string formatHTTP = string.Format("Length: {0},Status Code: {1},Response Phrase: {2}", http.Length, hr.StatusCode, hr.ReasonPhrase); //Header: ,Host: {1},Connection {2},Content Length: {3},CachePolicy: {4},ContentType: {5},
                                InsertDataWithSplit(formatHTTP, lbHTTP, ",");
                                if (http.Header != null)
                                {
                                    lbHTTP.Items.Add("Header:");
                                    InsertDataWithSplit(http.Header.ToString(), lbHTTP, "\r\n");
                                }

                            }
                        }
                    }
                }
            }
        }

        private static void InsertDataWithSplit(string data, ListBox lstBox, string parameter) // without number returns all
        {
            string[] sr;
            if (parameter.Length > 1)
            {
                sr = data.Split(new string[] { parameter }, StringSplitOptions.None);
            }
            else
            {
                sr = data.Split(parameter[0]);
            }
            for (int i = 0; i < sr.Length; i++)
            {
                lstBox.Items.Add(sr[i]);
            }
        }

        // ShowUI Functions:
        public void ShowData(Packet packet)
        {
            lock (lstPackets)
            {
                if (lstPackets.Count == 1000)
                {
                    this.Dispatcher.Invoke((Action)(() =>
                    {
                        lbEthernet.Items.RemoveAt(0);
                    }));
                    lstPackets.RemoveAt(0);
                }
                lstPackets.Add(packet);
            }
            EthernetDatagram dg = packet.Ethernet;
            string dataEthernet = string.Format("Ethernet Type: {0}, Length: {1} , Source : {2}, Dest : {3}", dg.EtherType, dg.Length, dg.Source, dg.Destination);
            this.Dispatcher.Invoke((Action)(() =>
            {

                if (dg.EtherType.ToString() == "Arp")//arp
                    lbEthernet.Background = Brushes.DarkGreen;
                else if (dg.EtherType.ToString() == "IpV4")//tcp 
                    lbEthernet.Background = Brushes.Blue;
                else if (dg.EtherType.ToString() == "IpV6")//udp 
                    lbEthernet.Background = Brushes.Red;
                else
                    lbEthernet.Background = Brushes.White;

                lbEthernet.Items.Add(dataEthernet);
            }));
        }
        public void ShowClientWork(string itemToShow)
        {
            this.Dispatcher.Invoke((Action)(() =>
            {
                buildF.AddObjectToLIstBox(itemToShow, this.clientListener);
            }));
        }
        public void ShowAttacksData(string ipVictim, string macAttacker, string status)
        {
            string macVictim = "";
            string ipAttacker = "";
            lock (dictionaryIPMac)
            {
                macVictim = dictionaryIPMac[ipVictim];
                if (dictionaryIPMac.ContainsValue(macAttacker))
                {
                    foreach (string key in dictionaryIPMac.Keys)
                    {
                        if (macAttacker.Equals(dictionaryIPMac[key]))
                        {
                            ipAttacker = key;
                        }
                    }
                }
            }
            NetworkProcess dataAttack = new NetworkProcess() { AttackerIP = ipAttacker, AttackerMac = macAttacker, VictimIP = ipVictim, VictimMac = macVictim, Deffense = "Strat Deffense", Status = status };
            List<NetworkProcess> dataAttackList = new List<NetworkProcess>();
            lock (discribeStatusAttacksAtNetwork)
            {
                for (int i = 0; i < discribeStatusAttacksAtNetwork.Items.Count; i++)
                {
                    NetworkProcess data = (NetworkProcess)discribeStatusAttacksAtNetwork.Items[i];
                    dataAttackList.Add(data);
                }
                bool exist = false;
                foreach (NetworkProcess data in dataAttackList)
                {
                    if (data.VictimMac.Equals(macVictim))
                    {
                        exist = true;
                        if (!data.Status.Equals(status))
                        {
                            this.Dispatcher.Invoke((Action)(() =>
                            {
                                RemoveItemFromLIstView(data, discribeStatusAttacksAtNetwork);
                                data.Status = status;
                                AddItemToLIstView(data, discribeStatusAttacksAtNetwork);
                            }));
                        }
                        break;
                    }
                }
                if (!exist)
                {
                    this.Dispatcher.Invoke((Action)(() =>
                    {

                        AddItemToLIstView(dataAttack, this.discribeStatusAttacksAtNetwork);
                    }));
                }
            }
        }
        public void ShowSubnet(Dictionary<string, string> dictionarySubnet)
        {
            lock (dictionarySubnet)
            {
                this.Dispatcher.Invoke((Action)(() =>
                {
                    arpTable.Items.Clear();
                }));
                foreach (string key in dictionarySubnet.Keys)
                {
                    this.Dispatcher.Invoke((Action)(() =>
                    {
                        buildF.AddObjectToLIstBox(key, arpTable);
                    }));
                    dictionaryIPMac = dictionarySubnet;
                }
                this.Dispatcher.Invoke((Action)(() =>
                {
                    buildF.AddObjectToLIstBox("Table Count " + arpTable.Items.Count, arpTable);
                }));
            }
        }
        public void ShowComputerWithFile(string ip, bool connected)
        {
            if (connected)
            {
                if (!computersWithFile.Contains(ip))
                {
                    computersWithFile.Add(ip);
                    this.Dispatcher.Invoke((Action)(() =>
                    {
                        serversComputer.Items.Add(ip);
                    }));
                }
                Thread t1 = new Thread(NewComputerConected);
                t1.Start();
            }
            else
            {
                if (computersWithFile.Contains(ip))
                {
                    computersWithFile.Remove(ip);
                    this.Dispatcher.Invoke((Action)(() =>
                    {
                        serversComputer.Items.Remove(ip);
                    }));
                }
            }
        }

        public void CreateListView(ListView lst, Grid wherePlaces, int numColumn, int numRow)
        {
            lst.HorizontalAlignment = HorizontalAlignment.Left;
            lst.VerticalAlignment = VerticalAlignment.Top;
            lst.Height = 150;
            lst.Width = 800;

            GridView myGridView = new GridView();
            myGridView.AllowsColumnReorder = true;

            GridViewColumn gvc1 = new GridViewColumn();
            gvc1.DisplayMemberBinding = new Binding("AttackerIP");
            gvc1.Header = "Attacker IP";
            gvc1.Width = 800 / 6;
            myGridView.Columns.Add(gvc1);
            GridViewColumn gvc2 = new GridViewColumn();
            gvc2.DisplayMemberBinding = new Binding("AttackerMac");
            gvc2.Header = "Attacker Mac";
            gvc2.Width = 800 / 6;
            myGridView.Columns.Add(gvc2);
            GridViewColumn gvc3 = new GridViewColumn();
            gvc3.DisplayMemberBinding = new Binding("VictimIP");
            gvc3.Header = "Victim IP";
            gvc3.Width = 800 / 6;
            myGridView.Columns.Add(gvc3);
            GridViewColumn gvc4 = new GridViewColumn();
            gvc4.DisplayMemberBinding = new Binding("VictimMac");
            gvc4.Header = "Victim Mac";
            gvc4.Width = 800 / 6;
            myGridView.Columns.Add(gvc4);

            GridViewColumn gvc5 = new GridViewColumn();
            gvc5.Header = "Deffense";
            gvc5.Width = 800 / 6;
            myGridView.Columns.Add(gvc5);

            DataTemplate template = new DataTemplate();
            FrameworkElementFactory factoryButton = new FrameworkElementFactory(typeof(Button));
            factoryButton.SetValue(Button.HorizontalAlignmentProperty, HorizontalAlignment.Right);
            factoryButton.SetBinding(Button.ToolTipProperty, new Binding("AttackerIP"));
            factoryButton.SetValue(Button.ContentProperty, "Start Def");
            factoryButton.AddHandler(Button.ClickEvent, new RoutedEventHandler(ButtonDifenseClicked));
            template.VisualTree = factoryButton;
            gvc5.CellTemplate = template;

            GridViewColumn gvc6 = new GridViewColumn();
            gvc6.DisplayMemberBinding = new Binding("Status");
            gvc6.Header = "Status";
            gvc6.Width = 800 / 6;
            myGridView.Columns.Add(gvc6);

            lst.View = myGridView;
            wherePlaces.Children.Add(lst);
            Grid.SetRow(lst, numRow);
            Grid.SetColumn(lst, numColumn);
        }
        private void AddItemToLIstView(NetworkProcess dataAttack, ListView lst)
        {
            GridView gv = lst.View as GridView;
            List<NetworkProcess> dataAttackList = new List<NetworkProcess>();
            for (int i = 0; i < lst.Items.Count; i++)
            {
                NetworkProcess data = (NetworkProcess)lst.Items[i];
                dataAttackList.Add(data);
            }
            dataAttackList.Add(dataAttack);
            lst.ItemsSource = dataAttackList;
            CollectionView vi = (CollectionView)CollectionViewSource.GetDefaultView(lst.ItemsSource);
            vi.SortDescriptions.Add(new SortDescription("AttackerIP", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("AttackerMac", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("VictimIP", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("VictimMac", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("Deffense", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("Status", ListSortDirection.Ascending));

            // Alert of a new one
            Thread grafity = new Thread(NewAlert);
            grafity.Start();

        }

        private void RemoveItemFromLIstView(NetworkProcess dataAttack, ListView lst)
        {
            // Delete NetworkProcess object from ListView
            List<NetworkProcess> dataAttackList = new List<NetworkProcess>();
            for (int i = 0; i < lst.Items.Count; i++)
            {
                NetworkProcess data = (NetworkProcess)lst.Items[i];
                if (!(data.AttackerIP.Equals(dataAttack.AttackerIP) && data.VictimIP.Equals(dataAttack.VictimIP)))
                {
                    dataAttackList.Add(data);
                }
            }
            lst.ItemsSource = dataAttackList;

            CollectionView vi = (CollectionView)CollectionViewSource.GetDefaultView(lst.ItemsSource);
            vi.SortDescriptions.Add(new SortDescription("AttackerIP", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("AttackerMac", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("VictimIP", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("VictimMac", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("Deffense", ListSortDirection.Ascending));
            vi.SortDescriptions.Add(new SortDescription("Status", ListSortDirection.Ascending));
        }
        private void NewComputerConected()
        {
            try
            {
                bool flag = false;
                this.Dispatcher.Invoke((Action)(() =>
                {
                    flag = tabSubject4.IsSelected;
                }));
                this.Dispatcher.Invoke((Action)(() =>
                {
                    if (!tabSubject4.IsSelected)
                        tabSubject4.Background = new SolidColorBrush(Colors.Orange);
                }));
                while (true)
                {
                    this.Dispatcher.Invoke((Action)(() =>
                    {
                        if (tabSubject4.IsSelected)
                        {
                            tabSubject4.Background = tabSubject1.Background;
                        }
                        flag = tabSubject4.IsSelected;
                    }));
                    if (flag)
                        break;
                }
            }
            catch { }
        }

        private void NewAlert()
        {
            try
            {
                bool flag = false;
                this.Dispatcher.Invoke((Action)(() =>
                {
                    flag = tabSubject3.IsSelected;
                }));
                this.Dispatcher.Invoke((Action)(() =>
                {
                    if (!tabSubject3.IsSelected)
                        tabSubject3.Background = new SolidColorBrush(Colors.Yellow);
                }));
                while (true)
                {
                    this.Dispatcher.Invoke((Action)(() =>
                    {
                        if (tabSubject3.IsSelected)
                        {
                            tabSubject3.Background = tabSubject1.Background;
                        }
                        flag = tabSubject3.IsSelected;
                    }));
                    if (flag)
                        break;
                }
            }
            catch { }
        }

        private void ButtonDifenseClicked(object sender, RoutedEventArgs e)
        {
            Button b = sender as Button;
            object attackerIP = b.ToolTip;
            ClientWork cwk = new ClientWork(attackerIP.ToString());
            cwk.Send("Process Defense");
            //bool lvi = discribeStatusAttacksAtNetwork.FindName("ip");
            //string secondCol = discribeStatusAttacksAtNetwork.SelectedItems[0].SubItems[1].Text;

            for (int i = 0; i < discribeStatusAttacksAtNetwork.Items.Count; i++)
            {
                NetworkProcess data = (NetworkProcess)discribeStatusAttacksAtNetwork.Items[i];
                if (data.AttackerIP != "")
                {
                    MessageBox.Show(attackerIP + "  is the attacker");

                }
                else
                    MessageBox.Show("NO Attacker");

                if (attackerIP.ToString().Equals(data.AttackerIP))
                {
                    RemoveItemFromLIstView(data, discribeStatusAttacksAtNetwork);
                    //send packet to the victm that change his GatewayMac     
                    data.SendDeffense(prop, selectedDevice);

                }
            }
        }

        public static void DisableConnection()
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())//get each network adapter 
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "cmd.exe";
                startInfo.Arguments = "/C netsh interface set interface name=\"" + adapter.Name + "\" admin=DISABLED";
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;

                Process.Start(startInfo);
            }
        }//create new process of netsh to disable the network adapter

        public static void Shutdown()
        {
            System.Diagnostics.Process.Start("shutdown", "/s /t 0");
        }
        public void StartCommands()
        {
            Commands(Console.ReadLine());
        }

        public void Commands(string c)
        {
            string un = Environment.UserDomainName;
            while (true)
            {
                if (c == "cmd" || c == "CMD")
                {
                    Console.WriteLine(un + ":/>Enter Password: ");
                    string p = Console.ReadLine();
                    if (p == this.pass)
                    {
                        StartCmd();
                        Console.WriteLine(un + ":/>Open cmd");
                    }
                    else
                        Console.WriteLine(un + ":/>Wrong password!");

                }
                else if (c == "DOS" || c == "dos")
                {
                    Console.WriteLine(un + ":/>Enter Password: ");
                    string p = Console.ReadLine();
                    if (p == this.pass)
                        SendDOS();
                    else
                        Console.WriteLine(un + ":/>Wrong password!");

                }
                else if (c == "color" || c == "Color" || c == "COLOR")
                {
                    Console.WriteLine(un + ":/>Change color (red/blue/green/yellow/white/reset)");
                    command = Console.ReadLine();
                    if (command == "red")
                        Console.ForegroundColor = ConsoleColor.Red;
                    else if (command == "blue")
                        Console.ForegroundColor = ConsoleColor.Blue;
                    else if (command == "green")
                        Console.ForegroundColor = ConsoleColor.DarkGreen;
                    else if (command == "yellow")
                        Console.ForegroundColor = ConsoleColor.Yellow;
                    else if (command == "white")
                        Console.ForegroundColor = ConsoleColor.White;
                    else if (command == "reset")
                        Console.ResetColor();
                    Console.WriteLine(un + ":/>It is what do you want?");
                }
                else if (c == "domain name")
                {
                    Console.WriteLine(un + ":/>User Domain Name is: " + Environment.UserDomainName);
                }
                else if (c == "user name")
                {
                    Console.WriteLine(un + ":/>User Name is: " + Environment.UserName);
                }
                else if (c == "os" || c == "OS" || c == "operation system")
                {
                    Console.WriteLine(un + ":/>Operation System Version: " + Environment.OSVersion.VersionString.ToString());
                }
                else if (c == "time")
                {
                    const string dataFmt = "{0,-30}{1}";
                    const string timeFmt = "{0,-30}{1:yyyy-MM-dd HH:mm}";

                    // Get the local time zone and the current local time and year.
                    TimeZone localZone = TimeZone.CurrentTimeZone;
                    DateTime currentDate = DateTime.Now;

                    // Display the current date and time and show if they occur 
                    // in daylight saving time.
                    Console.WriteLine("\n" + timeFmt, "Current date and time:", currentDate);
                    Console.WriteLine(dataFmt, "Daylight saving time?", localZone.IsDaylightSavingTime(currentDate));

                    DateTime currentUTC = localZone.ToUniversalTime(currentDate);
                    TimeSpan currentOffset = localZone.GetUtcOffset(currentDate);

                    Console.WriteLine(timeFmt, "Coordinated Universal Time:", currentUTC);
                    Console.WriteLine(dataFmt, "UTC offset:", currentOffset);

                }
                else if (c == "forget password" || c == "forget pass" || c == "bf" || c == "BF")
                {
                    BruteForce(this.pass);
                }
                else if (c == "new pass" || c == "set pass")
                {
                    Console.WriteLine(un + ":/>Enter old password: ");
                    string s = Console.ReadLine();
                    if (s == this.pass)
                    {
                        Console.WriteLine(un + ":/>Enter new password.");
                        this.pass = Console.ReadLine();
                        while (this.pass.Length != 4)
                        {
                            Console.WriteLine(un + ":/>Password Lenth should be 4 chars! \n Please try again: ");
                            this.pass = Console.ReadLine();
                        }
                        Console.WriteLine(un + ":/>Your password had changed.");
                    }

                }
                else if (c == "end")
                {
                    Console.ForegroundColor = ConsoleColor.DarkRed;
                    Console.WriteLine(un + ":/>Stop to write...");
                    break;
                }
                else if (c == "exit")
                    Environment.Exit(Environment.ExitCode);
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(un + ":/>There is no command like this!");
                    Console.WriteLine(un + ":/>Try one of this: cmd/dos/color/domain name/user name/time/OS/new pass/forget pass/end/exit");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                }

                c = Console.ReadLine();
            }
        }
        public static void BruteForce(string bf)
        {
            string s = "";
            string[] arr = new string[36];
            CreateTable(arr);

            int first = 0;
            int sec = 0;
            int third = 0;
            int fourth = 0;

            while (s != bf)
            {
                if (first == 36)
                {
                    sec++;
                    first = 0;
                }
                if (sec == 36)
                {
                    third++;
                    sec = 0;
                }
                if (third == 36)
                {
                    fourth++;
                    third = 0;
                }
                if (fourth == 36)
                {
                    break;
                }
                Console.WriteLine(s);
                s = arr[first] + arr[sec] + arr[third] + arr[fourth];
                first++;
            }
            Console.WriteLine("The password is: " + s);
        }
        private static void CreateTable(string[] arr)//Build table
        {
            int j = 97;
            for (int i = 0; i < arr.Length; i++)// Ascii table
            {
                arr[i] = "" + (char)j;
                j++;
            }
            j = 48;
            for (int i = 26; i < arr.Length; i++)
            {
                arr[i] = "" + (char)j;
                j++;
            }
        }

    }
}
