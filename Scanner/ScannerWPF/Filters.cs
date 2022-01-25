using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace ScannerWPF
{
    class Filters
    {
        private Dictionary<string, string> dictionary;
        private ComboBox combo;
        private TextBox value;

        public Filters(ComboBox combo, TextBox value)
        {
            this.combo = combo;
            combo.SelectionChanged += combo_SelectionChanged;
            this.value = value;

            SetDictionary();
            AddFiltersToCombo();
        }

        void combo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            value.Clear();
            if (this.combo.SelectedIndex >= 0)
            {
                string filterKey = this.combo.SelectedItem.ToString();

                if (dictionary[filterKey].Equals("X")) // true - need add value in the textbox
                {
                    value.Visibility = Visibility.Visible;
                }
                else
                {
                    value.Visibility = Visibility.Hidden;
                }
            }
        }

        public string GetFilter()
        {
            string str = "";
            if (this.combo.SelectedIndex >= 0)
            {
                string filterKey = combo.SelectedItem.ToString();
                string filterValue = dictionary[filterKey];

                if (filterValue.Equals("X"))
                {
                    str = filterKey + " " + value.Text.ToString();
                }
                else
                {
                    str = filterValue;
                }
            }
            else
            {
                MessageBox.Show("no filter");
            }
            MessageBox.Show(str);
            return str;
        }

        private void AddFiltersToCombo()
        {
            foreach (string name in dictionary.Keys)
                this.combo.Items.Add(name);
        }

        private void SetDictionary()
        {
            dictionary = new Dictionary<string, string>();
            dictionary.Add("All Packets", "");
            dictionary.Add("tcp", "tcp");
            dictionary.Add("udp", "udp");
            dictionary.Add("arp", "arp");
            dictionary.Add("http", "tcp port 80");
            dictionary.Add("dns", "udp port 53");
            dictionary.Add("tcp port", "X");
            dictionary.Add("udp port", "X");
            dictionary.Add("http method == POST", "tcp dst port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354)");
            dictionary.Add("http method == GET", "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 ");
            dictionary.Add("ip host", "X"); // IP Addr
            dictionary.Add("ip src", "X");
            dictionary.Add("ip dst", "X");
            dictionary.Add("ether host", "X"); //ether Addr
            dictionary.Add("ether src", "X");
            dictionary.Add("ether dst", "X");
        }
    }
}

