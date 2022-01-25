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

namespace ScannerWPF
{
    class ControlBuilder
    {
        public void CreateButton(Button button, Grid wherePlaces, int numColumn, int numRow, HorizontalAlignment horizontal, VerticalAlignment vertical)
        {
            button.HorizontalAlignment = horizontal;
            button.VerticalAlignment = vertical;

            wherePlaces.Children.Add(button);
            Grid.SetRow(button, numRow);
            Grid.SetColumn(button, numColumn);
        }

        public void CreateLabel(Label lable, Grid wherePlaces, string content, int numColumn, int numRow)
        {
            lable = new Label();
            lable.HorizontalAlignment = HorizontalAlignment.Left;
            lable.VerticalAlignment = VerticalAlignment.Top;
            lable.Content = content;

            wherePlaces.Children.Add(lable);
            Grid.SetRow(lable, numRow);
            Grid.SetColumn(lable, numColumn);
        }

        public void CreateLittleGrid(Grid grid, int columns, int rows)
        {
            // Create Main Grid:
            grid.HorizontalAlignment = HorizontalAlignment.Left;
            grid.VerticalAlignment = VerticalAlignment.Top;

            // Create Columns
            for (int i = 0; i < columns; i++)
            {
                grid.ColumnDefinitions.Add(new ColumnDefinition());
            }

            // Create Rows
            for (int i = 0; i < rows; i++)
            {
                grid.RowDefinitions.Add(new RowDefinition());
            }

        }

        public void CreateListBox(ListBox lst, Grid wherePlaces, int numColumn, int numRow, double height, double width)
        {
            lst.HorizontalAlignment = HorizontalAlignment.Left;
            lst.VerticalAlignment = VerticalAlignment.Top;
            lst.Height = height;
            lst.Width = width;
            wherePlaces.Children.Add(lst);
            Grid.SetRow(lst, numRow);
            Grid.SetColumn(lst, numColumn);
        }

        public void AddObjectToLIstBox(object item, ListBox lst)
        {
            lst.Items.Add(item);
        }

    }
}
