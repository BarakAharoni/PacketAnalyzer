using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace ScannerWPF
{
    class CheckedListBox
    {
        private int checkedCount;
        private List<string> positionItems; // Checked or Not;
        private List<CheckBox> checkedItems;
        private CheckBox[] items;

        public CheckedListBox(CheckBox[] items)
        {
            this.items = items;
            SetData();
            
        }

        public int CheckedCount
        {
            get { return this.checkedCount; }
        }

        public List<string> PositionItems
        {
            get { return this.positionItems; }
        }

        public List<CheckBox> CheckedItems
        {
            get { return this.checkedItems; }
        }

        public string GetContent(int index)
        {
            return items[index].Content.ToString();
        }

        public void SetData()
        {
            checkedCount = 0;
            checkedItems = new List<CheckBox>();
            positionItems = new List<string>();
            foreach (CheckBox ch in items)
            {
                if (ch.IsChecked.ToString().Equals("True"))
                {
                    checkedItems.Add(ch);
                    checkedCount++;
                }
                this.positionItems.Add(ch.IsChecked.ToString());
            }
        }
    
    }
}
