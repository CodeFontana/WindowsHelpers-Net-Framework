using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WindowsLibrary
{
    public class PageFile
    {
        public string Name { get; set; }
        public string DriveLetter { get; set; }
        public string Comment { get; set; }
        public bool AutomaticManagement { get; set; }
        public int InitialSize { get; set; }
        public int MaximumSize { get; set; }
        public int AllocatedBaseSize { get; set; }
        public int CurrentUsage { get; set; }
        public int PeakUsage { get; set; }
        public long AvailableSpace { get; set; }
    }
}