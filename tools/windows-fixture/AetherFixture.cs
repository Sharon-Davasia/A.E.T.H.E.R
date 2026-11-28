// AETHER native synthetic fixture (G05) - Windows Forms, synthetic data only.
// Built reproducibly with the in-box .NET Framework compiler; see
// build_fixture.cmd. Control contract (AutomationIds are the WinForms
// control names surfaced via UIA): status=101, increment=102,
// disabled=103, password=104, modal=105, replace=106, reset=107,
// delay-toggle=108. No network, no elevation, no real user data.
using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AetherFixture
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new FixtureForm());
        }
    }

    internal sealed class FixtureForm : Form
    {
        private int _count;
        private bool _delayNext;
        private readonly Label _status;
        private Button _increment;

        internal FixtureForm()
        {
            Text = "AETHER Fixture";
            ClientSize = new Size(420, 300);
            _status = new Label { Name = "101", Text = "Count: 0", Location = new Point(20, 15), Size = new Size(360, 25) };
            _increment = MakeButton("102", "Increment", 55);
            _increment.Click += async (sender, args) =>
            {
                if (_delayNext) { _delayNext = false; await Task.Delay(10000); }
                _count += 1;
                _status.Text = "Count: " + _count;
            };
            var disabled = MakeButton("103", "Disabled", 95);
            disabled.Enabled = false;
            var password = new TextBox { Name = "104", UseSystemPasswordChar = true, Location = new Point(20, 135), Size = new Size(200, 25) };
            var modal = MakeButton("105", "Open dialog", 175);
            modal.Click += (sender, args) =>
                MessageBox.Show(this, "AETHER fixture modal dialog", "AETHER Fixture", MessageBoxButtons.OK, MessageBoxIcon.Information);
            var replace = MakeButton("106", "Replace increment", 215);
            replace.Click += (sender, args) =>
            {
                var location = _increment.Location;
                Controls.Remove(_increment);
                _increment.Dispose();
                _increment = MakeButton("102", "Increment", location.Y);
                _increment.Click += (s2, a2) => { _count += 1; _status.Text = "Count: " + _count; };
                Controls.Add(_increment);
            };
            var reset = MakeButton("107", "Reset", 255);
            reset.Click += (sender, args) => { _count = 0; _status.Text = "Count: 0"; };
            var delay = new CheckBox { Name = "108", Text = "Delay next increment (10s)", Location = new Point(240, 255), Size = new Size(170, 25) };
            delay.CheckedChanged += (sender, args) => { _delayNext = delay.Checked; };
            Controls.AddRange(new Control[] { _status, _increment, disabled, password, modal, replace, reset, delay });
        }

        private Button MakeButton(string name, string text, int y)
        {
            return new Button { Name = name, Text = text, Location = new Point(20, y), Size = new Size(200, 30) };
        }
    }
}
