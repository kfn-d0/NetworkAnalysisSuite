using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using DnsClient;
using Newtonsoft.Json;

namespace NetworkAnalysisSuite
{
    #region API Data Models
    public class IpApiInfo
    {
        [JsonProperty("query")]
        public string Query { get; set; }
        [JsonProperty("status")]
        public string Status { get; set; }
        [JsonProperty("country")]
        public string Country { get; set; }
        [JsonProperty("city")]
        public string City { get; set; }
        [JsonProperty("as")]
        public string Asn { get; set; }
    }

    public class IpInfoIo
    {
        [JsonProperty("ip")]
        public string Ip { get; set; }
        [JsonProperty("city")]
        public string City { get; set; }
        [JsonProperty("country")]
        public string Country { get; set; }
        [JsonProperty("org")] // ipinfo.io
        public string AsnOrg { get; set; }
    }
    #endregion

    public static class HistoryService
    {
        private static string FilePath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetworkAnalysisSuite", "history.json");

        public static List<string> Load()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    var json = File.ReadAllText(FilePath);
                    return JsonConvert.DeserializeObject<List<string>>(json) ?? new List<string>();
                }
            }
            catch { }
            return new List<string>();
        }

        public static void Save(string host)
        {
            try
            {
                var history = Load();
                history.RemoveAll(h => h.Equals(host, StringComparison.OrdinalIgnoreCase));
                history.Insert(0, host);
                if (history.Count > 20) history = history.Take(20).ToList();

                var dir = Path.GetDirectoryName(FilePath);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);

                File.WriteAllText(FilePath, JsonConvert.SerializeObject(history));
            }
            catch { }
        }
    }

    public class HopInfo
    {
        public int HopNumber { get; set; }
        public string IPAddress { get; set; } = string.Empty;
        public string Hostname { get; set; } = string.Empty;
        public bool IsResolvingHostname { get; set; } = false;
        public int TotalSent { get; set; }
        public int PacketsLost { get; set; }
        public int LastPing { get; set; }
        public int BestPing { get; set; } = -1;
        public int WorstPing { get; set; }
        public double Jitter { get; set; }
        public List<int> PingTimes { get; set; } = new List<int>();
        public IPAddress AddressToPing { get; set; }
        public int WarmupPingsSent { get; set; } = 0;
        public string NetworkType { get; set; } = string.Empty;
        public string AsnInfo { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public bool IsFetchingGeoInfo { get; set; } = false;
    }

    public partial class MainForm : Form
    {
        private static readonly HttpClient httpClient = new HttpClient();
        private SplitContainer splitContainer;
        private DataGridView dgvResults;
        private RichTextBox rtbPathPing;
        private RichTextBox rtbDiagnosis;
        private GroupBox grpDiagnosis;
        private ComboBox cboHost;
        private Button btnStart, btnStop, btnClear, btnAbout;
        private Label lblStatus, lblHost;
        private GroupBox grpOptions;
        private NumericUpDown numInterval, numPacketSize;
        private Label lblInterval, lblPacketSize;
        private CheckBox chkResolveNames;
        private ComboBox cmbDnsServer, cmbIpPreference;
        private Label lblDnsServer, lblIpPreference;
        private ToolTip toolTip;
        private System.Windows.Forms.Timer updateTimer;
        private CancellationTokenSource cancellationTokenSource;
        private readonly Dictionary<int, HopInfo> hops = new Dictionary<int, HopInfo>();
        private bool isRunning = false;
        private bool isAnalyzingPath = false;
        private string targetHostForDisplay = string.Empty;

        private string userAsnInfo = "ASN Local";

        private const int WARMUP_PING_COUNT = 10;
        private const int PATHPING_PACKET_COUNT = 50;

        public MainForm()
        {
            InitializeComponent();
            updateTimer = new System.Windows.Forms.Timer { Interval = 500 };
            updateTimer.Tick += UpdateUiTimer_Tick;
        }

        #region Component Initialization
        private void InitializeComponent()
        {
            this.toolTip = new System.Windows.Forms.ToolTip();
            this.splitContainer = new System.Windows.Forms.SplitContainer();
            this.dgvResults = new System.Windows.Forms.DataGridView();
            this.rtbPathPing = new System.Windows.Forms.RichTextBox();
            this.rtbDiagnosis = new System.Windows.Forms.RichTextBox();
            this.grpDiagnosis = new System.Windows.Forms.GroupBox();
            this.chkResolveNames = new System.Windows.Forms.CheckBox();
            this.cmbDnsServer = new System.Windows.Forms.ComboBox();
            this.lblDnsServer = new System.Windows.Forms.Label();

            ((System.ComponentModel.ISupportInitialize)(this.splitContainer)).BeginInit();
            this.splitContainer.Panel1.SuspendLayout();
            this.splitContainer.Panel2.SuspendLayout();
            this.splitContainer.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dgvResults)).BeginInit();
            this.SuspendLayout();

            this.Text = "Network Analysis Suite - MTRoute";
            this.Size = new Size(1400, 800);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MinimumSize = new Size(1100, 600);
            this.Font = new Font("Segoe UI", 9F);

            lblHost = new Label { Text = "Host:", Location = new Point(12, 15), Size = new Size(40, 23), TextAlign = ContentAlignment.MiddleLeft };
            
            cboHost = new ComboBox { Location = new Point(55, 12), Size = new Size(180, 23), DropDownStyle = ComboBoxStyle.DropDown };
            try {
                var history = HistoryService.Load();
                cboHost.Items.AddRange(history.ToArray());
                if (history.Count > 0) cboHost.Text = history[0];
                else cboHost.Text = "google.com";
            } catch { cboHost.Text = "google.com"; }

            btnStart = new Button { Text = "Iniciar Análise", Location = new Point(250, 10), Size = new Size(90, 27), BackColor = Color.FromArgb(192, 255, 192) };
            btnStart.Click += BtnStart_Click;
            toolTip.SetToolTip(btnStart, "Inicia o monitoramento contínuo (MTR) e a análise da rota (PathPing).");
            
            btnStop = new Button { Text = "Parar", Location = new Point(350, 10), Size = new Size(90, 27), BackColor = Color.FromArgb(255, 192, 192), Enabled = false };
            btnStop.Click += BtnStop_Click;
            
            btnClear = new Button { Text = "Limpar", Location = new Point(450, 10), Size = new Size(90, 27), BackColor = Color.FromArgb(192, 224, 255) };
            btnClear.Click += BtnClear_Click;
            
            btnAbout = new Button { Text = "Sobre", Location = new Point(550, 10), Size = new Size(90, 27) };
            btnAbout.Click += BtnAbout_Click;
            
            grpOptions = new GroupBox { Text = "Opções de Análise", Location = new Point(12, 45), Size = new Size(950, 55) };
            lblInterval = new Label { Text = "Intervalo (ms):", Location = new Point(10, 22), Size = new Size(90, 20) };
            numInterval = new NumericUpDown { Location = new Point(100, 20), Size = new Size(70, 23), Minimum = 100, Maximum = 10000, Value = 500, Increment = 50 };
            lblPacketSize = new Label { Text = "Tam. Pacote:", Location = new Point(180, 22), Size = new Size(80, 20) };
            numPacketSize = new NumericUpDown { Location = new Point(265, 20), Size = new Size(70, 23), Minimum = 1, Maximum = 65500, Value = 32 };
            
            chkResolveNames = new CheckBox { Text = "Resolver Nomes", Checked = true, Location = new Point(350, 22), AutoSize = true };
            lblDnsServer = new Label { Text = "Servidor DNS:", Location = new Point(480, 22), Size = new Size(80, 20) };
            cmbDnsServer = new ComboBox { Location = new Point(565, 20), Size = new Size(150, 23), DropDownStyle = ComboBoxStyle.DropDownList };
            cmbDnsServer.Items.AddRange(new object[] { "Padrão do Sistema", "Google (8.8.8.8)", "Cloudflare (1.1.1.1)", "OpenDNS (208.67.222.222)" });
            cmbDnsServer.SelectedIndex = 0;

            lblIpPreference = new Label { Text = "Protocolo:", Location = new Point(730, 22), Size = new Size(70, 20) };
            cmbIpPreference = new ComboBox { Location = new Point(800, 20), Size = new Size(120, 23), DropDownStyle = ComboBoxStyle.DropDownList };
            cmbIpPreference.Items.AddRange(new object[] { "Priorizar IPv4", "Priorizar IPv6" });
            cmbIpPreference.SelectedIndex = 0;

            grpOptions.Controls.AddRange(new Control[] { lblInterval, numInterval, lblPacketSize, numPacketSize, chkResolveNames, lblDnsServer, cmbDnsServer, lblIpPreference, cmbIpPreference });

            lblStatus = new Label { Text = "Pronto", Location = new Point(970, 60), Font = new Font("Segoe UI", 9F, FontStyle.Bold), ForeColor = Color.DarkBlue, AutoSize = true };

            splitContainer.Location = new Point(12, 110);
            splitContainer.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            splitContainer.Size = new Size(this.ClientSize.Width - 24, this.ClientSize.Height - 122);
            splitContainer.SplitterDistance = (int)(this.ClientSize.Width * 0.65);
            splitContainer.IsSplitterFixed = true;

            grpDiagnosis.Text = "Diagnóstico";
            grpDiagnosis.Dock = DockStyle.Bottom;
            grpDiagnosis.Height = 130;
            rtbDiagnosis.Dock = DockStyle.Fill;
            rtbDiagnosis.ReadOnly = true;
            rtbDiagnosis.BackColor = Color.FromArgb(245, 245, 245);
            rtbDiagnosis.Font = new Font("Segoe UI", 9.5F);
            rtbDiagnosis.Text = "Aguardando dados para iniciar o diagnóstico...";
            grpDiagnosis.Controls.Add(rtbDiagnosis);

            dgvResults.Dock = DockStyle.Fill;
            dgvResults.ReadOnly = true;
            dgvResults.AllowUserToAddRows = false;
            dgvResults.RowHeadersVisible = false;
            dgvResults.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(240, 248, 255) };
            
            var contextMenu = new ContextMenuStrip();
            var copyIpItem = new ToolStripMenuItem("Copiar IP");
            copyIpItem.Click += (s, e) => CopyIpToClipboard();
            contextMenu.Items.Add(copyIpItem);
            dgvResults.ContextMenuStrip = contextMenu;
            dgvResults.CellMouseDown += DgvResults_CellMouseDown;

            dgvResults.Columns.AddRange(new DataGridViewColumn[] {
                new DataGridViewTextBoxColumn { Name = "Hop", HeaderText = "#", Width = 35 },
                new DataGridViewTextBoxColumn { Name = "Hostname", HeaderText = "IP [Hostname]", Width = 220 },
                new DataGridViewTextBoxColumn { Name = "Asn", HeaderText = "ASN / Provedor", Width = 220 },
                new DataGridViewTextBoxColumn { Name = "Location", HeaderText = "Localização", Width = 150 },
                new DataGridViewTextBoxColumn { Name = "Loss", HeaderText = "Perda %", Width = 60 },
                new DataGridViewTextBoxColumn { Name = "Sent", HeaderText = "Enviados", Width = 60 },
                new DataGridViewTextBoxColumn { Name = "Last", HeaderText = "Último", Width = 60 },
                new DataGridViewTextBoxColumn { Name = "Avg", HeaderText = "Média", Width = 60 },
                new DataGridViewTextBoxColumn { Name = "Best", HeaderText = "Melhor", Width = 60 },
                new DataGridViewTextBoxColumn { Name = "Worst", HeaderText = "Pior", Width = 60 },
                new DataGridViewTextBoxColumn { Name = "Jitter", HeaderText = "Jitter", Width = 60 }
            });
            dgvResults.Columns["Hostname"].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            dgvResults.Columns["Asn"].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

            foreach (DataGridViewColumn col in dgvResults.Columns)
            {
                col.SortMode = DataGridViewColumnSortMode.NotSortable;
                if (col.Name != "Hostname" && col.Name != "Asn" && col.Name != "Location") 
                    col.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleCenter;
                col.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleCenter;
            }

            rtbPathPing.Dock = DockStyle.Fill;
            rtbPathPing.ReadOnly = true;
            rtbPathPing.BackColor = Color.Black;
            rtbPathPing.ForeColor = Color.WhiteSmoke;
            rtbPathPing.Font = new Font("Consolas", 10F);
            rtbPathPing.Text = "O relatório da Análise de Rota (PathPing) aparecerá aqui...";

            this.Controls.AddRange(new Control[] { lblHost, cboHost, btnStart, btnStop, btnClear, btnAbout, grpOptions, lblStatus, splitContainer });
            this.splitContainer.Panel1.Controls.Add(this.dgvResults);
            this.splitContainer.Panel1.Controls.Add(this.grpDiagnosis);
            this.splitContainer.Panel2.Controls.Add(this.rtbPathPing);

            ((System.ComponentModel.ISupportInitialize)(this.splitContainer)).EndInit();
            this.splitContainer.Panel1.ResumeLayout(false);
            this.splitContainer.Panel2.ResumeLayout(false);
            this.splitContainer.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.dgvResults)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();
        }
        #endregion

        #region UI Event Handlers
        private async void BtnStart_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(cboHost.Text)) { MessageBox.Show("Digite um host.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }

            targetHostForDisplay = cboHost.Text.Trim();
            
            try 
            {
                HistoryService.Save(targetHostForDisplay);
                var history = HistoryService.Load();
                cboHost.Items.Clear();
                cboHost.Items.AddRange(history.ToArray());
                cboHost.Text = targetHostForDisplay;
            } catch {}

            isRunning = true;
            isAnalyzingPath = true;
            SetUiState();
            
            await FetchUserPublicInfoAsync();
            
            UpdateStatus($"Resolvendo {targetHostForDisplay}...", Color.DarkBlue);
            
            var targetIp = await ResolveHostWithCustomDnsAsync(targetHostForDisplay);
            if(targetIp == null)
            {
                UpdateStatus($"Falha ao resolver o host: {targetHostForDisplay}", Color.Red);
                isRunning = false;
                isAnalyzingPath = false;
                SetUiState();
                return;
            }
            
            cancellationTokenSource = new CancellationTokenSource();
            ClearResults();
            updateTimer.Start();

            UpdateStatus($"Fase 1/3: Descobrindo rota para {targetHostForDisplay} [{targetIp}]...", Color.DarkBlue);

            var discoveredHops = await DiscoverRouteAsync(targetIp, cancellationTokenSource.Token);

            if (cancellationTokenSource.IsCancellationRequested || discoveredHops == null || discoveredHops.Count == 0)
            {
                StopTraceroute();
                UpdateStatus("Falha ao descobrir a rota.", Color.Red);
                return;
            }

            Task mtrTask = StartTraceAndMonitor(discoveredHops, cancellationTokenSource.Token);
            Task pathPingTask = StartPathAnalysis(discoveredHops, cancellationTokenSource.Token);

            _ = Task.Run(async () =>
            {
                await Task.WhenAll(mtrTask, pathPingTask);
                isAnalyzingPath = false;
            });
        }

        private void BtnStop_Click(object sender, EventArgs e) => StopTraceroute();
        private void BtnClear_Click(object sender, EventArgs e) => ClearResults();
        
        private void BtnAbout_Click(object sender, EventArgs e)
        {
            using (var aboutForm = new AboutForm())
            {
                aboutForm.ShowDialog(this);
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e) { if (isRunning) StopTraceroute(); base.OnFormClosing(e); }
        #endregion

        #region Core MTR & PathPing Logic
        private async Task StartTraceAndMonitor(List<HopInfo> discoveredHops, CancellationToken token)
        {
            this.Invoke(new Action(() =>
            {
                foreach (var hop in discoveredHops.OrderBy(h => h.HopNumber))
                {
                    int rowIndex = dgvResults.Rows.Add();
                    var row = dgvResults.Rows[rowIndex];
                    row.Cells["Hop"].Value = hop.HopNumber;
                    row.Cells["Hostname"].Value = hop.IPAddress;
                    row.Cells["Asn"].Value = hop.AsnInfo;
                    row.Cells["Location"].Value = hop.Location;
                    row.Cells["Loss"].Value = "N/A";
                }
            }));

            string statusMessage = $"Fase 2/3: Monitorando {discoveredHops.Count} saltos. (Aguardando {WARMUP_PING_COUNT} pings de aquecimento)";
            UpdateStatus(statusMessage, Color.DarkGreen);

            await StartConcurrentMonitoring(discoveredHops, token);
        }

        private Task StartConcurrentMonitoring(List<HopInfo> discoveredHops, CancellationToken token)
        {
            return Task.Run(async () =>
            {
                var pingOptions = new PingOptions(128, true);
                var packetBuffer = new byte[(int)numPacketSize.Value];
                while (!token.IsCancellationRequested)
                {
                    var pingTasks = new List<Task>();
                    foreach (var hop in discoveredHops.Where(h => h.AddressToPing != null))
                    {
                        pingTasks.Add(Task.Run(async () =>
                        {
                            PingReply reply = null;
                            try
                            {
                                using (var pinger = new Ping()) reply = await pinger.SendPingAsync(hop.AddressToPing, 2000, packetBuffer, pingOptions);
                            }
                            catch { }
                            UpdateHopStats(hop, reply);
                        }, token));
                    }
                    await Task.WhenAll(pingTasks);
                    await Task.Delay((int)numInterval.Value, token);
                }
            }, token);
        }

        private void UpdateHopStats(HopInfo hop, PingReply reply)
        {
            lock (hop)
            {
                hop.WarmupPingsSent++;
                if (hop.WarmupPingsSent <= WARMUP_PING_COUNT)
                {
                    if (hop.WarmupPingsSent == WARMUP_PING_COUNT && !isAnalyzingPath) UpdateStatus($"Monitorando {hops.Count} saltos...", Color.DarkGreen);
                    return;
                }
                hop.TotalSent++;
                if (reply != null && reply.Status == IPStatus.Success)
                {
                    int rtt = (int)reply.RoundtripTime;
                    hop.LastPing = rtt;
                    hop.PingTimes.Add(rtt);
                    if (hop.PingTimes.Count > 50) hop.PingTimes.RemoveAt(0);
                    if (hop.BestPing == -1 || rtt < hop.BestPing) hop.BestPing = rtt;
                    if (rtt > hop.WorstPing) hop.WorstPing = rtt;
                    if (hop.PingTimes.Count > 1)
                    {
                        var validPings = hop.PingTimes.Where(p => p >= 0);
                        if (validPings.Any())
                        {
                            double avg = validPings.Average();
                            hop.Jitter = Math.Sqrt(validPings.Sum(t => Math.Pow(t - avg, 2)) / validPings.Count());
                        }
                    }
                }
                else
                {
                    hop.PacketsLost++;
                    hop.LastPing = -1;
                    hop.PingTimes.Add(-1);
                    if (hop.PingTimes.Count > 50) hop.PingTimes.RemoveAt(0);
                }
            }
        }
        
        private async Task StartPathAnalysis(List<HopInfo> discoveredHops, CancellationToken token)
        {
            UpdateStatus($"Fase 3/3: Analisando rota para {targetHostForDisplay}...", Color.Purple);
            rtbPathPing.Clear();

            var results = new Dictionary<int, List<long>>();
            var sb = new StringBuilder();
            sb.AppendLine($"Rastreando a rota para {targetHostForDisplay} [{discoveredHops.LastOrDefault()?.IPAddress ?? "N/A"}]");
            sb.AppendLine($"com um máximo de {discoveredHops.Count} saltos:\n");

            foreach (var hop in discoveredHops)
            {
                string name = chkResolveNames.Checked && !string.IsNullOrEmpty(hop.Hostname) ? hop.Hostname : hop.IPAddress;
                sb.AppendLine($"{hop.HopNumber,3}  {name}");
            }
            rtbPathPing.Text = sb.ToString();

            sb.AppendLine($"\nProcessando estatísticas para {discoveredHops.Count} saltos:");
            for (int i = 0; i < discoveredHops.Count; i++)
            {
                if (token.IsCancellationRequested) return;

                var hop = discoveredHops[i];
                results[i] = new List<long>();
                UpdateStatus($"Análise: Enviando pings para o salto {i + 1}/{discoveredHops.Count} ({hop.IPAddress})...", Color.Purple);

                if (hop.AddressToPing != null)
                {
                    using (var pinger = new Ping())
                    {
                        for (int j = 0; j < PATHPING_PACKET_COUNT; j++)
                        {
                            if (token.IsCancellationRequested) return;
                            try
                            {
                                var reply = await pinger.SendPingAsync(hop.AddressToPing, 1000);
                                results[i].Add(reply.Status == IPStatus.Success ? reply.RoundtripTime : -1);
                            }
                            catch { results[i].Add(-1); }
                        }
                    }
                }

                sb.Append(".");
                rtbPathPing.Text = sb.ToString();
                rtbPathPing.ScrollToCaret();
            }

            UpdateStatus("Análise: Calculando e formatando resultados...", Color.Purple);
            await Task.Delay(500, token);

            sb.AppendLine("\n\nEstatísticas de rota de origem para nó:");
            sb.AppendLine("Salto  RTT   Perdido/Enviado = %   Endereço");
            sb.AppendLine("                             ... ");

            for (int i = 0; i < discoveredHops.Count; i++)
            {
                var hop = discoveredHops[i];
                var hopPings = results.ContainsKey(i) ? results[i] : new List<long>();

                int lost = hopPings.Count(p => p == -1);
                var validPings = hopPings.Where(p => p >= 0).ToList();
                long avgRtt = validPings.Any() ? (long)validPings.Average() : 0;

                string lossStr = $"{lost}/{PATHPING_PACKET_COUNT} = {(lost * 100 / PATHPING_PACKET_COUNT)}%";
                string addressStr = chkResolveNames.Checked && !string.IsNullOrEmpty(hop.Hostname) && hop.Hostname != hop.IPAddress
                    ? $"{hop.Hostname} [{hop.IPAddress}]" 
                    : hop.IPAddress;

                sb.AppendLine($"{i + 1,3}   {avgRtt,3}ms  {lossStr,-21} {addressStr}");
            }

            sb.AppendLine("\nAnálise completa.");
            rtbPathPing.Text = sb.ToString();
            if (!isRunning) UpdateStatus("Análise de rota concluída.", Color.DarkGreen);
        }
        #endregion

        #region Automatic Diagnosis
        private void AnalyzeNetworkHealth()
        {
            var findings = new List<Tuple<string, Color, bool>>();
            List<HopInfo> currentHops;
            lock (hops)
            {
                currentHops = hops.Values.OrderBy(h => h.HopNumber).ToList();
            }

            if (currentHops.Count == 0 || currentHops.All(h => h.TotalSent == 0))
            {
                findings.Add(Tuple.Create("Aguardando mais dados para uma análise precisa...", Color.Black, false));
                UpdateDiagnosisUI(findings);
                return;
            }

            var lastHop = currentHops.LastOrDefault(h => h.AddressToPing != null);
            if (lastHop == null) return;

            var firstHop = currentHops.FirstOrDefault();
            if (firstHop != null && firstHop.TotalSent > 5)
            {
                double firstHopLoss = (double)firstHop.PacketsLost / firstHop.TotalSent * 100;
                if (firstHopLoss > 2.0)
                {
                    findings.Add(Tuple.Create("ALERTA: Perda de pacotes significativa no primeiro salto (seu roteador).", Color.DarkRed, true));
                    findings.Add(Tuple.Create("Isso indica um problema na sua rede local. Verifique seu cabo de rede, conexão Wi-Fi ou o próprio roteador.", Color.Black, false));
                }
                if (firstHop.BestPing > 20)
                {
                    findings.Add(Tuple.Create("AVISO: Latência alta para o seu roteador.", Color.DarkOrange, true));
                    findings.Add(Tuple.Create("A comunicação na rede local está lenta. Isso pode ser causado por interferência no Wi-Fi ou um roteador sobrecarregado.", Color.Black, false));
                }
            }

            double previousLoss = 0.0;
            HopInfo problematicHop = null;
            foreach (var hop in currentHops.Where(h => h.TotalSent > 5))
            {
                double currentLoss = (double)hop.PacketsLost / hop.TotalSent * 100;
                if (currentLoss > previousLoss + 5 && hop != lastHop)
                {
                    var subsequentHops = currentHops.Where(h => h.HopNumber > hop.HopNumber && h.TotalSent > 0);
                    if (subsequentHops.Any() && subsequentHops.Average(h => (double)h.PacketsLost / h.TotalSent * 100) >= currentLoss - 5)
                    {
                        problematicHop = hop;
                        break;
                    }
                }
                previousLoss = currentLoss;
            }
            if (problematicHop != null)
            {
                string name = chkResolveNames.Checked && !string.IsNullOrEmpty(problematicHop.Hostname) ? problematicHop.Hostname : problematicHop.IPAddress;
                findings.Add(Tuple.Create($"ALERTA: A perda de pacotes parece começar no salto {problematicHop.HopNumber} ({name}).", Color.DarkRed, true));
                findings.Add(Tuple.Create($"Este nó pertence a '{problematicHop.AsnInfo}' e está provavelmente em '{problematicHop.Location}'. O problema pode ser com este provedor.", Color.Black, false));
            }

            double lastHopLoss = (double)lastHop.PacketsLost / lastHop.TotalSent * 100;
            var hopBeforeLast = currentHops.LastOrDefault(h => h.HopNumber == lastHop.HopNumber - 1 && h.TotalSent > 0);
            if (hopBeforeLast != null)
            {
                double lossBeforeLast = (double)hopBeforeLast.PacketsLost / hopBeforeLast.TotalSent * 100;
                if (lastHopLoss > lossBeforeLast + 10)
                {
                    string name = chkResolveNames.Checked && !string.IsNullOrEmpty(lastHop.Hostname) ? lastHop.Hostname : lastHop.IPAddress;
                    findings.Add(Tuple.Create("AVISO: A perda de pacotes ocorre principalmente no destino final.", Color.DarkOrange, true));
                    findings.Add(Tuple.Create($"O servidor {name} pode estar sobrecarregado ou configurado para limitar o tráfego que estamos enviando.", Color.Black, false));
                }
            }

            var highLossIntermediateHops = currentHops.Where(h => h.TotalSent > 5 && ((double)h.PacketsLost / h.TotalSent * 100) > 80 && h != lastHop).ToList();
            if (highLossIntermediateHops.Any() && lastHopLoss < 10)
            {
                findings.Add(Tuple.Create("INFORMATIVO: Alguns saltos intermediários mostram alta perda de pacotes.", Color.DarkBlue, true));
                findings.Add(Tuple.Create("Como a perda não se reflete no destino final, isso é provavelmente devido a roteadores que desprioritizam pings (comportamento normal).", Color.Black, false));
            }

            if (findings.Count == 0)
            {
                findings.Add(lastHopLoss < 2.0
                    ? Tuple.Create("Nenhum problema significativo detectado na rota até o momento.", Color.DarkGreen, true)
                    : Tuple.Create("Analisando...", Color.Gray, false));
            }

            UpdateDiagnosisUI(findings);
        }

        private void UpdateDiagnosisUI(List<Tuple<string, Color, bool>> findings)
        {
            if (rtbDiagnosis.InvokeRequired)
            {
                rtbDiagnosis.Invoke(new Action(() => UpdateDiagnosisUI(findings)));
                return;
            }

            rtbDiagnosis.Clear();
            foreach (var finding in findings)
            {
                AppendText(rtbDiagnosis, finding.Item1 + Environment.NewLine, finding.Item2, finding.Item3);
            }
        }

        private void AppendText(RichTextBox box, string text, Color color, bool isBold = false)
        {
            box.SelectionStart = box.TextLength;
            box.SelectionLength = 0;
            box.SelectionColor = color;
            box.SelectionFont = new Font(box.Font, isBold ? FontStyle.Bold : FontStyle.Regular);
            box.AppendText(text);
            box.SelectionColor = box.ForeColor;
            box.SelectionFont = box.Font;
        }
        #endregion

        #region Shared & Helper Methods
        
        private async Task<List<HopInfo>> DiscoverRouteAsync(string targetIp, CancellationToken token)
        {
            const int maxHops = 40; 
            var discoveredHops = new List<HopInfo>();
            var infoTasks = new List<Task>();

            IPAddress lastAddress = null;
            int stallCount = 0;
            const int stallThreshold = 5;

            for (int ttl = 1; ttl <= maxHops && !token.IsCancellationRequested; ttl++)
            {
                PingReply reply = null;
                try
                {
                    using (var pinger = new Ping()) 
                    {
                        reply = await pinger.SendPingAsync(targetIp, 2000, new byte[32], new PingOptions(ttl, false));
                    }
                }
                catch (PingException ex) { UpdateStatus($"Erro de Ping na descoberta: {ex.InnerException?.Message ?? ex.Message}", Color.Red); return null; }

                var hop = new HopInfo { HopNumber = ttl };

                lock (hops) hops[ttl] = hop;
                discoveredHops.Add(hop);

                if (reply != null && (reply.Status == IPStatus.Success || reply.Status == IPStatus.TtlExpired))
                {
                    hop.AddressToPing = reply.Address;
                    hop.IPAddress = reply.Address?.ToString() ?? "N/A";
                    hop.NetworkType = GetNetworkType(hop.AddressToPing);
                    
                    infoTasks.Add(ResolveHostnameAsync(hop));
                    infoTasks.Add(GetIpInfoAsync(hop));

                    if (lastAddress != null && lastAddress.Equals(reply.Address))
                    {
                        stallCount++;
                    }
                    else
                    {
                        stallCount = 0;
                    }

                    lastAddress = reply.Address;

                    if (stallCount >= stallThreshold)
                    {
                        Debug.WriteLine($"A rota parece ter estagnado no IP {lastAddress}. Interrompendo a descoberta.");
                        break;
                    }
                    
                    if (reply.Status == IPStatus.Success) break;
                }
                else
                {
                    hop.IPAddress = "*";
                    hop.Hostname = "Sem resposta do host";
                    hop.NetworkType = "N/A";
                    hop.AsnInfo = "N/A";
                    hop.Location = "N/A";
                    
                    stallCount++; 
                    if (stallCount >= stallThreshold)
                    {
                         Debug.WriteLine("A rota encontrou múltiplos timeouts consecutivos. Interrompendo a descoberta.");
                         break;
                    }
                }
            }
            await Task.WhenAll(infoTasks);
            return discoveredHops;
        }

        #region IP Info Fetching with Fallback
        
        private async Task FetchUserPublicInfoAsync()
        {
            UpdateStatus("Detectando informações da rede local...", Color.DarkBlue);
            try
            {
                var response = await httpClient.GetStringAsync("http://ip-api.com/json?fields=status,as,query");
                var ipInfo = JsonConvert.DeserializeObject<IpApiInfo>(response);
                if (ipInfo != null && ipInfo.Status == "success" && !string.IsNullOrWhiteSpace(ipInfo.Asn))
                {
                    this.userAsnInfo = ipInfo.Asn;
                    return;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Falha ao buscar info do usuário com ip-api.com: {ex.Message}");
            }

            try
            {
                var response = await httpClient.GetStringAsync("https://ipinfo.io/json");
                var ipInfo = JsonConvert.DeserializeObject<IpInfoIo>(response);
                if (ipInfo != null && !string.IsNullOrWhiteSpace(ipInfo.AsnOrg))
                {
                    this.userAsnInfo = ipInfo.AsnOrg;
                    return;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Falha ao buscar info do usuário com ipinfo.io: {ex.Message}");
            }
            
            this.userAsnInfo = "ASN do Usuário (Falha na busca)";
        }
        
        private async Task GetIpInfoAsync(HopInfo hop)
        {
            if (hop.AddressToPing == null || hop.NetworkType != "Público")
            {
                hop.AsnInfo = this.userAsnInfo;
                hop.Location = "Rede Local";
                return;
            }

            hop.IsFetchingGeoInfo = true;

            bool success = await TryGetInfoFromIpApiCom(hop);
            if (!success)
            {
                Debug.WriteLine($"Fallback para ipinfo.io para o IP: {hop.IPAddress}");
                success = await TryGetInfoFromIpInfoIo(hop);
            }
            
            if (!success)
            {
                hop.AsnInfo = "Falha na Busca";
                hop.Location = "N/A";
            }

            hop.IsFetchingGeoInfo = false;
        }

        private async Task<bool> TryGetInfoFromIpApiCom(HopInfo hop)
        {
            try
            {
                var response = await httpClient.GetStringAsync($"http://ip-api.com/json/{hop.IPAddress}?fields=status,country,city,as,query");
                var ipInfo = JsonConvert.DeserializeObject<IpApiInfo>(response);

                if (ipInfo != null && ipInfo.Status == "success" && !string.IsNullOrWhiteSpace(ipInfo.Asn))
                {
                    hop.AsnInfo = ipInfo.Asn;
                    hop.Location = (string.IsNullOrWhiteSpace(ipInfo.City) ? "" : ipInfo.City + ", ") + ipInfo.Country;
                    return true;
                }
            }
            catch (Exception ex) { Debug.WriteLine($"Erro na API ip-api.com: {ex.Message}"); }
            return false;
        }

        private async Task<bool> TryGetInfoFromIpInfoIo(HopInfo hop)
        {
            try
            {
                var response = await httpClient.GetStringAsync($"https://ipinfo.io/{hop.IPAddress}/json");
                var ipInfo = JsonConvert.DeserializeObject<IpInfoIo>(response);
                
                if (ipInfo != null && !string.IsNullOrWhiteSpace(ipInfo.AsnOrg))
                {
                    hop.AsnInfo = ipInfo.AsnOrg;
                    hop.Location = (string.IsNullOrWhiteSpace(ipInfo.City) ? "" : ipInfo.City + ", ") + ipInfo.Country;
                    return true;
                }
            }
            catch (Exception ex) { Debug.WriteLine($"Erro na API ipinfo.io: {ex.Message}"); }
            return false;
        }
        #endregion

        private async Task<string> ResolveHostWithCustomDnsAsync(string host)
        {
            if (IPAddress.TryParse(host, out IPAddress parsedIp)) return parsedIp.ToString();

            bool preferIpv6 = false;
            this.Invoke(new Action(() => {
                preferIpv6 = cmbIpPreference.SelectedIndex == 1;
            }));

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host);
                IPAddress target = null;

                if (preferIpv6)
                    target = addresses.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) 
                            ?? addresses.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                else
                    target = addresses.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) 
                            ?? addresses.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

                if (target != null)
                {
                    Debug.WriteLine($"Resolução via Sistema sucesso para {host}: {target}");
                    return target.ToString();
                }
            }
            catch (Exception sysDnsEx)
            {
                Debug.WriteLine($"Falha na resolução padrão do sistema para {host}: {sysDnsEx.Message}. Tentando com DnsClient...");
            }

            Debug.WriteLine($"Resolução via sistema falhou. Usando DnsClient para {host}.");
            try
            {
                var lookupClient = GetSelectedDnsClient();
                
                // Try AAAA first if IPv6 preferred
                if (preferIpv6)
                {
                   var result6 = await lookupClient.QueryAsync(host, QueryType.AAAA);
                   var record6 = result6.Answers.AaaaRecords().FirstOrDefault();
                   if (record6 != null) return record6.Address.ToString();
                }

                // Try A (IPv4)
                var result = await lookupClient.QueryAsync(host, QueryType.A);
                var record = result.Answers.ARecords().FirstOrDefault();
                if (record != null) return record.Address.ToString();

                // If IPv4 preferred but failed, try AAAA as fallback
                if (!preferIpv6)
                {
                   var result6 = await lookupClient.QueryAsync(host, QueryType.AAAA);
                   var record6 = result6.Answers.AaaaRecords().FirstOrDefault();
                   if (record6 != null) return record6.Address.ToString();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Erro na resolução com DnsClient para {host}: {ex.Message}");
            }

            return null;
        }
        
        private Task ResolveHostnameAsync(HopInfo hop)
        {
            if (!chkResolveNames.Checked)
            {
                hop.Hostname = hop.IPAddress;
                return Task.CompletedTask;
            }
            
            if (hop.AddressToPing == null || hop.IsResolvingHostname) return Task.CompletedTask;

            hop.IsResolvingHostname = true;
            return Task.Run(async () =>
            {
                try
                {
                    var lookupClient = GetSelectedDnsClient();
                    var result = await lookupClient.QueryReverseAsync(hop.AddressToPing);
                    if(result.Answers.PtrRecords().Any())
                    {
                        hop.Hostname = result.Answers.PtrRecords().First().PtrDomainName.Value.TrimEnd('.');
                    }
                    else
                    {
                        hop.Hostname = hop.IPAddress;
                    }
                }
                catch { hop.Hostname = hop.IPAddress; }
                finally { hop.IsResolvingHostname = false; }
            });
        }
        
        private ILookupClient GetSelectedDnsClient()
        {
            string selection = (string)this.Invoke(new Func<string>(() => cmbDnsServer.SelectedItem.ToString()));

            switch(selection)
            {
                case "Google (8.8.8.8)":
                    return new LookupClient(IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4"));
                case "Cloudflare (1.1.1.1)":
                    return new LookupClient(IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1"));
                case "OpenDNS (208.67.222.222)":
                    return new LookupClient(IPAddress.Parse("208.67.222.222"), IPAddress.Parse("208.67.220.220"));
                case "Padrão do Sistema":
                default:
                    return new LookupClient();
            }
        }

        private string GetNetworkType(IPAddress ipAddress)
        {
            if (ipAddress == null) return "N/A";
            if (IPAddress.IsLoopback(ipAddress)) return "Loopback";

            byte[] bytes = ipAddress.GetAddressBytes();
            if (bytes.Length == 4)
            {
                switch (bytes[0])
                {
                    case 10: return "Privado (Classe A)";
                    case 172: if (bytes[1] >= 16 && bytes[1] <= 31) return "Privado (Classe B)"; break;
                    case 192: if (bytes[1] == 168) return "Privado (Classe C)"; break;
                    case 169: if (bytes[1] == 254) return "Link-Local"; break;
                }
            }
            return "Público";
        }

        private void UpdateUiTimer_Tick(object sender, EventArgs e)
        {
            if (!isRunning) return;
            dgvResults.SuspendLayout();
            lock (hops)
            {
                foreach (var hop in hops.Values.OrderBy(h => h.HopNumber))
                {
                    var row = dgvResults.Rows.Cast<DataGridViewRow>().FirstOrDefault(r => r.Cells["Hop"].Value != null && (int)r.Cells["Hop"].Value == hop.HopNumber);
                    if (row == null) continue;

                    lock (hop)
                    {
                        if (hop.WarmupPingsSent <= WARMUP_PING_COUNT)
                        {
                            row.Cells["Sent"].Value = 0;
                            row.Cells["Loss"].Value = "0.0%";
                        }
                        else
                        {
                            double lossPercentage = hop.TotalSent > 0 ? (double)hop.PacketsLost / hop.TotalSent * 100 : 0;
                            double avgPing = hop.PingTimes.Count > 0 ? hop.PingTimes.Where(p => p >= 0).DefaultIfEmpty(0).Average() : 0;
                            row.Cells["Loss"].Value = $"{lossPercentage:F1}%";
                            row.Cells["Sent"].Value = hop.TotalSent;
                            row.Cells["Last"].Value = hop.LastPing >= 0 ? hop.LastPing.ToString() : "*";
                            row.Cells["Avg"].Value = avgPing > 0 ? $"{avgPing:F1}" : "*";
                            row.Cells["Best"].Value = hop.BestPing >= 0 ? hop.BestPing.ToString() : "*";
                            row.Cells["Worst"].Value = hop.WorstPing > 0 ? hop.WorstPing.ToString() : "*";
                            row.Cells["Jitter"].Value = hop.Jitter > 0 ? $"{hop.Jitter:F1}" : "*";
                            Color rowColor = Color.White;
                            if (lossPercentage > 25) rowColor = Color.FromArgb(255, 192, 192); else if (lossPercentage > 5) rowColor = Color.FromArgb(255, 255, 192); else if (hop.WorstPing > 200) rowColor = Color.FromArgb(255, 224, 192);
                            row.DefaultCellStyle.BackColor = (row.Index % 2 != 0 && rowColor == Color.White) ? dgvResults.AlternatingRowsDefaultCellStyle.BackColor : rowColor;
                        }

                        string hostnameDisplay = hop.IPAddress;
                        if (chkResolveNames.Checked)
                        {
                            if (hop.IsResolvingHostname)
                            {
                                hostnameDisplay += " [Resolvendo...]";
                            }
                            else if (!string.IsNullOrEmpty(hop.Hostname) && hop.Hostname != hop.IPAddress)
                            {
                                hostnameDisplay += $" [{hop.Hostname}]";
                            }
                        }
                        row.Cells["Hostname"].Value = hostnameDisplay;

                        if (hop.IsFetchingGeoInfo)
                        {
                            row.Cells["Asn"].Value = "Buscando...";
                            row.Cells["Location"].Value = "Buscando...";
                        }
                        else
                        {
                            row.Cells["Asn"].Value = hop.AsnInfo;
                            row.Cells["Location"].Value = hop.Location;
                        }
                    }
                }
            }
            dgvResults.ResumeLayout();
            AnalyzeNetworkHealth();
        }

        private void StopTraceroute()
        {
            if (!isRunning) return;
            isRunning = false;
            isAnalyzingPath = false;
            cancellationTokenSource?.Cancel();
            updateTimer.Stop();
            SetUiState();
            UpdateStatus($"Parado. Operação interrompida.", Color.DarkRed);
        }

        private void ClearResults()
        {
            lock (hops) hops.Clear();
            dgvResults.Rows.Clear();
            rtbPathPing.Text = "O relatório da Análise de Rota (PathPing) aparecerá aqui...";
            rtbDiagnosis.Text = "Aguardando dados para iniciar o diagnóstico...";
            if (!isRunning) UpdateStatus("Pronto", Color.DarkBlue);
        }

        private void SetUiState()
        {
            this.Invoke(new Action(() => {
                bool isBusy = isRunning || isAnalyzingPath;
                btnStart.Enabled = !isBusy;
                cboHost.Enabled = !isBusy;
                grpOptions.Enabled = !isBusy;
                btnClear.Enabled = !isBusy;
                btnAbout.Enabled = !isBusy;

                btnStop.Enabled = isRunning;
            }));
        }

        private void DgvResults_CellMouseDown(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right && e.RowIndex >= 0)
            {
                dgvResults.CurrentCell = dgvResults.Rows[e.RowIndex].Cells[e.ColumnIndex >= 0 ? e.ColumnIndex : 1];
                dgvResults.Rows[e.RowIndex].Selected = true;
            }
        }

        private void CopyIpToClipboard()
        {
            if (dgvResults.CurrentRow != null && dgvResults.CurrentRow.Index >= 0)
            {
                var hopCell = dgvResults.CurrentRow.Cells["Hop"];
                if (hopCell != null && hopCell.Value is int hopNum)
                {
                    string ip = null;
                    lock (hops)
                    {
                        if (hops.ContainsKey(hopNum))
                        {
                            ip = hops[hopNum].IPAddress;
                        }
                    }

                    if (!string.IsNullOrEmpty(ip) && ip != "*" && ip != "N/A")
                    {
                        Clipboard.SetText(ip);
                        MessageBox.Show($"IP {ip} copiado para a área de transferência!", "Sucesso", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                         MessageBox.Show("Não há um IP válido para copiar neste salto.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
            }
        }

        private void UpdateStatus(string message, Color color)
        {
            if (lblStatus.InvokeRequired) lblStatus.Invoke(new Action(() => UpdateStatus(message, color)));
            else { lblStatus.Text = message; lblStatus.ForeColor = color; }
        }
        #endregion
    }

    public class AboutForm : Form
    {
        public AboutForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.Text = "Sobre Network Analysis Suite - MTRoute";
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterParent;
            this.Size = new Size(340, 160);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowInTaskbar = false;
            this.Font = new Font("Segoe UI", 9F);

            var lblTitle = new Label
            {
                Text = "Network Analysis Suite - MTRoute v1.5",
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(12, 12)
            };

            var lblCreator = new Label
            {
                Text = "Criado por:",
                AutoSize = true,
                Location = new Point(12, 45)
            };
            
            var linkLabel = new LinkLabel
            {
                Text = "t.me/Caio_Fndo",
                AutoSize = true,
                Location = new Point(80, 45)
            };
            linkLabel.LinkClicked += (sender, args) =>
            {
                Process.Start(new ProcessStartInfo("https://t.me/Caio_Fndo") { UseShellExecute = true });
            };
            
            var btnOk = new Button
            {
                Text = "OK",
                DialogResult = DialogResult.OK,
                Size = new Size(80, 28),
                Location = new Point(this.ClientSize.Width - 92, this.ClientSize.Height - 40)
            };

            this.Controls.AddRange(new Control[] { lblTitle, lblCreator, linkLabel, btnOk });
            this.AcceptButton = btnOk;
        }
    }

    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}