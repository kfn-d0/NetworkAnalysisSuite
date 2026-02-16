# MTRoute - Network Analysis Suite

🖼️ Captura de tela
![1](https://github.com/user-attachments/assets/2d85cfb5-9c1f-4b47-8578-f98b73c0cc30)
Exemplo de análise ativa até o IP 8.8.8.8 (Google DNS).

Ferramenta de diagnóstico de rede avançada "tudo em um" para Windows que combina as funcionalidades de Traceroute, Ping e MTR (My Traceroute). Ele fornece monitoramento de tráfego em tempo real, análise detalhada de rotas e diagnóstico automático da saúde da rede em uma interface moderna e fácil de usar.

## Principais Recursos

*   **Monitoramento MTR em Tempo Real**: Envia pings continuamente para cada salto na rota para detectar perda de pacotes e picos de latência ao longo do tempo.
*   **Análise PathPing**: Realiza uma análise detalhada com múltiplos pacotes na rota para identificar estatísticas confiáveis para cada nó.
*   **Histórico Inteligente**: Salva automaticamente suas consultas recentes. Acesse-as rapidamente através do campo de entrada suspenso.
*   **Suporte a IPv6**: Suporte total a IPv6. Escolha priorizar resolução IPv4 ou IPv6 para hosts dual-stack.
*   **Detecção GeoIP e ASN**: Resolve e exibe automaticamente a Localização (Cidade/País) e ASN (Provedor/Organização) para cada salto usando múltiplas APIs públicas.
*   **Diagnóstico Visual**:
    *   **Linhas Coloridas**: Identifique instantaneamente nós problemáticos (Alta Latência = Laranja/Vermelho, Perda de Pacote = Vermelho).
    *   **Cálculo de Jitter**: Monitora a variação nos tempos de ping para detectar instabilidade na rede.
*   **Diagnóstico Automático**: Um assistente inteligente analisa os dados coletados e fornece um resumo em texto simples sobre a saúde da sua rede, apontando problemas específicos como falhas no roteador local ou congestionamento no provedor.
*   **Menu de Contexto**: Clique com o botão direito em qualquer linha de resultado para copiar o endereço IP para a área de transferência.

## Requisitos

*   **SO**: Windows 10 ou Windows 11
*   **Runtime**: .NET 9.0 Desktop Runtime

## Como Usar

1.  **Digite um Host**: Digite um domínio (ex: `google.com`) ou um endereço IP na caixa de entrada. Você também pode selecionar um host consultado anteriormente no menu suspenso.
2.  **Selecione as Opções** (Opcional):
    *   *Intervalo*: Com que frequência os pings são enviados (padrão: 500ms).
    *   *Tam. Pacote*: Tamanho do pacote de ping (padrão: 32 bytes).
    *   *Servidor DNS*: Escolha um resolvedor DNS específico (Padrão do Sistema, Google, Cloudflare ou OpenDNS).
    *   *Protocolo*: Escolha priorizar **IPv4** ou **IPv6**.
3.  **Iniciar**: Clique em **Iniciar Análise**.
    *   **Fase 1**: A ferramenta descobre a rota para o destino.
    *   **Fase 2**: Inicia o monitoramento contínuo (MTR) de todos os saltos descobertos.
    *   **Fase 3**: Simultaneamente, executa uma análise estilo "PathPing" para estatísticas mais profundas.
4.  **Analisar**:
    *   Observe as colunas **Loss %** (Perda) e **Worst** (Pior) na grade.
    *   Leia o painel **Diagnóstico Automático** na parte inferior para um resumo inteligente dos problemas.
    *   Veja a saída bruta do **PathPing** no painel à direita.
5.  **Parar**: Clique em **Parar** para encerrar a sessão.

## Troubleshooting

*   **Falha ao descobrir a rota**: Verifique se há conexão ativa com a internet e se o ICMP (Ping) não está bloqueado pelo firewall local.
*   **No GeoIP Data**: A ferramenta utiliza APIs gratuitas (ip-api.com, ipinfo.io). Alto volume de uso pode gerar limitação temporária de requisições.

## Projeto em desenvolvimento. 

Sugestões e melhorias são bem-vindas!
