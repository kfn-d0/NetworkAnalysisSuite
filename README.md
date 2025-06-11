🖼️ Captura de tela
![1](https://github.com/user-attachments/assets/2d85cfb5-9c1f-4b47-8578-f98b73c0cc30)
Exemplo de análise ativa até o IP 8.8.8.8 (Google DNS).

O NetworkAnalysisSuite - MTRoute é uma ferramenta avançada de análise de rede desenvolvida em C# e .NET, com funcionalidade semelhante ao WinMTR. Seu objetivo é fornecer um diagnóstico detalhado do caminho percorrido pelos pacotes até um destino, exibindo:

Todos os saltos (hops) até o destino.

Estatísticas de latência (mínima, média, máxima).

Jitter de cada salto.

Perda de pacotes individual por salto.

Identificação de IPs internos e externos.

Exibição do ASN, provedor e localização geográfica de cada IP.

Diagnóstico automático com sugestões em caso de perda significativa.

Customização de:

DNS (usando DNS do sistema ou Google / Cloudflare).

Intervalo entre pacotes (em ms).

Tamanho dos pacotes ICMP.

Tecnologias utilizadas
.NET / C#
Windows Forms
APIs de GeoIP e ASN (via consulta DNS reversa ou serviços integrados)

🚧 Status
Projeto em desenvolvimento contínuo. Sugestões e melhorias são bem-vindas!
