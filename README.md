# DNS Blocklists

Publicador gratuito de listas DNS para AdGuard DNS. Não é um resolvedor DNS, não recebe consultas DNS, não coleta histórico de navegação, não usa analytics nem transforma destinos bloqueados em links. Hospedagem: GitHub Pages, repositório público, GitHub Actions em runner Linux padrão gratuito. Sem domínio próprio ou cartão.

## Uso

Abra a página `/status/` e cadastre **todos os arquivos `gambling-NN.txt`** como listas de bloqueio personalizadas no AdGuard DNS. Não cadastre `gambling-master.txt`: é uma cópia completa para auditoria e pode ultrapassar 5 MB. Atualize as listas no AdGuard e confirme que seus dispositivos realmente usam o servidor configurado. O limite de regras e de listas da sua conta AdGuard é independente do limite por arquivo; se ele impedir a inclusão, dividir arquivos não elimina esse limite.

As seis camadas extras são opcionais: anti-bypass, new-domains, dynamic-dns, abused-tlds, shorteners e suspicious-domains. Podem causar falsos positivos, especialmente NRD e TLDs inteiros. Comece pela camada de apostas. Anti-bypass não substitui restrições do dispositivo ou firewall: VPNs, IPs diretos e resolvedores embutidos podem escapar ao DNS.

## Arquitetura

Fontes HTTPS → download com timeout/limite/retries → validação UTF-8 e conteúdo → normalização de domínio/IDN → deduplicação por camada → remoção de subdomínios já cobertos → divisão por bytes → testes → artefato completo Pages → testes HTTP públicos → checkpoint Git.

`sources.json` controla cada feed com `enabled`, categoria, URL, formato, licença, limites de tamanho e contagem. Nove feeds de três projetos independentes: HaGeZi (Gambling Full e seis camadas de segurança), Block List Project Gambling e StevenBlack Gambling Only. NRD usa os últimos 7 dias completos; DGA usa os últimos 30 dias completos. Não há truncamento de fontes escolhidas. Não incluímos o hosts geral StevenBlack, que mistura outras categorias. TLDs usam a variante HaGeZi sem exceções; ela evita perder exceções de regras complexas. Licenças e avisos de redistribuição acompanham os arquivos. O manifesto registra responsável, formato, licença, última atualização conhecida, entradas e estado de cada fonte.

Fontes regulatórias sem licença clara de redistribuição não são automaticamente incorporadas. Nenhum domínio é inventado. Não se promete 100% de cobertura presente ou futura.

## Sintaxe e segurança

Saída: `||example.org^`, bloqueando domínio e subdomínios. Lowercase, IDNA/punycode, comentários e linhas vazias removidos, hosts/adguard/domínios/DNSMasq aceitos. Para fontes explicitamente de domínios, URLs perdem protocolo/caminho. Regras com modificadores, exceções e instruções arbitrárias são recusadas; nunca executadas. HTML, arquivos vazios ou com corrupção excessiva invalidam a fonte. TLD isolado só é aceito na fonte especializada. Domínios críticos do publicador e do AdGuard são protegidos e exclusões de segurança são contabilizadas.

## Deduplicação e métricas

Deduplicação entre todas as fontes da mesma camada. O manifesto também mede domínios únicos e duplicatas entre camadas. Camadas opcionais preservam sobreposições entre si para permanecerem independentes: ativar somente uma não depende de outra. Duplicatas literais e subdomínios redundantes têm contadores distintos. `raw_entries` conta candidatos de dados, sem comentários; `valid_entries` conta candidatos válidos antes de deduplicar. `unique_entries` é a união global antes da redução pai/subdomínio; regras efetivamente emitidas aparecem por categoria. Não somar regras opcionais como se fossem exclusivamente apostas.

## Limites e publicação

Cada parte tem no máximo 4.200.000 bytes, incluindo cabeçalhos; o teste exige estritamente menos de 4.500.000. UTF-8 texto puro não compactado nas URLs AdGuard. Master é exceção explícita. SHA-256 e tamanho exato constam no manifesto. Cache comprimido serve somente para recuperação, nunca para cadastro no AdGuard.

Publicação de um artefato completo, sem editar os arquivos públicos individualmente. A origem troca o deployment inteiro; nenhum serviço pode garantir uma transação entre downloads independentes do AdGuard através de caches. Cabeçalhos de build e hashes permitem detectar versões diferentes. As URLs numeradas permanecem estáveis, mas se a lista crescer e criar novas partes será necessário adicioná-las ao AdGuard. A página de status mostra a quantidade atual.

## Atualização e fail-safe

Agendamento `17 */6 * * *` em UTC, mais execução manual e alterações de código. GitHub pode atrasar ou deixar de executar um agendamento; não é SLA. Checkpoints periódicos no repositório mantêm atividade; o GitHub pode desativar agendas de repositórios públicos após 60 dias sem atividade, suspensão da conta ou mudanças de política.

Cada fonte mantém último cache válido, com hash publicado. 404/500/timeout/HTML/vazio/conteúdo inválido: usa cache anterior e marca `stale`; sem cache, fonte fica indisponível. Falta de categoria ou menos de duas fontes de apostas impede publicação. Queda para menos de 60% ou crescimento acima de 3x por fonte gera anomalia; limites absolutos também existem. Queda de regras por categoria abaixo de 75% impede build. A versão pública anterior permanece se download, geração ou testes pré-deploy falharem. Falhas de verificação HTTP após deploy são reportadas no Actions; não são apresentadas como sucesso. Consulte Actions se `/status/` estiver desatualizado: uma falha não substitui a página da última versão boa.

A primeira execução não tem cache e precisa das sete categorias. Cache local/staging é descartável; cache válido publicado e Git permitem retomada. LAST_KNOWN_GOOD_BUILD só é atualizado no repositório após testes reais de produção. Nunca interpretar um build local como comprovação de publicação.

## Manutenção

Adicionar fonte: incluir objeto em `sources.json` com ID exclusivo, URL HTTPS, categoria existente, formato, licença, limites mínimo/máximo coerentes e `enabled: true`. Confirmar manutenção, licença e conteúdo antes do commit. Remover fonte: `enabled: false`; não remover a última fonte de uma categoria sem alterar explicitamente os critérios. Mudanças reais e grandes de upstream precisam revisão dos limiares, não desativação cega dos testes.

Comandos: `python3 pipeline.py test`, `python3 pipeline.py build`, `python3 pipeline.py verify --base URL`, `python3 pipeline.py checkpoint`. Python 3.11+ sem dependências externas. Execute o verificador com `--expected BUILD_ID` para exigir o build recém-publicado. Testes incluem injeção, IDN, hostnames inválidos, arquivo vazio/HTML, deduplicação, pais, split sem perdas e anomalias. Cada build testa todos os arquivos; verificação pública testa HTTPS com certificado válido, HTTP 200, sem cookie/autenticação, Content-Type, tamanho, sintaxe, contagem e SHA-256 de cada arquivo.

## Retomada

Leia PROJECT_STATUS.md, state.json, LAST_KNOWN_GOOD_BUILD.json, PRODUCTION_TESTS.json, histórico Git, último Actions e manifesto público. Continue do último checkpoint válido. Não recrie o repositório nem duplique infraestrutura. Não são necessários tokens pessoais nem credenciais no código.

## Licença

Código e listas derivadas: GPL-3.0. HaGeZi: GPL-3.0 (`LICENSE`); Block List Project: Unlicense (`LICENSE-BLP.txt`); StevenBlack e hostsVN: MIT (avisos em `LICENSE-StevenBlack.txt` e notices upstream). A classificação e manutenção dos upstreams pertencem aos respectivos autores. Sem garantia de ausência de falsos positivos.
