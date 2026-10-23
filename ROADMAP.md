# Roadmap — scanner web passivo de URL

> **Objetivo:** construir em poucas semanas um scanner pequeno, útil e testável, enquanto aprende fundamentos de AppSec. A primeira versão verifica sinais observáveis numa aplicação web; não promete encontrar todas as vulnerabilidades.

## Decisão de escopo

Comece com uma **CLI local em Python** que recebe uma URL autorizada, faz poucas requisições `GET` e gera um relatório. Python reaproveita sua experiência com automação/RPA: HTTP, tratamento de erros, parsing e relatórios são habilidades transferíveis.

A versão inicial é **passiva e não intrusiva**. Ela pode apontar configurações e exposições visíveis, mas não confirma falhas que dependem de contexto, autenticação ou exploração. Por exemplo, um scanner passivo não consegue afirmar com confiança que encontrou SQL injection, XSS explorável, IDOR/controle de acesso quebrado, SSRF ou falhas de lógica de negócio.

**Use apenas em sistemas próprios, ambientes de laboratório ou alvos para os quais você tenha autorização explícita.** Não disponibilize o scanner como serviço público que aceita URLs arbitrárias.

## Resultado esperado do MVP

Uma execução como `webscan https://meu-lab.example` deve:

1. validar e exibir o escopo do alvo;
2. consultar a página inicial, sem enviar formulários ou payloads de teste;
3. observar HTTPS, status, redirecionamentos, cabeçalhos e cookies;
4. emitir achados com evidência, explicação, recomendação e limitações;
5. salvar um relatório Markdown ou JSON;
6. funcionar contra um servidor de teste local e ter testes automatizados.

### Verificações iniciais

- **Transporte:** URL usa HTTPS; certificado TLS é validado pelo cliente HTTP (não desabilitar essa validação).
- **Cabeçalhos:** presença/configuração de HSTS em HTTPS, CSP, `X-Content-Type-Options`, proteção contra framing (`frame-ancestors` ou `X-Frame-Options`) e `Referrer-Policy`.
- **Cookies recebidos:** sinalizar `Secure`, `HttpOnly` e `SameSite` ausentes, sem presumir que cada cookie exige todos os atributos.
- **Exposição de tecnologia:** valores excessivamente detalhados em `Server`/`X-Powered-By` e mensagens de erro potencialmente informativas.
- **Redirecionamento:** registrar o status e o cabeçalho `Location`; não seguir redirects no MVP. Um seguimento limitado a same-origin pode ser avaliado depois, com controles de escopo.

Trate ausência de cabeçalho como **sinal para revisão**, não como prova automática de vulnerabilidade. Contexto (por exemplo, API JSON versus página HTML), arquitetura e necessidade de compatibilidade mudam a interpretação.

## Plano curto: 4 etapas

Ritmo sugerido: 4–5 sessões semanais de 45–90 minutos. Em cada sessão, estude só o conceito necessário para a próxima entrega e implemente algo pequeno.

### Etapa 1 — Fundamentos e primeira resposta (dias 1–3)

**Estudar:** URL, DNS em alto nível, HTTP request/response, status, TLS, cabeçalhos e exceções/timeouts em Python.

**Construir:** CLI que valida esquema `http`/`https`, faz uma requisição `GET` para um alvo de laboratório e imprime status, URL consultada (sem seguir redirects por padrão) e cabeçalhos relevantes.

**Concluído quando:** timeout, DNS inválido, certificado inválido e resposta HTTP normal produzem mensagens claras; a validação TLS continua habilitada.

### Etapa 2 — Regras passivas e segurança do próprio scanner (dias 4–7)

**Estudar:** cabeçalhos de segurança, cookies e o que uma checagem passiva pode ou não concluir.

**Construir:** regras independentes para os cabeçalhos e cookies da lista acima; cada regra deve devolver um achado estruturado, com evidência mínima e recomendação. Adicione timeout, limite de bytes da resposta, limite de requisições e User-Agent identificável.

**Proteções obrigatórias:** execução local, escopo explícito por hostname, somente `GET`, sem autenticação/cookies fornecidos pelo usuário, sem formulários, sem payloads e sem seguir redirects fora do escopo. Limite de taxa baixo. Para domínios públicos, rejeite destinos não públicos e use também restrição de saída de rede (firewall/ambiente isolado); uma checagem DNS feita antes da conexão, sozinha, não elimina DNS rebinding. Para laboratório local, use uma opção explícita de modo-lab e mantenha o serviço isolado.

**Concluído quando:** o programa recusa esquemas inesperados, não atravessa redirects para outro host, e as regras têm testes para presente/ausente e casos de contexto.

### Etapa 3 — Relatório e qualidade (semana 2)

**Construir:** relatório Markdown legível e JSON estável; agrupar achados repetidos; registrar URL, horário, status e limitações; incluir nível de confiança e severidade conservadora (por exemplo, `info`/`baixo`, quando aplicável). Não coletar nem armazenar corpos completos por padrão.

**Testar:** servidor HTTP local com respostas simuladas, testes unitários por regra, URL malformada, timeout, redirects, cookies múltiplos e respostas grandes. Não use sites de terceiros como fixtures de testes.

**Concluído quando:** execução repetida em fixture produz resultados previsíveis e o JSON pode ser consumido por outro script RPA/CI.

### Etapa 4 — Validação e portfólio (semana 3; opcional semana 4)

1. Rode o scanner somente no seu laboratório, como OWASP Juice Shop local.
2. Compare as observações passivas com o **OWASP ZAP Baseline Scan**, que documenta uma abordagem passiva de curta duração. Investigue diferenças e falsos positivos; não copie resultados sem entender a regra.
3. Escreva no README como instalar, executar, quais riscos cobre, quais não cobre, limites de uso e um exemplo de relatório sanitizado.
4. Grave uma demonstração curta e inclua testes automatizados no repositório. Isso transforma o projeto em evidência de engenharia, não apenas em uma lista de ferramentas.

**Concluído quando:** outra pessoa consegue executar o projeto no laboratório, entender um achado e reproduzir os testes sem instruções particulares.

## O que deixar para depois

Somente após o MVP e estudo separado, considere crawl limitado de links same-origin, análise de `robots.txt`/sitemap como fontes de URLs, autenticação em ambiente próprio, análise de dependências/SBOM, ou checks ativos em modo estritamente isolado. Antes de adicionar crawl, defina limites de páginas/profundidade, deduplicação, taxa, regras de escopo e exclusões de rotas com efeitos colaterais.

**Fora do MVP:** brute force, fuzzing, exploração automática, envio de payloads de SQLi/XSS, submissão de formulários, testes de escrita/alteração, varredura de portas e qualquer execução contra alvos arbitrários. Esses recursos aumentam risco e complexidade, e não são necessários para demonstrar um primeiro scanner funcional.

## Como estudar sem transformar em maratona

Use um ciclo simples por tema: **20–30 min de leitura → 30–60 min de laboratório autorizado → uma nota curta sobre evidência e limites → uma regra/teste no projeto**. Priorize apenas:

1. HTTP, cookies, TLS e cabeçalhos;
2. leitura introdutória do OWASP Top 10;
3. fundamentos de XSS, SQL injection e controle de acesso, para entender por que checagens passivas não bastam;
4. prática em laboratórios interativos da PortSwigger Web Security Academy;
5. revisão do resultado com o OWASP WSTG e comparação com ZAP Baseline.

Não tente “implementar o OWASP Top 10 inteiro” no scanner. Use o Top 10 como mapa de riscos e o WSTG como referência de testes; converta apenas um conceito de cada vez em uma checagem cuja evidência você consegue explicar.

## Critérios de qualidade do projeto

- Cada achado explica **o que foi observado**, **por que pode importar**, **como corrigir** e **o que a ferramenta não conseguiu verificar**.
- Findings descrevem sinais, não fazem alegações de exploração sem evidência.
- Regras têm testes automatizados; falhas de rede não viram “site vulnerável”.
- O escopo e os limites de requisição são visíveis antes de iniciar.
- Não se armazenam credenciais, cookies de sessão ou conteúdo sensível.
- README deixa claro que ferramenta automatizada não substitui revisão manual nem autorização.

## Referências selecionadas

- [OWASP Top 10 (versão atual)](https://owasp.org/Top10/2025/) — panorama de riscos; ponto de partida, não checklist completo de scanner.
- [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) — referência para metodologia e testes web; use os tópicos pertinentes, não tente ler tudo de uma vez.
- [OWASP Cheat Sheet: HTTP Security Response Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) — recomendações e ressalvas de cabeçalhos/cookies.
- [OWASP Cheat Sheet: SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — importante porque um programa que busca URLs pode ser abusado como cliente de rede; reforça validação, escopo e controles de rede.
- [ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/) — exemplo de baseline passiva e relatórios; não confundir com teste abrangente.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — material gratuito e laboratórios interativos para estudar vulnerabilidades com segurança.
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — aplicação deliberadamente vulnerável para laboratório e avaliação de ferramentas.

## Próximo passo

Comece pela Etapa 1 e limite a primeira entrega a uma URL e uma resposta HTTP. O foco inicial é terminar um scanner pequeno, seguro e honesto sobre seus limites — ampliar cobertura vem depois.
