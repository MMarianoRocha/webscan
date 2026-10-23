# Roadmap — WebScan: do baseline à análise ativa

> **Novo objetivo:** evoluir o comando existente `webscan scan` com uma verificação ativa, limitada, para estudar **reflected Cross-Site Scripting (XSS refletido)**. Primeiro identificaremos reflexão de entrada de forma não executável e depois avaliaremos o contexto. O projeto não será um scanner de exploração genérico.

## Por que começar por XSS refletido?

É uma boa primeira investigação ativa porque conecta diretamente o que já existe (requisição HTTP, query string e resposta) a conceitos centrais de segurança web: entrada controlada pelo usuário, codificação de saída e contexto HTML/JavaScript. O ciclo pode ser observado numa resposta do laboratório sem autenticação ou alteração persistente de dados.

O objetivo da primeira versão ativa **não é executar JavaScript nem provar impacto contra usuários**. O scanner enviará apenas um marcador aleatório e inerte, como texto alfanumérico, para um parâmetro explicitamente indicado. Se esse marcador aparecer na resposta, o resultado será “entrada refletida”, não “XSS confirmado”. A prova de XSS depende do contexto de saída, do encoding e do comportamento do navegador; reflexão textual sozinha não é vulnerabilidade.

> **Uso:** a pessoa que executa é responsável por ter autorização e definir o escopo. A implementação será integrada ao fluxo do comando `scan`, mas a parte ativa será opt-in, limitada a endpoint/parâmetro informados e terá proteções contra varreduras amplas ou acidentais. Desenvolver e validar primeiro em laboratório local ou fixture; não usar em alvos sem autorização explícita.

## O que já existe

- CLI `webscan scan`, com análise passiva e uma sonda ativa opt-in;
- validação básica de URL, TLS verificado e política de destino público/loopback;
- observações passivas de cabeçalhos e flags de cookies;
- sonda de reflexão que envia um único marcador inerte para um parâmetro indicado, exige `--lab` e IP loopback literal em conexões reais, não segue redirects e limita a leitura da resposta;
- testes com respostas HTTP simuladas, incluindo redirects, resposta grande e proteção contra hostname na sonda ativa.

O scanner ainda **não faz crawling**, não descobre formulários nem parâmetros e não classifica com segurança o contexto HTML da reflexão. A sonda só informa que o marcador foi ou não observado; isso não confirma XSS.

## Fases

Ritmo sugerido: 4–5 sessões de 45–90 minutos por semana. Cada fase termina com teste e nota breve explicando evidência e limitações.

### Fase 0 — Preparar o fluxo padrão `scan` (implementada)

**Estudar:** escopo de autorização, diferença entre modo passivo e ativo, efeitos de redirects, limite de requisições e risco de um scanner que aceita URLs.

**Construir antes de qualquer sonda:**

- integrar a análise passiva e a ativa ao fluxo do comando `webscan scan`, mantendo a análise ativa desativada por padrão e habilitada por opção explícita, como `--active-xss`;
- começar o desenvolvimento e a validação em loopback/fixture; manter validação de URL, escopo explícito, TLS verificado e redirects desativados;
- exigir que a pessoa informe um único endpoint e o nome do parâmetro a testar — sem spider, descoberta automática ou submissão de formulário;
- permitir apenas `GET`, não enviar credenciais/cookies e não seguir redirects;
- limite pequeno configurável e explícito de requisições, timeout, limite efetivo de bytes, User-Agent identificável e pausa entre requisições;
- abortar em erro de escopo, redirect, resposta grande ou falha de rede, sem tentar outros caminhos;
- imprimir o alvo, parâmetro e número máximo de requisições antes de começar.

**Concluído quando:** testes provam que `webscan scan` mantém o comportamento passivo sem opção ativa, limita a sonda a um endpoint/parâmetro definido, não segue redirects e aborta em entradas inválidas; os testes usam mocks ou loopback.

### Fase 1 — Aprender reflexão de entrada sem payload executável (implementada)

**Estudar:** query parameters, percent-encoding, marcador único, diferença entre reflexão e execução, conteúdo HTML e escaping.

**Construir:** para um endpoint e parâmetro fornecidos manualmente, enviar um marcador alfanumérico aleatório e curto em uma requisição `GET`. Ler somente resposta limitada, procurar o marcador e registrar se aparece e quantas vezes. Preservar uma cópia sanitizada do contexto ao redor do marcador, sem guardar tokens, cookies ou resposta completa.

**Resultado esperado:** achado `input-reflected` ou `input-not-observed`, com endpoint redigido, parâmetro, posição aproximada, status e evidência sanitizada. Não rotular como XSS.

**Concluído quando:** fixture local cobre reflexão em texto, ausência de reflexão, múltiplas ocorrências, resposta sem HTML, marcador transformado e limite de corpo; nenhuma requisição vai para rede externa.

### Próxima fase — Entender contexto e encoding

**Estudar:** contextos de saída (texto HTML, atributo HTML, string JavaScript), codificação contextual, DOM e por que regex simples não prova explorabilidade.

**Construir:** classificador conservador do contexto do marcador em HTML usando parser, se aplicável. Diferenciar “texto refletido”, “reflexão em atributo/texto/script aparentemente codificada” e “contexto indeterminado”. Em caso duvidoso, informar que requer revisão manual. Não executar o conteúdo no browser nem enviar strings executáveis.

**Concluído quando:** testes locais incluem HTML escapado, atributos entre aspas, resposta não HTML e contexto ambíguo; a ferramenta nunca declara XSS confirmado apenas por encontrar o marcador.

### Fase 3 — Validação comparativa em laboratório

1. Usar uma aplicação deliberadamente vulnerável **local** (por exemplo, OWASP Juice Shop) e/ou uma fixture mínima própria com casos de reflexão codificada e não codificada.
2. Comparar a observação do WebScan com a inspeção manual do HTML retornado e com os materiais da PortSwigger Academy.
3. Registrar falsos positivos e negativos; não testar sites de terceiros nem reutilizar exemplos contra alvos reais.
4. Acrescentar relatório JSON/Markdown com nível de confiança, evidência mínima, recomendação defensiva e limitações.

**Concluído quando:** outra pessoa reproduz os casos no laboratório e entende por que “refletido” é diferente de “executável/vulnerável”.

### Fase 4 — Integração e documentação

- Atualizar README e guia de iniciantes com a diferença entre testes passivos e ativos.
- Documentar como usar o comando `scan` em modo passivo e como habilitar, de forma explícita, a verificação ativa limitada.
- Documentar escopo, pré-requisitos de autorização, limites da análise e como interpretar os resultados.
- Rodar testes e lint antes de cada versão; não incluir relatório com cookies, tokens ou dados pessoais.

**Concluído quando:** o projeto explica o raciocínio, os controles e as limitações, e os testes automatizados reproduzem o comportamento previsto.

## Limites que não devem ser removidos nesta trilha

- O modo ativo exige opt-in, escopo explícito e um único endpoint/parâmetro; não aceitar URLs arbitrárias de usuários como serviço público.
- Sem crawl, brute force, fuzzing, payloads executáveis, coleta de dados, envio de formulário, autenticação ou alteração de estado.
- Sem seguir redirects ou resolver subdomínios automaticamente.
- Começar com um endpoint, um parâmetro e poucas requisições; sem concorrência.
- Redigir query strings e nunca persistir cookies, credenciais ou corpos integrais.
- Diferenciar claramente evidência observada, hipótese e vulnerabilidade confirmada.

O uso em qualquer sistema deve estar coberto por autorização e escopo definidos por quem executa. A opção ativa não deve transformar o projeto em crawler/atacante autônomo nem remover limites de requisições.

## Por que não começar por SQLi, SSRF ou IDOR?

- **SQL injection:** técnicas de detecção podem envolver entradas de teste que mudam consultas ou timing e podem afetar sistemas; é melhor estudar primeiro em labs e evoluir com um plano de segurança separado.
- **SSRF:** testar pode induzir o alvo a fazer conexões a redes internas; é uma fronteira de rede de maior risco.
- **IDOR/controle de acesso:** exige identidades e dados de teste, e comparar autorização entre usuários, algo que o scanner ainda não suporta com segurança.

XSS refletido com marcador inerte oferece um recorte didático e verificável sem tentar explorar a execução. A implementação fica integrada ao `scan`, com opt-in e validação inicial em laboratório.

## Como estudar sem maratona

Para cada conceito: **20–30 min de leitura → 30–60 min de laboratório local → anotar hipótese/evidência/limitação → criar um teste automatizado**. Ordem sugerida:

1. HTTP GET, query parameters e percent-encoding;
2. reflexão de entrada e encoding de saída;
3. HTML e contextos de saída;
4. classificação de achados e falsos positivos;
5. testes automatizados com servidor/transport simulado.

O OWASP Top 10 é mapa de riscos, não uma lista de funcionalidades a implementar. Use o WSTG e a Web Security Academy como referências pontuais para o assunto estudado.

## Critérios de qualidade

- Todo achado mostra o que foi enviado e observado, por que importa, correção defensiva e limitações.
- “Reflexão detectada” nunca vira automaticamente “XSS confirmado”.
- Os testes ativos usam mocks ou loopback; não há chamada real a domínios de terceiros na suíte.
- Os limites estão visíveis antes da requisição; exceções de rede não viram achados de vulnerabilidade.
- O modo passivo mantém seu comportamento e o ativo permanece opt-in.

## Referências selecionadas

- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) — conceito, contextos de reflexão e processo de análise.
- [PortSwigger — Reflected XSS Apprentice Lab](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded) — laboratório de aprendizagem; usar somente no ambiente oficial da Academy e manualmente, não como alvo do scanner.
- [PortSwigger Web Security Academy — todos os labs](https://portswigger.net/web-security/all-labs) — trilhas de XSS por nível, incluindo exercícios Apprentice.
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — metodologia; consultar o capítulo de validação de entrada e XSS.
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) — orientação defensiva sobre encoding contextual.
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — aplicação deliberadamente vulnerável para laboratório local.

## Próximo passo

Implementar a próxima fase: classificar de forma conservadora o contexto do marcador na resposta HTML. Não começar por payloads executáveis nem remover os limites de escopo e volume.
