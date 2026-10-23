# Guia de leitura do WebScan para iniciantes

Este guia acompanha o código atual do projeto e explica o que acontece quando você executa uma análise. A ideia não é decorar cada linha: é entender o fluxo, as escolhas de segurança e o que os resultados realmente permitem concluir.

> **Escopo atual:** o WebScan faz uma requisição HTTP `GET`, não segue redirecionamentos, não envia payloads e não analisa o corpo da página. Suas regras observam alguns cabeçalhos e atributos de cookies. Os resultados são sinais para revisão, não confirmação de vulnerabilidades.

## 1. O percurso de uma execução

Ao executar `./.venv/bin/webscan scan https://seu-alvo-autorizado.example/`, o fluxo, resumidamente, é:

```text
terminal
  → Typer interpreta o comando e as opções
  → CLI valida/exibe avisos e chama inspect_url()
  → validação da URL
  → verificação de escopo do endereço IP
  → HTTPX envia uma requisição GET
  → resposta é reduzida a metadados e atributos de cookies
  → regras passivas produzem Findings
  → Rich mostra cabeçalhos e sinais no terminal
```

A sequência começa em [pyproject.toml](pyproject.toml), que registra `webscan = "webscan.cli:app"`: o executável chama o objeto `app` do módulo `webscan.cli`. A CLI fica em [src/webscan/cli.py](src/webscan/cli.py); transporte HTTP e validações ficam em [src/webscan/http_client.py](src/webscan/http_client.py); regras ficam em [src/webscan/checks/headers.py](src/webscan/checks/headers.py) e [src/webscan/checks/cookies.py](src/webscan/checks/cookies.py).

## 2. O que a CLI faz

A biblioteca **Typer** transforma argumentos do terminal em parâmetros Python. Neste projeto, `scan` recebe a URL e a opção `--lab`. A CLI cria a configuração padrão, chama `inspect_url()` e trata erros esperados:

- URL fora do formato aceito: erro de entrada;
- destino fora da política: erro de escopo;
- falha HTTP, como timeout ou erro TLS: a CLI mostra o tipo do erro, sem imprimir uma exceção que possa incluir a URL completa.

Se houver resposta, a CLI mostra o status HTTP, a versão do protocolo, os cabeçalhos selecionados e a quantidade de cookies. Depois chama as regras e apresenta os achados. **Um status `200` só significa que o servidor respondeu com sucesso HTTP; não significa que o site é seguro.** Um status `404` ou `500` também pode trazer cabeçalhos que valem a pena observar.

A biblioteca **Rich** monta tabelas. A função `_safe_text()` remove caracteres de controle e trata valores remotos como texto, em vez de permitir que sejam interpretados como marcação de terminal. Isso é importante porque cabeçalhos vêm do servidor consultado, e não devem ser tratados como conteúdo confiável.

## 3. URL, DNS e escopo

### Validar uma URL não é autorizar um alvo

`validate_target_url()` usa `urllib.parse.urlsplit()` para separar esquema, hostname, porta, caminho, query string e fragmento. Aceita apenas `http` e `https`, exige hostname, rejeita credenciais embutidas (`usuario:senha@host`), porta inválida, espaços e fragmentos. Isso reduz entradas ambíguas e impede esquemas que não são HTTP.

Essa validação **não comprova que você tem autorização**. A responsabilidade de testar somente sistemas próprios, laboratórios ou alvos autorizados continua sendo da pessoa que executa a ferramenta.

### O que o controle de destino faz

`validate_target_scope()` resolve o hostname com `socket.getaddrinfo()` e verifica os endereços retornados usando `ipaddress`:

- no modo normal, permite apenas se todos os IPs forem considerados públicos (`is_global`);
- com `--lab`, permite somente se todos forem loopback, como `127.0.0.1` ou `::1`.

Isso ajuda a evitar que a ferramenta acesse endereços privados ou serviços locais por engano. O modo laboratório é intencionalmente restrito: um IP de rede local como `192.168.x.x` não é loopback e será rejeitado.

**Limitação importante:** o programa consulta o DNS para decidir se o destino parece permitido, e depois o cliente HTTPX pode fazer outra resolução ao conectar. Uma resposta DNS pode mudar entre essas etapas (DNS rebinding). A validação atual, por si só, não elimina esse risco. Por isso, mantenha a ferramenta local, não a transforme em serviço público que aceita URLs de usuários e use restrições de saída de rede no ambiente de execução.

Nos testes, `httpx.MockTransport` substitui a conexão real. Quando esse transporte de teste está presente, a verificação DNS é ignorada porque nenhuma conexão de rede ocorre. Isso torna os testes previsíveis e impede que eles dependam de sites externos.

## 4. A requisição HTTP por baixo dos panos

`inspect_url()` cria um `httpx.Client` com:

- **timeout** de 5 segundos por padrão;
- **TLS verificado** (`verify=True`), sem desativar a validação do certificado;
- **redirects desativados** (`follow_redirects=False`);
- **proxy/variáveis de ambiente ignorados** (`trust_env=False`);
- um `User-Agent` que identifica o WebScan;
- método `GET` e conexão em modo streaming.

Um redirect é uma resposta como `301`, `302` ou `307` que sugere outro endereço no cabeçalho `Location`. O scanner registra esse cabeçalho, mas não visita o endereço seguinte. Isso mantém a execução em uma única requisição e evita atravessar escopo automaticamente.

A resposta é consumida como um `ResponseSummary`, definido em [src/webscan/http_client.py](src/webscan/http_client.py). Ele guarda URL sem query string, código HTTP, versão, cabeçalhos selecionados e atributos resumidos dos cookies. O corpo da resposta e os valores dos cookies não são guardados.

`display_url()` remove query strings antes de exibir/armazenar URLs. Isso reduz o risco de vazar tokens que alguns sistemas colocam na query, embora o caminho da URL ainda possa conter informação sensível.

### O que ainda não está implementado nessa camada

A configuração [src/webscan/config.py](src/webscan/config.py) já declara `max_response_bytes`, `max_requests`, `requests_per_second` e `follow_redirects`, mas nem todos esses limites estão conectados ao transporte. Hoje há só uma requisição `GET` por execução e redirects estão desativados explicitamente. **O limite de bytes ainda não é aplicado**; o scanner não lê nem armazena o corpo, mas não se deve interpretar esse campo da configuração como proteção já implementada. Limitação de taxa e limite configurável de requisições também precisam ser implementados antes de adicionar crawling ou várias consultas.

`trust_env=False` impede que variáveis de proxy do ambiente alterem a conexão. Isso ajuda a tornar o comportamento previsível, mas pode impedir o acesso em redes que dependem de proxy corporativo.

## 5. Cabeçalhos e o que as regras significam

A resposta retém uma lista pequena de cabeçalhos: `Content-Type`, `Server`, `X-Powered-By`, `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options` e `Referrer-Policy`; `Location` é incluído quando presente.

Em [src/webscan/checks/headers.py](src/webscan/checks/headers.py), as verificações fazem comparações simples sobre esses metadados:

- **HSTS:** só é avaliado quando a URL consultada usa HTTPS. Se o cabeçalho faltar ou não tiver um `max-age` positivo reconhecido, surge um achado de baixa severidade. HSTS ajuda navegadores a manter o uso de HTTPS; sua configuração depende do domínio e da implantação.
- **CSP:** a ausência é sinalizada apenas quando `Content-Type` parece ser HTML. CSP pode restringir origens de conteúdo e reduzir o impacto de certas injeções, mas a ausência não prova XSS.
- **`X-Content-Type-Options`:** a regra procura o valor `nosniff` em respostas HTML. Ele ajuda navegadores a não adivinhar o tipo do conteúdo em alguns cenários.
- **Framing:** a regra procura a presença da diretiva `frame-ancestors` na CSP ou valores conhecidos de `X-Frame-Options`. Isso é uma checagem superficial; detectar a diretiva não prova que toda a política CSP é válida ou eficaz.
- **`Referrer-Policy`:** a regra verifica se existe um valor reconhecido em HTML. A política controla quanto da URL de origem pode ser enviado no cabeçalho `Referer` durante navegações.

As regras são intencionalmente conservadoras e atribuem severidade baixa. Cabeçalhos ausentes podem ser aceitáveis em alguns contextos, e uma política presente pode estar mal configurada. Um scanner pequeno não conhece a arquitetura nem os requisitos do sistema: valide o achado antes de concluir que há uma falha.

## 6. Cookies: dados sensíveis tratados com cuidado

O servidor envia cookies por cabeçalhos `Set-Cookie`. Pode haver vários deles na mesma resposta, então o HTTPX é consultado com `get_list("set-cookie")` para preservar essa multiplicidade.

`_cookie_attributes()` separa atributos como `Secure`, `HttpOnly` e `SameSite`, mas descarta o nome e o valor. O resultado guardado em [src/webscan/models.py](src/webscan/models.py) é um `CookieAttributes`: três observações e um indicador booleano heurístico chamado `session_like`.

A regra em [src/webscan/checks/cookies.py](src/webscan/checks/cookies.py) então:

- procura `Secure` ausente nos cookies recebidos por HTTPS;
- só procura `HttpOnly` e `SameSite` nos cookies cujo nome contém marcadores como `session`, `auth`, `token` ou `sid`;
- informa quantos cookies parecem não ter determinada flag, mas não exibe nomes nem valores.

Isso evita guardar credenciais de sessão no resultado, mas a heurística pode errar: nomes comuns não garantem que um cookie seja de autenticação, e um cookie de sessão pode ter um nome inesperado. `HttpOnly` não é obrigatório para todo cookie, e a política `SameSite` correta depende do fluxo funcional. O achado pede revisão, não mudança automática.

## 7. Como um achado é representado

`Finding`, em [src/webscan/models.py](src/webscan/models.py), é uma `dataclass`: uma estrutura nomeada para guardar dados relacionados. Cada achado tem identificador estável (`check_id`), título, severidade, evidência, explicação, recomendação e confiança.

As regras devolvem tuplas de `Finding`. A CLI junta as tuplas de cabeçalhos e cookies e as imprime. Separar **coleta HTTP**, **regras** e **apresentação** ajuda a testar cada parte independentemente. Também evita misturar uma comparação simples de cabeçalho com a lógica de conexão de rede.

## 8. Conceitos de Python que aparecem no projeto

- **Módulos e imports:** arquivos `.py` são módulos; `import` permite reutilizar funções e tipos de outros módulos.
- **Funções:** blocos reutilizáveis como `validate_target_url()` e `check_headers()` recebem entradas e devolvem resultados.
- **Type hints:** anotações como `url: str` e `tuple[Finding, ...]` documentam os formatos esperados e ajudam o editor; não validam sozinhas os dados em tempo de execução.
- **Dataclasses:** `@dataclass(frozen=True, slots=True)` gera uma classe de dados concisa e evita reatribuir seus campos após a criação.
- **Exceções:** `raise` interrompe o fluxo em uma condição inválida; `try/except` transforma erros técnicos em mensagens compreensíveis.
- **Context manager (`with`):** fecha cliente e resposta mesmo se ocorrer erro, liberando recursos de rede.
- **Comprehensions e tuplas:** criam coleções de forma concisa; o modelo usa tuplas para apresentar resultados sem mutação acidental.
- **Testes com doubles:** `MockTransport` simula respostas HTTP, e `monkeypatch` substitui funções como resolução DNS para testar cenários sem acessar rede real.

## 9. Como os testes demonstram o comportamento

Os testes unitários em [test_http_client.py](tests/unit/test_http_client.py), [test_headers.py](tests/unit/test_headers.py), [test_cookies.py](tests/unit/test_cookies.py) e [test_scope.py](tests/unit/test_scope.py) verificam entradas e saídas específicas. Por exemplo:

- URL malformada deve ser rejeitada antes de uma requisição;
- um `302` deve ser reportado sem seguir o `Location`;
- query string e valores de cookies não devem aparecer no resultado resumido;
- resposta HTML sem políticas deve gerar os sinais previstos;
- uma API JSON não deve receber alertas destinados especificamente a HTML;
- destinos privados devem ser bloqueados, e `--lab` deve aceitar só loopback.

Esses testes demonstram o comportamento para os casos simulados. **Não provam** que o scanner detecta todas as configurações incorretas, nem substituem testes em ambiente controlado, revisão manual ou autorização.

Para rodar a suíte: `./.venv/bin/pytest -q`. Para checar estilo: `./.venv/bin/ruff check src tests`.

## 10. O que este scanner não detecta

Uma única requisição sem autenticação, crawling ou payloads não consegue avaliar de forma confiável:

- SQL injection ou XSS explorável;
- controle de acesso, IDOR e autorização entre usuários;
- SSRF dentro da aplicação alvo;
- CSRF, lógica de negócio e fluxos de autenticação;
- vulnerabilidades que só aparecem em endpoints não visitados;
- comportamento JavaScript que depende de executar a aplicação no navegador.

O WebScan também não é um scanner completo de portas, TLS, dependências ou configuração de infraestrutura. Ele é um projeto de aprendizado para entender HTTP, observações passivas, engenharia de ferramentas e limites de automação.

## 11. Um exercício curto de aprendizagem

1. Inicie uma aplicação de laboratório na sua máquina, por exemplo OWASP Juice Shop local.
2. Rode com `--lab` e observe status, versão HTTP e cabeçalhos.
3. Antes de ler os achados, preveja quais regras devem disparar com base nos cabeçalhos mostrados.
4. Confira a previsão no código de `check_headers()` e `check_cookies()`.
5. Rode os testes unitários e altere mentalmente uma resposta simulada para entender como um atributo muda o resultado.
6. Anote uma limitação: por exemplo, por que a ausência de CSP não prova que existe XSS?

Use o modo `--lab` somente com servidor local ligado à interface loopback, como `127.0.0.1`. Ele não é uma autorização para varrer a rede local.

## 12. Leituras de apoio

- [OWASP Top 10 2025](https://owasp.org/Top10/2025/) — panorama de riscos comuns em aplicações web.
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — metodologia de testes; consulte tópicos conforme surgirem dúvidas.
- [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) — contexto e ressalvas sobre cabeçalhos.
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — riscos de aplicações que recebem URLs e fazem requisições de saída.
- [HTTPX: Clients](https://www.python-httpx.org/advanced/clients/) e [HTTPX: Streaming responses](https://www.python-httpx.org/quickstart/#streaming-responses) — como funcionam cliente e resposta em streaming usados aqui.
- [Python: `urllib.parse`](https://docs.python.org/3/library/urllib.parse.html) — parsing e composição de URLs.
