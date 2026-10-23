# WebScan

CLI de scanner web com análise **passiva** e uma sonda **ativa opcional e limitada** de reflexão de parâmetro. Use somente em sistemas próprios, laboratórios ou alvos com autorização explícita. A sonda ativa envia apenas um marcador alfanumérico inerte por `GET`; não executa payloads, não submete formulários e não tenta explorar falhas.

O plano de desenvolvimento está em [ROADMAP.md](ROADMAP.md).
Para entender o fluxo do programa, os conceitos usados e as limitações atuais, consulte o [Guia para iniciantes](GUIA_INICIANTE.md).

## Começar

Requer Python 3.10 ou superior. Crie e ative um ambiente virtual, depois instale o projeto com as dependências de desenvolvimento:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

No Linux/macOS, execute contra um serviço local ligado a loopback:

```bash
webscan scan --lab http://127.0.0.1:3000/
```

Para habilitar a sonda única de reflexão, indique explicitamente um parâmetro de query:

```bash
webscan scan --lab --active-xss --param q "http://127.0.0.1:3000/search?q=teste"
```

`--active-xss` exige `--lab`, um IP loopback literal (`127.0.0.1` ou `::1`) e `--param`; hostnames como `localhost` não são aceitos pela sonda ativa para evitar re-resolução DNS. A ferramenta envia uma única requisição de sonda, não segue redirects e limita os bytes lidos da resposta. “Marcador refletido” significa apenas que o texto apareceu na resposta; **não confirma XSS**.

Para ver as opções disponíveis: `webscan scan --help`.

O scanner faz uma consulta passiva e, apenas com opt-in, no máximo uma sonda ativa por execução. Não segue redirecionamentos. Os achados são conservadores e precisam de revisão manual. Não exponha essa ferramenta como serviço público que aceita URLs arbitrárias: a validação DNS prévia não elimina DNS rebinding, então ambientes que executem o scanner também precisam de restrição de saída de rede.

## Estrutura

- `src/webscan/cli.py`: interface de linha de comando (`webscan scan <URL>`).
- `src/webscan/config.py`: valores padrão e opções de execução (alguns limites ainda estão planejados e não aplicados).
- `src/webscan/models.py`: estruturas compartilhadas, como achados e resultados.
- `src/webscan/http_client.py`: camada HTTP passiva, validação de URL e política de escopo de rede.
- `src/webscan/active_xss.py`: sonda opt-in de reflexão com marcador inerte e limites de resposta.
- `src/webscan/checks/`: verificações passivas independentes.
- `src/webscan/reports/`: exportação de relatórios Markdown e JSON.
- `tests/unit/`: testes das regras, modelos e utilitários.
- `tests/integration/`: testes com servidor HTTP local simulado.

## Desenvolvimento

Requer Python 3.10 ou superior. Instale o projeto em modo editável com as dependências de desenvolvimento:

```bash
python -m pip install -e ".[dev]"
```

Rode a suíte e o lint com `pytest -q` e `ruff check src tests`. Consulte o guia para iniciantes e o roadmap para entender os limites das análises passiva e ativa.
