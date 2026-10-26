# Testes Praticos contra Injecao de SQL e XSS em APIs

Repositorio com a atividade de reposicao da disciplina de Qualidade e Testes de Software (QTS) da Fatec Registro.

Implementacao de testes ofensivos e defensivos em API FastAPI abordando vulnerabilidades de SQL Injection (SQLi) e Cross-Site Scripting (XSS), seguindo as diretrizes da OWASP.

---

## Estrutura do Projeto

```text
├── main.py                # API com rotas vulneraveis e rotas protegidas
├── tests/
│   └── test_seguranca.py  # Testes automatizados com pytest e TestClient
├── pyproject.toml         # Dependencias e configuracao do pytest
├── .gitignore             # Arquivos ignorados pelo Git
└── README.md              # Documentacao e respostas do questionario
```

---

## Vulnerabilidades e Mitigacoes

### SQL Injection (OWASP A03)
- **Problema:** Concatenacao direta de parametros em queries SQL (f-strings), permitindo burlar autenticacoes (`' OR '1'='1' --`) ou extrair dados com `UNION SELECT`.
- **Mitigacao:** Uso de Prepared Statements (consultas parametrizadas com `?`), tratando entradas como literais.

### Cross-Site Scripting (XSS - OWASP A03)
- **Problema:** Armazenamento ou reflexao de tags HTML/scripts (`<script>`, `<img onerror=...>`) sem tratamento.
- **Mitigacao:** Sanitizacao contextual com `html.escape()`.

---

## Execucao dos Testes

Instalar as dependencias:
```powershell
uv sync
```

Executar a suite de testes:
```powershell
uv run pytest -v
```

Executar a API:
```powershell
uv run uvicorn main:app --reload
```

---

## Saida dos Testes

```text
tests/test_seguranca.py::test_deve_comprovar_vulnerabilidade_de_sql_injection PASSED [ 14%]
tests/test_seguranca.py::test_deve_comprovar_vulnerabilidade_de_xss PASSED           [ 28%]
tests/test_seguranca.py::test_deve_comprovar_vulnerabilidade_union_select PASSED     [ 42%]
tests/test_seguranca.py::test_endpoint_seguro_deve_bloquear_sql_injection PASSED    [ 57%]
tests/test_seguranca.py::test_endpoint_seguro_deve_sanitizar_tags_xss PASSED        [ 71%]
tests/test_seguranca.py::test_deve_rejeitar_extracao_union_select PASSED            [ 85%]
tests/test_seguranca.py::test_deve_bloquear_xss_com_evento_onerror PASSED           [100%]

============================== 7 passed ==============================
```

---

## Respostas do Questionario (Quizzes)

1. **Por que a concatenacao direta de parametros de entrada em instrucoes SQL e uma pratica perigosa?**
   - **Resposta:** Porque permite que o usuario envie caracteres especiais (como aspas simples e comentarios) que alteram a sintaxe e a logica do interpretador SQL, executando instrucoes arbitrarias.

2. **Qual e o mecanismo tecnico correto para prevenir completamente vulnerabilidades de Injecao de SQL em aplicacoes com banco relacional?**
   - **Resposta:** Utilizar Consultas Parametrizadas (Prepared Statements), nas quais os dados do usuario sao enviados separadamente e tratados exclusivamente como valores literais pelo banco de dados.

3. **Qual e a principal diferenca entre o XSS Armazenado (Stored XSS) e o XSS Refletido (Reflected XSS)?**
   - **Resposta:** No XSS Armazenado, o script malicioso e persistido no banco de dados e afeta qualquer usuario que visualize aquele registro posteriormente; no XSS Refletido, o payload viaja na requisicao atual e e devolvido imediatamente na resposta do servidor.

4. **Em uma suite de testes de seguranca automatizada com o pytest, qual deve ser a assercao esperada ao enviar uma carga de injecao de SQL (' OR '1'='1) para o endpoint de autenticacao de uma API segura?**
   - **Resposta:** Status HTTP 401 Unauthorized rejeitando categoricamente o login.
