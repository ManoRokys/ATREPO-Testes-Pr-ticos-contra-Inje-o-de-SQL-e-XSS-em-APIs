import pytest
from fastapi.testclient import TestClient
from main import app

cliente = TestClient(app)


# Testes nos endpoints vulneraveis

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_sql_injection():
    payload = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_qualquer",
    }
    resposta = cliente.post("/vulneravel/login", json=payload)

    assert resposta.status_code == 200
    dados = resposta.json()
    assert dados["email"] == "admin@hubsolidario.org"
    assert dados["is_admin"] is True


@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_xss():
    payload = {
        "autor": "Atacante",
        "conteudo": "<script>alert('xss')</script>",
    }
    resposta = cliente.post("/vulneravel/comentarios", json=payload)

    assert resposta.status_code == 200
    assert "<script>" in resposta.json()["conteudo"]


@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_union_select():
    payload = "%' UNION SELECT id, email, senha FROM usuarios --"
    resposta = cliente.get(f"/vulneravel/campanhas/buscar?termo={payload}")

    assert resposta.status_code == 200
    assert "segredo_admin_123" in str(resposta.json())


# Testes nos endpoints protegidos

@pytest.mark.security
def test_endpoint_seguro_deve_bloquear_sql_injection():
    payload = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_qualquer",
    }
    resposta = cliente.post("/seguro/login", json=payload)

    assert resposta.status_code == 401
    assert resposta.json()["detail"] == "Credenciais invalidas"


@pytest.mark.security
def test_endpoint_seguro_deve_sanitizar_tags_xss():
    payload = {
        "autor": "Atacante",
        "conteudo": "<script>alert('xss')</script>",
    }
    resposta = cliente.post("/seguro/comentarios", json=payload)

    assert resposta.status_code == 200
    conteudo = resposta.json()["conteudo"]
    assert "<script>" not in conteudo
    assert "&lt;script&gt;" in conteudo


@pytest.mark.security
def test_deve_rejeitar_extracao_union_select():
    payload = "%' UNION SELECT id, email, senha FROM usuarios --"
    resposta = cliente.get(f"/seguro/campanhas/buscar?termo={payload}")

    assert resposta.status_code == 200
    for item in resposta.json():
        assert "segredo_admin_123" not in str(item)


@pytest.mark.security
def test_deve_bloquear_xss_com_evento_onerror():
    payload = {
        "autor": "Invasor",
        "conteudo": '<img src="invalido" onerror="alert(1)">',
    }
    resposta = cliente.post("/seguro/comentarios", json=payload)

    assert resposta.status_code == 200
    conteudo = resposta.json()["conteudo"]
    assert "<img" not in conteudo
    assert "&lt;img" in conteudo
