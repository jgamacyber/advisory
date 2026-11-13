# Security Advisory — Stored Cross-Site Scripting in Tax Rates Management

## 1. Informações gerais

| Campo | Informação |
|---|---|
| Produto | Modified eCommerce Shopsoftware |
| Versão analisada | 3.3.0 |
| Revisão | 16825 |
| Componente | Administration — Tax Rates |
| Arquivo afetado | `admin/tax_rates.php` |
| Vulnerabilidade | Stored Cross-Site Scripting (XSS) |
| CWE | CWE-79 |
| OWASP Top 10 | A03:2021 — Injection |
| CVSS | A definir |
| Status | PoC reproduzida anteriormente |

## 2. Descrição da vulnerabilidade

Foi identificada uma vulnerabilidade de Cross-Site Scripting armazenado (Stored XSS) no componente administrativo responsável pelo gerenciamento de alíquotas de impostos (Tax Rates).

A vulnerabilidade está relacionada ao campo `tax_description`, cujo conteúdo é recebido por requisições POST, armazenado no banco de dados e posteriormente apresentado na interface administrativa.

O valor persistido é recuperado por meio da função `parse_multi_language_value()` e concatenado diretamente ao conteúdo HTML apresentado pelo componente `infoBox`.

A ausência de escaping explícito no ponto de renderização permite que conteúdo HTML controlado pelo usuário seja interpretado pelo navegador.

## 3. Endpoint afetado

**Endpoint utilizado na reprodução:**

```http
GET /admin/tax_rates.php?page=1&tID=118
```

**Registro analisado:**

| Campo | Valor |
|---|---|
| Tax Rate ID | `118` |
| Tabela | `tax_rates` |
| Campo vulnerável | `tax_description` |
| Idioma utilizado | `DE` |
| Valor original | `DE::` |

## 4. Parâmetros identificados

| Parâmetro | Método | Finalidade |
|---|---|---|
| `tID` | GET | Identificação do registro de imposto |
| `action` | GET | Define a operação administrativa |
| `tax_description` | POST | Descrição da alíquota por idioma |
| `tax_zone_id` | POST | Identificação da zona geográfica |
| `tax_class_id` | POST | Identificação da classe de imposto |
| `tax_rate` | POST | Valor da alíquota |
| `tax_priority` | POST | Prioridade da alíquota |

## 5. Evidências técnicas

### 5.1. Entrada dos dados

Arquivo: `admin/tax_rates.php`

**Linhas 70–78 — Recebimento e preparação dos dados:**

```php
$tax_description = xtc_db_prepare_input($_POST['tax_description']);

$tax_description_array = array();
foreach ($tax_description as $key => $value) {
    if (xtc_not_null($value)) {
        $tax_description_array[] = $key . '::' . $value;
    }
}

$tax_description = implode('||', $tax_description_array);
```

O sistema recebe descrições associadas aos idiomas e organiza os valores em uma estrutura separada pelo delimitador `||`.

### 5.2. Persistência no banco de dados

**Linha 84 — Associação do campo à estrutura de persistência:**

```php
'tax_description' => $tax_description,
```

**Linha 88 — Atualização do registro:**

```php
xtc_db_perform(
    TABLE_TAX_RATES,
    $sql_data_array,
    'update',
    "tax_rates_id = '" . (int)$tax_rates_id . "'"
);
```

O conteúdo recebido é persistido na tabela de alíquotas de impostos.

### 5.3. Recuperação do registro

**Linha 183:**

```php
if ((!isset($_GET['tID']) ||
    $_GET['tID'] == $rates['tax_rates_id'])
    && !isset($trInfo)
    && (substr($action, 0, 3) != 'new')) {

    $trInfo = new objectInfo($rates);
}
```

O parâmetro `tID` permite selecionar o registro que será apresentado no painel administrativo.

### 5.4. Ponto de renderização vulnerável

**Linha 276:**

```php
$contents[] = array(
    'text' => '<br />' . TEXT_INFO_RATE_DESCRIPTION .
    '<br />' . parse_multi_language_value(
        $trInfo->tax_description,
        $_SESSION['language_code']
    )
);
```

O conteúdo de `tax_description` é recuperado e concatenado diretamente à estrutura HTML.

O resultado é posteriormente enviado à renderização do painel administrativo:

```php
$box = new box;
echo $box->infoBox($heading, $contents);
```

**Linha 284.**

Não há escaping explícito na chamada de renderização apresentada.

### 5.5. Formulário de edição

**Linha 253:**

```php
$description .= xtc_draw_input_field(
    'tax_description[' . strtoupper($languages[$i]['code']) . ']',
    parse_multi_language_value(
        $trInfo->tax_description,
        $languages[$i]['code'],
        true
    ),
    'style="margin-left:2px; width:200px"'
) . '<br>';
```

O valor armazenado também é recuperado durante a edição e encaminhado ao helper `xtc_draw_input_field()`.

A proteção efetiva desse contexto depende da implementação interna desse helper.

## 6. Prova de conceito (PoC)

**Registro utilizado:**

```text
tax_rates_id = 118
```

**Campo manipulado:**

```text
tax_description
```

**Payload utilizado na reprodução:**

```html
DE::</textarea><svg onload=alert(document.domain)>
```

O payload utiliza um elemento SVG com evento `onload` para demonstrar a execução de JavaScript no navegador.

A PoC foi executada anteriormente no ambiente de laboratório, utilizando o registro identificado.

Após a reprodução, o conteúdo original do registro foi restaurado:

```text
DE::
```

## 7. Impacto

A exploração da vulnerabilidade pode permitir:

- Execução de JavaScript no navegador de usuários que visualizem o registro afetado.
- Manipulação do conteúdo apresentado na interface administrativa.
- Execução de ações em nome de usuários autenticados, dependendo das permissões e proteções existentes.
- Comprometimento da integridade da sessão administrativa em cenários nos quais os controles de segurança permitam.

A vulnerabilidade apresenta persistência porque o conteúdo é armazenado no banco de dados e apresentado posteriormente na interface.

## 8. Classificação

| Referência | Classificação |
|---|---|
| CWE-79 | Improper Neutralization of Input During Web Page Generation |
| OWASP Top 10 2021 | A03 — Injection |
| Categoria | Stored Cross-Site Scripting |
| CVSS | Pendente de avaliação |

## 9. Recomendação de correção

Recomenda-se:

1. Implementar escaping HTML contextual antes da apresentação de `tax_description`.
2. Revisar a implementação de `parse_multi_language_value()` para garantir que não seja tratada como mecanismo de sanitização sem garantia.
3. Garantir codificação adequada em todos os pontos de renderização do painel administrativo.
4. Revisar a implementação de `xtc_draw_input_field()` para garantir escaping dos valores inseridos nos atributos HTML.
5. Aplicar validação de entrada conforme o formato esperado para cada idioma.
6. Revisar outros campos multilíngues que utilizem o mesmo mecanismo de persistência e renderização.

A validação de entrada não substitui a codificação contextual de saída.

## 10. Referências

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## 11. Status da investigação

- [x] Identificação do endpoint administrativo.
- [x] Identificação dos parâmetros.
- [x] Identificação do campo `tax_description`.
- [x] Identificação do fluxo de persistência.
- [x] Identificação do ponto de renderização na linha 276.
- [x] PoC realizada anteriormente.
- [x] Registro restaurado após a reprodução, conforme histórico.
- [ ] Consolidar implementação interna de `parse_multi_language_value()`.
- [ ] Consolidar evidência visual original da PoC.
- [ ] Definir pontuação CVSS.
- [ ] Finalizar divulgação do advisory.

---

**Pesquisador:** Jaime Gama

**Organização:** RedScan Academy Research

**Área:** Segurança Ofensiva / Vulnerability Research

**Tipo de relatório:** Security Advisory
