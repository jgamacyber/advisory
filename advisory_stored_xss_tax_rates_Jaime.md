# Advisory de Segurança --- Stored Cross-Site Scripting (Stored XSS) em Tax Rates

**Identificador:** ID interno --- CVE não atribuído\
**Data de publicação:** A definir\
**Última atualização:** 12/11/2026\
**Severidade:** Em avaliação\
**CVSS:** Pendente de avaliação\
**CWE:** CWE-79 --- Improper Neutralization of Input During Web Page
Generation ('Cross-site Scripting')\
**CAPEC:** CAPEC-592 --- Stored XSS\
**Status:** Vulnerabilidade reproduzida; persistência
após nova autenticação confirmada

------------------------------------------------------------------------

## 1. Resumo executivo

Foi identificada uma vulnerabilidade de **Stored Cross-Site Scripting
(Stored XSS)** no componente administrativo `Tax Rates` do **modified
eCommerce Shopsoftware**.

A falha está associada ao campo `tax_description`, processado pelo
arquivo `/admin/tax_rates.php`.

A aplicação recebe o conteúdo fornecido pelo usuário, realiza seu
armazenamento no banco de dados e posteriormente recupera esse conteúdo
para exibição no painel administrativo. Durante a análise estática, foi
identificado que o valor recuperado é processado por
`parse_multi_language_value()`, que utiliza `decode_htmlentities()`, e
encaminhado à renderização HTML sem codificação contextual explícita no
ponto de saída analisado.

Em ambiente autorizado, foi demonstrada a execução de
JavaScript no contexto da aplicação administrativa por meio de conteúdo
armazenado no campo de descrição.

A persistência foi confirmada por testes repetidos com diferentes
payloads. Após salvar os registros, encerrar a sessão administrativa e
autenticar-se novamente, o conteúdo armazenado voltou a ser interpretado
e executado ao acessar o registro correspondente. Esse comportamento
confirma que o problema não se limita à reflexão do conteúdo na
requisição original.

O achado está confirmado na instalação de laboratório utilizada. A
identificação de versões oficiais afetadas, a validação pelo fornecedor
e a atribuição de CVE permanecem pendentes.

## 2. Produtos afetados

  -----------------------------------------------------------------------
  Produto / Componente    Versão                  Status
  ----------------------- ----------------------- -----------------------
  modified eCommerce      `3.3.0-r16825-lab`      Stored XSS reproduzido
  Shopsoftware --- Tax                            e persistência
  Rates                                           confirmada no
                                                  laboratório

  -----------------------------------------------------------------------

### Produtos não afetados

Ainda não determinados.

**Observação:** a identificação da imagem Docker utilizada não
estabelece, por si só, que todas as instalações dessa versão sejam
afetadas. É necessária validação em uma instalação oficial e
identificação precisa da versão do código.

## 3. Descrição da vulnerabilidade

A vulnerabilidade está relacionada à ausência de neutralização adequada
de conteúdo HTML na saída do campo `tax_description`.

A análise do arquivo `/admin/tax_rates.php` identificou o seguinte
fluxo:

1.  O campo `tax_description` é recebido por meio de `$_POST`.
2.  O valor é processado por `xtc_db_prepare_input()`.
3.  O conteúdo é organizado por idioma.
4.  O conteúdo é persistido na tabela `TABLE_TAX_RATES`.
5.  Posteriormente, o valor é recuperado e processado por
    `parse_multi_language_value()`.
6.  A função `decode_htmlentities()` decodifica o conteúdo.
7.  O resultado é concatenado ao HTML do painel de informações.
8.  O conteúdo é renderizado por meio das classes de apresentação
    administrativas.
    
## 3. Vulnerability Description

The vulnerability is related to the lack of proper neutralization of HTML content in the output of the `tax_description` field.

Analysis of the `/admin/tax_rates.php` file identified the following flow:

1. The `tax_description` field is received via `$_POST`.
2. The value is processed by `xtc_db_prepare_input()`.
3. The content is organized by language.
4. The content is persisted in the `TABLE_TAX_RATES` table.
5. Subsequently, the value is retrieved and processed by `parse_multi_language_value()`.
6. The `decode_htmlentities()` function decodes the content.
7. The result is concatenated into the information panel's HTML.
8. The content is rendered through the administrative presentation classes.

### Condições necessárias

-   Acesso à interface administrativa.
-   Permissão para criar ou editar taxas de imposto.
-   Possibilidade de inserir conteúdo no campo `tax_description`.
-   Acesso de um usuário à página que apresenta a descrição armazenada.

A execução ocorre quando um usuário com acesso à área administrativa
visualiza o registro que contém o conteúdo armazenado. Não foi
demonstrado que um visitante não autenticado consiga inserir o payload.

## 4. Impacto

A exploração pode permitir a execução de JavaScript no contexto de
segurança da aplicação administrativa.

Possíveis consequências, dependendo das permissões do usuário que
visualiza o conteúdo e dos controles adicionais da aplicação:

-   Manipulação da interface administrativa.
-   Apresentação de conteúdo fraudulento na interface.
-   Redirecionamento do navegador.
-   Tentativa de executar operações em nome do usuário autenticado, caso
    existam condições e controles vulneráveis.
-   Acesso a informações disponibilizadas ao contexto JavaScript da
    aplicação, respeitando as restrições de mesma origem e as proteções
    de cookies.

### Impacto sobre a confidencialidade

Pode permitir acesso a informações disponibilizadas ao contexto
JavaScript da aplicação, sujeito às restrições de mesma origem, às
proteções de cookies e aos controles implementados.

### Impacto sobre a integridade

Pode permitir manipulação da interface e potencial execução de operações
em nome do usuário autenticado, conforme os controles de autorização e
proteção contra CSRF existentes. Essas consequências adicionais não
foram demonstradas na PoC.

### Impacto sobre a disponibilidade

Pode permitir interferência na utilização da interface administrativa.
Não foi demonstrada indisponibilidade do serviço.

## 5. Classificação

### CVSS

- **Versão:** CVSS 3.1
- **Pontuação preliminar:** 4.8
- **Severidade:** Média
- **Vetor:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`

A avaliação considera que a inserção do conteúdo malicioso exige privilégios administrativos e que outro usuário administrativo precisa acessar a página afetada para que o JavaScript armazenado seja executado.

A persistência foi confirmada por meio de testes repetidos, inclusive após encerramento da sessão administrativa e novo acesso ao painel.

Os impactos de confidencialidade e integridade representam uma estimativa do potencial de exploração no contexto da vítima e ainda dependem de validação adicional. A pontuação deverá ser revisada caso os testes demonstrem impacto diferente.

##A pontuação apresentada é preliminar e está sujeita à validação final das métricas CVSS.##

### CWE

-   **CWE-79 --- Improper Neutralization of Input During Web Page
    Generation ('Cross-site Scripting').**

### CAPEC

-   **CAPEC-592 --- Stored XSS.**

## 6. Cenário de exploração

Um cenário de exploração demonstrado em laboratório ocorre da seguinte
forma:

1.  Um usuário com permissão administrativa acessa a funcionalidade
    `Tax Rates`.
2.  O usuário cria ou modifica uma taxa de imposto.
3.  Um conteúdo HTML/JavaScript é inserido no campo `tax_description`.
4.  A aplicação armazena o conteúdo no banco de dados.
5.  O registro é posteriormente acessado na interface administrativa.
6.  O conteúdo é recuperado, processado e incorporado ao HTML do painel
    de informações.
7.  O navegador interpreta e executa o JavaScript.
8.  Após encerrar a sessão administrativa e autenticar-se novamente, o
    acesso ao registro provoca novamente a execução do conteúdo
    armazenado.

O cenário foi reproduzido repetidamente em ambiente local de
laboratório, utilizando diferentes mensagens de alerta.

## 7. Evidências técnicas

### Componente afetado

``` text
/admin/tax_rates.php
Campo: tax_description
Tabela: TABLE_TAX_RATES
```

### Análise do fluxo de entrada

Arquivo: `/admin/tax_rates.php`

O conteúdo é recebido e processado:

``` php
$tax_description = xtc_db_prepare_input($_POST['tax_description']);
```

A descrição é organizada por idioma e preparada para armazenamento.

O código utiliza `xtc_db_perform()` para persistir os dados na tabela
correspondente.

### Análise da função de preparação

Arquivo: `/inc/db_functions.inc.php`

``` php
function xtc_db_prepare_input($string) {
    if (is_string($string)) {
        $string = trim(stripslashes($string));
    } elseif (is_array($string)) {
        foreach ($string as $key => $value) {
            $string[$key] = xtc_db_prepare_input($value);
        }
    }

    return $string;
}
```

A função realiza operações de preparação e remoção de espaços, mas não
aplica codificação HTML contextual.

### Análise da recuperação do conteúdo

Arquivo: `/inc/parse_multi_language_value.inc.php`

``` php
if (isset($lang_array[$lang_code])) {
    return decode_htmlentities($lang_array[$lang_code]);
}
```

O conteúdo recuperado passa por `decode_htmlentities()`.

### Ponto de saída identificado

Arquivo: `/admin/tax_rates.php`

``` php
$contents[] = array(
    'text' => '<br />' .
        TEXT_INFO_RATE_DESCRIPTION .
        '<br />' .
        parse_multi_language_value(
            $trInfo->tax_description,
            $_SESSION['language_code']
        )
);
```

O resultado é encaminhado para a renderização:

``` php
echo $box->infoBox($heading, $contents);
```

A implementação de `infoBox()` utiliza `createBlock()` para montar o
HTML. A análise da classe `tableBox` mostrou que o conteúdo do campo
`text` é concatenado diretamente à estrutura HTML.

### Payload de demonstração

A entrada foi realizada pela interface administrativa, no campo
`tax_description`.

``` html
<script>alert('Stored XSS - Tax Rates - Jaime')</script>
```

### Resultado observado

O navegador exibiu uma caixa de diálogo com a mensagem definida no
payload.

Foram utilizados diferentes textos de alerta em testes repetidos. A
execução foi reproduzida após salvar o registro, sair da área
administrativa, autenticar-se novamente e acessar o mesmo registro.

**Evidência:** execução de JavaScript persistente no contexto da
aplicação em `127.0.0.1:8081`.

## 8. Prova de conceito

A prova de conceito utiliza um payload mínimo e não realiza acesso a
informações sensíveis.

``` html
<script>alert('Stored XSS - Tax Rates - Jaime')</script>
```

### Resultado esperado

Ao acessar o registro que contém a descrição armazenada, o navegador
executa o JavaScript e apresenta a caixa de diálogo com a mensagem
definida no payload.

### Persistência confirmada

A persistência foi validada por meio dos seguintes procedimentos:

1.  Inserção e salvamento do payload no campo `tax_description`.
2.  Acesso ao registro e observação da execução do alerta.
3.  Encerramento da sessão administrativa.
4.  Nova autenticação no painel.
5.  Acesso ao mesmo registro.
6.  Nova execução do conteúdo armazenado.
7.  Repetição do procedimento com diferentes mensagens de alerta.


## 9. Passos para reprodução

1.  Disponibilizar uma instalação do modified eCommerce Shopsoftware no
    ambiente de laboratório.
2.  Acessar a interface administrativa.
3.  Navegar até `Zones/Tax` e selecionar `Tax Rates`.
4.  Criar ou editar uma taxa de imposto.
5.  Inserir o payload de demonstração no campo `Tax Description`.
6.  Salvar a alteração.
7.  Selecionar a taxa correspondente na listagem.
8.  Observar a execução do JavaScript no painel lateral de informações.
9.  Encerrar a sessão administrativa.
10. Autenticar-se novamente.
11. Selecionar o mesmo registro e verificar que o JavaScript é executado
    novamente.

## 10. Mitigação

Até que uma correção definitiva seja disponibilizada, recomenda-se:

-   Restringir o acesso administrativo à funcionalidade `Tax Rates`.
-   Limitar a edição de descrições de taxas a usuários autorizados.
-   Revisar descrições já armazenadas no banco de dados.
-   Monitorar alterações no campo `tax_description`.
-   Evitar a renderização direta de conteúdo armazenado como HTML.

As medidas temporárias reduzem o risco, mas não substituem a correção da
causa raiz.

## 11. Correção

A versão corrigida ainda não foi identificada.

### Alteração recomendada

Aplicar codificação HTML contextual no momento da saída do conteúdo
armazenado.

Para conteúdo exibido como texto HTML, utilizar uma função equivalente
a:

``` php
htmlspecialchars(
    $value,
    ENT_QUOTES | ENT_SUBSTITUTE,
    'UTF-8'
);
```

A codificação deve ocorrer no ponto de saída, preservando o tratamento
correto dos dados armazenados e evitando decodificação seguida de
renderização não segura.

Também é recomendável revisar outros campos administrativos que utilizem
`parse_multi_language_value()` e sejam incorporados diretamente ao HTML.

A correção deve ser validada com testes de regressão para conteúdo com
caracteres especiais, múltiplos idiomas e entradas HTML.

## 12. Detecção e indicadores

Possíveis indicadores de exploração:

-   Alterações suspeitas no campo `tax_description`.
-   Conteúdo armazenado contendo tags HTML ou JavaScript.
-   Descrições contendo elementos `<script>`.
-   Tentativas de inserção de atributos HTML com manipuladores de
    eventos.
-   Execução inesperada de JavaScript ao abrir a página administrativa.

### Exemplo de busca no código

``` bash
grep -nE \
'tax_description|parse_multi_language_value|infoBox' \
/var/www/html/admin/tax_rates.php
```

A análise de logs deve ser complementada pela inspeção dos registros
armazenados no banco de dados.

## 13. Timeline de divulgação

  -----------------------------------------------------------------------
  Data                                Evento
  ----------------------------------- -----------------------------------
  11/11/2026                          Análise estática de
                                      `admin/tax_rates.php`

  11/11/2026                          Identificação do fluxo de entrada e
                                      persistência

  11/11/2026                          Identificação do ponto de saída
                                      HTML

  11/11/2026                          Primeira demonstração de execução
                                      de JavaScript no laboratório

  12/11/2026                          Testes repetidos com diferentes
                                      payloads

  12/11/2026                          Confirmação de persistência após
                                      encerramento e nova autenticação

 ## Pendente                            Validação em instalação oficial e
                                      identificação do escopo de versões

  Pendente                            Notificação ao fornecedor

  Pendente                            Validação pelo fornecedor

  Pendente                            Solicitação ou atribuição de CVE

  Pendente                            Publicação do advisory ###
  -----------------------------------------------------------------------

## 14. Comunicação com o fornecedor

-   **Fornecedor:** modified eCommerce Shopsoftware.
-   **Canal utilizado:** Ainda não definido.
-   **Data da primeira notificação:** Pendente.
-   **Status da resposta:** Não notificado.
-   **Posicionamento do fornecedor:** Não disponível.

## 15. Créditos

A vulnerabilidade foi identificada e reproduzida em ambiente de
laboratório por:

-   **Pesquisador:** Jaime de Melo Gama da Silva.
-   **Organização:** Redscan academy research team.
-   **Contato:** A definir.
-   **Perfil:** A definir.

## 16. Referências

-   Código-fonte: `admin/tax_rates.php`.
-   Código-fonte: `inc/db_functions.inc.php`.
-   Código-fonte: `inc/parse_multi_language_value.inc.php`.
-   Código-fonte: `admin/includes/classes/box.php`.
-   Código-fonte: `includes/classes/boxes.php`.
-   CWE-79: <https://cwe.mitre.org/data/definitions/79.html>
-   CAPEC-592: <https://capec.mitre.org/data/definitions/592.html>
-   CVE: Não atribuído.

## 17. Histórico de revisões

  -----------------------------------------------------------------------
  Versão                  Data                    Alteração
  ----------------------- ----------------------- -----------------------
  0.1                     11/11/2026              Rascunho inicial
                                                  baseado na análise
                                                  estática e na primeira
                                                  PoC

  0.2                     12/11/2026              Inclusão dos testes
                                                  repetidos e confirmação
                                                  da persistência após
                                                  nova autenticação
  -----------------------------------------------------------------------

## 18. Aviso legal

Este advisory é elaborado com finalidade educacional, defensiva e de
melhoria da segurança.

As informações apresentadas foram obtidas em ambiente de laboratório
autorizado. A prova de conceito foi limitada à demonstração controlada
de execução persistente de JavaScript.

O autor não incentiva o uso destas informações para acesso não
autorizado, interrupção de serviços, violação de privacidade ou qualquer
atividade ilegal.

A utilização das informações deste documento é de responsabilidade
exclusiva do leitor.

## 19. Contato

Para correções, atualizações ou informações adicionais:

-   **E-mail:** A definir.
-   **Site:** A definir.
-   **Chave PGP:** A definir.

------------------------------------------------------------------------

**Nota sobre o estado do achado:** este documento registra uma
vulnerabilidade Stored XSS reproduzida em laboratório, incluindo
confirmação de persistência após encerramento da sessão e nova
autenticação. O achado ainda não possui CVE atribuído. A validação em
uma versão oficial, a determinação do intervalo de versões afetadas e a
avaliação do fornecedor permanecem pendentes.
