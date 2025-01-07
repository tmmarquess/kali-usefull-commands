## Script para adaptar as estas anotações com os ips necessários
```python
from jinja2 import Template


data = {
	'vm_group_1': {
		'client_75': '192.168.204.75',
		'files_04': '192.168.204.73'
	},
	'vm_group_2': {
		'cliente_75': '192.168.204.75'	
		'web_04': '192.168.204.72'
	}
}

def load_template(path):
    with open(path, 'r', encoding='utf-8') as f:
        return Template(f.read())


def save_note(path, output):
    with open(path, 'w', encoding="utf-8") as f:
        f.write(output)


def main():
    save_note('notas.md', load_template('notes-template.md').render(**data))


main()
```


# Resumo do teórico
### Resumo: Aprendendo a enumerar o Active Directory (AD) com PowerShell e .NET

#### **Ferramentas e Contexto**:

- **Cmdlets PowerShell** como `Get-ADUser` são úteis, mas exigem privilégios administrativos e o RSAT instalado (geralmente não disponível em clientes de domínio).
- Alternativa: desenvolver um script PowerShell usando **classes .NET**, que funciona com privilégios básicos e reflete operações comuns no AD.

---

#### **Protocolo LDAP e sua Importância**:

- O **LDAP** (Lightweight Directory Access Protocol) é o canal de comunicação usado para consultar objetos no AD, como usuários ou grupos.
- No AD, o LDAP é implementado através de um provedor chamado **ADSI (Active Directory Service Interfaces)**.

##### **Formato de um Caminho LDAP**:

`LDAP://HostName[:PortNumber][/DistinguishedName]`

1. **HostName**: Nome do domínio, endereço IP ou nome do DC (e.g., `corp.com`).
2. **PortNumber**: Opcional, geralmente padrão (389 para conexões não SSL, 636 para SSL).
3. **DistinguishedName (DN)**: Identifica objetos de forma única no AD, e segue a hierarquia LDAP.

**Exemplo de DN**:  
`CN=Stephanie,CN=Users,DC=corp,DC=com`

- **DC**: Domain Component (representa o topo da árvore LDAP, e.g., `corp.com`).
- **CN**: Common Name (identifica o objeto ou contêiner, e.g., `Users` ou `Stephanie`).

---

#### **Encontrando o Controlador de Domínio Primário (PDC)**:

- Para obter informações precisas, o PDC (Primary Domain Controller) deve ser localizado. Apenas um DC em um domínio possui o papel de **PdcRoleOwner**.
- O namespace .NET **`System.DirectoryServices.ActiveDirectory`** oferece a **`Domain Class`**, que contém propriedades úteis como `PdcRoleOwner`.

**Método relevante**:

- `Domain.GetCurrentDomain()`: Retorna o domínio atual do usuário logado, permitindo identificar o PDC.

---

#### **Próximos Passos no Script**:

1. Obter o **hostname** do PDC.
2. Construir o caminho LDAP apropriado.
3. Executar consultas para enumerar objetos no domínio.

---
## Tabela com siglas significados e descrições

| **Sigla** | **Significado**                       | **Descrição**                                                                                                                                              |
| --------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AD**    | Active Directory                      | Serviço de diretório da Microsoft que armazena informações sobre objetos na rede (usuários, grupos, computadores) e facilita o gerenciamento centralizado. |
| **LDAP**  | Lightweight Directory Access Protocol | Protocolo usado para consultar e modificar diretórios, incluindo o Active Directory.                                                                       |
| **DC**    | Domain Controller                     | Servidor que gerencia o domínio do Active Directory e autentica usuários e computadores na rede.                                                           |
| **DN**    | Distinguished Name                    | Nome exclusivo que identifica um objeto no Active Directory.                                                                                               |
| **CN**    | Common Name                           | Parte do DN que identifica o nome de um objeto (e.g., `CN=Users` para o contêiner de usuários).                                                            |
| **OU**    | Organizational Unit                   | Contêiner lógico usado para organizar objetos dentro de um domínio no AD.                                                                                  |
| **PDC**   | Primary Domain Controller             | Controlador de domínio principal que contém informações atualizadas sobre o domínio e desempenha um papel especial em réplicas.                            |
| **FSMO**  | Flexible Single Master Operations     | Conjunto de cinco funções especializadas no AD para evitar conflitos na replicação e garantir operações consistentes.                                      |
| **RSAT**  | Remote Server Administration Tools    | Ferramentas para gerenciar remotamente servidores, incluindo controladores de domínio no AD.                                                               |
| **SID**   | Security Identifier                   | Identificador exclusivo usado para objetos no AD para fins de segurança e permissões.                                                                      |
| **RID**   | Relative Identifier                   | Parte do SID que identifica exclusivamente objetos dentro de um domínio.                                                                                   |
| **GPO**   | Group Policy Object                   | Objeto usado para aplicar configurações de políticas (segurança, software, etc.) a usuários e computadores no domínio.                                     |
| **SAM**   | Security Accounts Manager             | Banco de dados usado para armazenar contas de usuários e grupos em máquinas locais e no AD.                                                                |
| **RDN**   | Relative Distinguished Name           | Parte do DN que identifica um objeto em relação ao seu contêiner pai.                                                                                      |
| **UPN**   | User Principal Name                   | Nome de login no formato de e-mail (e.g., `usuario@dominio.com`) usado para autenticação no AD.                                                            |
| **SPN**   | Service Principal Name                | Identificador exclusivo de um serviço para suporte à autenticação Kerberos no AD.                                                                          |
| **GC**    | Global Catalog                        | Funcionalidade do AD que armazena um subconjunto de objetos e atributos para facilitar consultas em domínios diferentes.                                   |
| **OU**    | Organizational Unit                   | Contêiner lógico usado para organizar objetos dentro de um domínio no AD.                                                                                  |
| **DNS**   | Domain Name System                    | Sistema usado para resolver nomes de domínio (e.g., `corp.com`) em endereços IP.                                                                           |
| **KDC**   | Key Distribution Center               | Componente do AD responsável pela emissão de tickets de autenticação Kerberos.                                                                             |
| **NTLM**  | NT LAN Manager                        | Protocolo de autenticação mais antigo usado pelo Windows, substituído pelo Kerberos no AD moderno.                                                         |
| **RPC**   | Remote Procedure Call                 | Protocolo usado para comunicação entre clientes e servidores no AD.                                                                                        |
| **ADSI**  | Active Directory Service Interfaces   | Conjunto de APIs baseadas em COM para interação com o AD usando LDAP.                                                                                      |

# Dicas opcionais mas que podem ser muito úteis 
é possível utilizar scripts c# em um terminal interativo para realizar interações mais complexas com o .net Framework legado. Esta é uma boa alternativa caso seja necessário fazer construções mais complexas como criação de funções e métodos, condicionais e estruturas de repetição que não é tão amigável no powershell.
## A seguir uma útil para instalar o c# interativo no host do cliente sem a necessidade de permissão de administrador
1. Baixe via terminal o script de instalação do dotnet CLI
```
Invoke-WebRequest -Uri https://dotnet.microsoft.com/download/dotnet/scripts/v1/dotnet-install.ps1 -OutFile dotnet-install.ps1
```

2. Verifique se o powershell possui alguma política restringindo a execução de scripts ps1 `Get-ExecutionPolicy` se a saída deste comando for **Restricted** então é necessário realizar a modificação desta política para **RemoteSigned**, veja o passo 4 para saber como prosseguir
3. Rode o comando `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` que vai remover a restrição de exeução de scripts ps1 no powershell
4. Rode o comando `.\dotnet-install.ps1 -InstallDir $HOME\.dotnet -Channel STS` para instalar o dotnet cli no client.
5. Adicione o caminho do dotnet as variáveis de ambientes permanentes `[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$HOME\.dotnet", "User")
6. A esta altura você já vai poder rodar o comando `dotnet --version` para verificar se está corretamente instalado
7. Vamos instalar a ferramenta de terminal interativo que nos possibilitará rodar scripts c# de forma similar ao terminal do python `dotnet tool install -g dotnet-script`
8. Vamos testar se o terminal interativo esta funcionando `dotnet script`, isso deve abrir o terminal interativo, agora vamos ver se conseguimos rodar comandos c# `Console.WriteLine("This is similar to print from python")`, a mensagem *"This is similar to print from python"* deverá ser exibida.

## A seguir como invocar o .net framework usando scripts python como uma alternativa aos  scripts powershell
Para realizar esta tarefa vamos precisar instalar no host do cliente o IronPython que é totalmente compatível com o .net Framework 4.8, mas para tal precisamos instalar o python no cliente para que possamos adicionar o IronPython ao ambiente do python

```
# instala o python3.10 pelo winget
winget install -e --id Python.Python.3.10 --accept-package-agreements --accept-source-agreements # infelizmente esse comando faz ruído

# recarregue as variáveis de ambiente para obter o python configurado
$env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')

# verifique se o python esta instalado
python --version
pip --version
```

# Comandos úteis

#commands/linux/xfreedp
-  Usuário fornecido é **stephanie**, domínio **corp.com**, senha **LegmanTeamBenzoin!!**
```
xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_1.client_75 }} /p:"LegmanTeamBenzoin\!\!"
```

- Usando o **net.ext** para enumerar domínios, grupos e usuários de domínio
#commands/windows/net
```
net user /domain
```

- Inspecionando usuário com net
#commands/windows/net 
```
net user jeffadmin /domain
```

- enumerando grupos de domínio
#commands/windows/net 
```
net group /domain
```

- enumerando membros de grupos
#commands/windows/net 
```
net group "Sales Department" /domain
```

## Lab 21.2.1 Active Directory - Enumeração usando ferramentas legadas do windows
![[Pasted image 20241216184220.png]]

2. Inicie o VM Group 1 e faça login no CLIENT75 como _stephanie_ . Use **net.exe** para enumerar o domínio _corp.com_ . Qual usuário é membro do grupo _Management Department ?_ **dica:** Certifique-se de especificar /domain no comando, pois estamos consultando o domínio.
	1. rode o comando `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_1.client_75 }} /p:"LegmanTeamBenzoin\!\!"` para se connectar
	2. rode o comando `net group /domain` para listar os grupos
	3. rode o comando `net group "Management Department" /domain` para identificar que quem esta neste grupo é o **jen**

4. Inicie o VM Group 2 e faça login no CLIENT75 como _stephanie_ . Use **net.exe** para enumerar os usuários e grupos no domínio _corp.com_ modificado para obter o sinalizador. **dica:** Certifique-se de especificar /domain no comando, pois estamos consultando o domínio.
	1. rode o comando `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_2.client_75 }} /p:"LegmanTeamBenzoin\!\!"` para se connectar
	2. rode o comando `net group /domain | findstr "OS"` e terá a flag como retorno 

## Lab 21.2.2. Enumerando o Active Directory usando o PowerShell e as classes .NET

### resolução dos labs
1. Inicie o VM Group 1 e repita as etapas descritas nesta seção para criar o script. Use o script para obter dinamicamente o caminho LDAP para o domínio _corp.com_ . Qual propriedade no _objeto de domínio_ mostra o controlador de domínio primário para o domínio?
```
PdcRoleOwner
```
2. Qual conjunto de interfaces COM nos fornece um provedor LDAP que podemos usar para comunicação com o Active Directory?
	 - O conjunto de interfaces **COM** que fornece um provedor **LDAP** para comunicação com o **Active Directory** é o **Active Directory Service Interfaces (ADSI)**. O ADSI utiliza o provedor LDAP para se comunicar com o Active Directory e outros serviços de diretório que suportam o protocolo LDAP.
```
ADSI
```

## Lab 21.2.3. Adicionando funcionalidade de pesquisa ao nosso script

### Comandos úteis
- Desativa as políticas de execução de scripts ps1
#commands/windows/powershell
```
powershell -ep bypass
```

- Função **lab 21.2.3/2**
```
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()
}
```

#commands/windows/powershell
- Importar módulos no powershell `Import-Module .\function.ps1`

- exemplos de utilização da função criada
```
# Passando filtros simples
LDAPSearch -LDAPQuery "(samAccountType=805306368)"
LDAPSearch -LDAPQuery "(objectclass=group)"
```

-  utilizando em loops
```
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
	$group.properties | select {$_.cn}, {$_.member}
}
```

```
# filtrando por departamento
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member

# enumerando o departamento de desenvolvimento
$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
$group.properties.member

# enumerando o management department
$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"
$group.properties.member

# obter informações do usuário
$user = [ADSI]"LDAP://CN=michelle,CN=Users,DC=corp,DC=com" 

# comando para obter a flag
([ADSI]"LDAP://CN=michelle,CN=Users,DC=corp,DC=com").properties | findstr "OS"
```

### Resolução dos labs
1. Inicie o VM Group 1 e faça login no CLIENT75 como _stephanie_ . Siga as etapas descritas nesta seção para adicionar a funcionalidade de pesquisa ao script. Encapsule a funcionalidade do script em uma função e repita o processo de enumeração. Qual classe .NET faz a pesquisa no Active Directory?
```
DirectorySearcher
```
2. Inicie o VM Group 2 e faça login no CLIENT75 como _stephanie_ . Use o script PowerShell recém-desenvolvido para enumerar os grupos de domínio, começando com _Service Personnel_ . Desvende os grupos aninhados e, em seguida, enumere os atributos para o último membro de usuário direto dos grupos aninhados para obter o sinalizador.
	**DICA**
	1. O script a ser usado foi extraído da listagem 26.
	2. Consultar o objeto de categoria de grupo e fornecer o cn.
	3. Liste as propriedades e encontre o sinalizador na descrição do usuário correto depois de enumerar todos os membros do grupo aninhado.
	**Steps**
	1.  Conecte-se como _stephanie_ `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_2.client_75 }} /p:"LegmanTeamBenzoin\!\!"`
	2. *(opcional)* No power shell rode o comando que da bypass na execução de scripts ps1 `powershell -ep bypass`
	3. *(opcional)* vamos criar uma função para melhor reaproveitamento da enumeração, no power shell digite `notepad function.ps1`, cole a função **lab 21.2.3/2**, salve o script com o `Ctrl + s` e feche o notepad
	4. *(opcional)* import a função como modulo `Import-Module .\function.ps1`
	5. *(opcional)* rode o comando `(LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Service Personnel))).properties.member"` para identificar quem é membro deste grupo, e faça isso alternando a propriedade cn do comando colocando o grupo membro até chegar no usuário **michelle**
	6. finalmente sabemos que o usuário é michelle, rode o comando a seguir para opter as flags `([ADSI]"LDAP://CN=michelle,CN=Users,DC=corp,DC=com").properties | findstr "OS"`

## 21.2.4. Enumeração de AD com PowerView
### Comandos úteis
- importando o PowerView que esta instalado no **CLIENTE75** no path **C:\Tools** `Import-Module .\PowerView.ps1`
- informações básicas do domínio `Get-NetDomain`
- obtendo uma lista de todos os usuários no domínio `Get-NetUser`
- realizando filtros indicando os atributos desejados no select `Get-NetUser | select cn`
- Verificando se uma senha foi atualizada e quando o usuário logou pela última vez `Get-NetUser | select cn,pwdlastset,lastlogon`
- enumerando grupos `Get-NetGroup | select cn
- verificando membros de grupos `Get-NetGroup "Sales Department" | select member`

### resolução dos labs
1. Inicie o VM Group 1 e faça login no CLIENT75 como _stephanie_ . Importe o script do PowerView para a memória e repita as etapas de enumeração descritas nesta seção. Qual comando podemos usar com o PowerView para listar os grupos de domínio?
	1. ative a vm e reponda **Get-NetGroup**

2. Inicie o VM Group 2 e faça login no CLIENT75 como _stephanie_ . Use o PowerView para enumerar o domínio _corp.com_ modificado . Qual novo usuário faz parte do grupo _Domain Admins ?_
	1. entre como _stephanie_ `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_1.client_75 }} /p:"LegmanTeamBenzoin\!\!"`
	2. abra o powershell e vá entre no diretório **C:\Tools\**
	3. rode o comando `powershell -ep bypass`
	4. import o PowerView.ps1 `Import-Module .\PowerView.ps1`
	5. Rode o comando `Get-NetGroup "Domain Admins" | select member`, a saída retornará alguns usuários e o que funcionou foi o usuário **nathalie**

## 21.3.1. Enumerando sistemas operacionais
### Comandos úteis
- usando o PowerView esse comando enumera os objetos de computador no domínio `Get-NetComputer`
- filtrando a saida com select para obter os sistemas operacionais e os dns de nome de hosts `Get-NetComputer | select operatingsystem,dnshostname`

### Resolução dos laboratórios
1. Inicie o VM Group 1 e faça login no CLIENT75 como _stephanie_ . Repita as etapas de enumeração do PowerView conforme descrito nesta seção. Qual é o _DistinguishedName_ para a máquina WEB04?
	1. entre como _stephanie_ `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_1.client_75 }} /p:"LegmanTeamBenzoin\!\!"`
	2. abra o powershell e vá entre no diretório **C:\Tools\
	3. rode o comando `powershell -ep bypass`
	4. import o PowerView.ps1 `Import-Module .\PowerView.ps1`
	5. rode o comando abaixo `Get-NetComputer | select operatingsystem,dnshostname,distinguishedname | findstr "web04.corp.com"`, o valor do distinguishedname é **CN=web04,CN=Computers,DC=corp,DC=com**

2. Continue enumerando os sistemas operacionais no VM Group 1. Qual é a versão exata do sistema operacional para _FILES04_ ? Certifique-se de fornecer o número da versão principal e secundária na resposta.
	1. entre como _stephanie_ `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_1.client_75 }} /p:"LegmanTeamBenzoin\!\!"`
	2. abra o powershell e vá entre no diretório **C:\Tools\
	3. rode o comando `powershell -ep bypass`
	4. import o PowerView.ps1 `Import-Module .\PowerView.ps1`
	5. rode o comando abaixo `Get-NetComputer | select operatingsystemversion,dnshostname | findstr "FILES04.corp.com"`, o valor é **10.0 (20348)**

3. Inicie o VM Group 2 e faça login no _CLIENT75_ como _stephanie_ . Use o PowerView para enumerar os sistemas operacionais no domínio _corp.com_ modificado para obter o sinalizador.
	1. entre como _stephanie_ `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_2.client_75 }} /p:"LegmanTeamBenzoin\!\!"`
	2. rode o comando `powershell -ep bypass`
	3. import o PowerView.ps1 `Import-Module C:\Tools\PowerView.ps1`
	4. rode o comando abaixo `Get-NetComputer | select operatingsystem,dnshostname,distinguishedname | findstr "OS"`, o valor da flag deverá ser listada entre os sistemas operacionais

## 21.3.2. Obtendo uma visão geral - Permissões e usuários conectados

### comandos úteis
- Procurar máquinas que o usuário local pode ser acesso como administrador `Find-LocalAdminAccess`
- Verificar qual usuário esta logado em qual computador, esse comandos também indica se o usuário possui privilégios administrativos `Get-NetSession -ComputerName files04 -Verbose`
- Alternativa as limitações de acesso privilegiado do PowerView para enumerar usuários logados `.\PsLoggedon.exe \\files04`

### Resolução dos laboratórios
1. Em qual chave de registro _o NetSessionEnum_ confia para descobrir sessões conectadas? R = **SrvsvcSessionInfo**
2. Inicie o VM Group 1 e faça login no CLIENT75 como _stephanie_ . Repita as etapas de enumeração descritas nesta seção para encontrar as sessões conectadas. Qual serviço deve ser habilitado na máquina remota para que o PsLoggedOn possa enumerar sessões? R = **Remote Registry**
3. Inicie o VM Group 2 e faça login no CLIENT75 como _stephanie_ . Descubra em qual nova máquina _stephanie_ tem privilégios administrativos, então faça login nessa máquina e obtenha o sinalizador do Administrator Desktop.
	1. *(opicional)* entre como _stephanie_ `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_2.client_75 }} /p:"LegmanTeamBenzoin\!\!"`
	2. *(opicional)* rode o comando `powershell -ep bypass`
	3. *(opicional)* importe o PowerView.ps1 `Import-Module C:\Tools\PowerView.ps1`
	4. *(opicional)* Ao rodar o comando `Find-LocalAdminAccess` descobrimos que o novo servidor que a stephanie possui acesso como administrador é o **web04**, e ela possui acesso remoto a este host, vamos fechar esta máquina virtual e entrar em **web04**
	5. entre como _stephanie_ `xfreerdp /u:stephanie /d:corp.com /v:{{ vm_group_2.web_04 }} /p:"LegmanTeamBenzoin\!\!"`
	6. usando o windows explorer vamos entrar na pastas **C:\Users\Administrator\Desktop**, uma caixa de diálogo deve aparecer perguntando se deseja entrar na pasta como administrador, click em ok para continuar
	7. a flag deve estar no arquivo de texto **proof**

## 21.3.3. Enumeração por meio de nomes principais de serviço
### comandos úteis
- lista objetos de serviços SPN no AD `setspn -L iis_service` (este comando foi executado na pasta **C:\Tools**)
- outra forma de enumerar SPNs com PowerView `Get-NetUser -SPN | select samaccountname,serviceprincipalname`
- tenta identificar os ips dos serviços identificados usando o nslookup `nslookup.exe web04.corp.com`

### Resolução dos laboratórios
1. Inicie o VM Group 1 e faça login no CLIENT75 como _stephanie_ . Repita as etapas de enumeração descritas nesta seção para enumerar a Service Account. Qual é o nome do identificador de serviço exclusivo usado para associar a um serviço específico no Active Directory? R = **SPN**

## 21.3.4. Enumerando permissões de objetos
### Comandos úteis
- lista as permissões de um usuário na ACL `Get-ObjectAcl -Identity stephanie`, atentar para os valores dos campos **ObjectSID**, **ActiveDirectoryRights** e **SecurityIdentifier**
- usando o PowerView podemos converter o valor ObjectSID de um objeto para um nome legível `Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104`, este comando retornará **CORP\stephanie**
- usando o PowerView para converter o **SecurityIdentifier** `Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553`, valor retornado **CORP\RAS and IAS Servers**
- Obtendo uma lista comas as permissões **SecirityIdentifier** e **ActiveDirectoryRights** de cada usuário no _"Management Department"_ filtrando pela permissão mais alta que é o **GenericAll** `Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
- Convertendo uma lista de SIDs em nomes legíveis `"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName`
- Aproveitando as permissões **GenericAll** da _stephanie_ para adicioná-la no grupo _"Management Department"_ `net group "Management Department" stephanie /add /domain`
- Verificando membros de grupos específicos com o PowerView `Get-NetGroup "Management Department" | select member`
- Remover um usuário de um grupo `net group "Management Department" stephanie /del /domain`

```
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18,S-1-5-21-1987370270-658905905-1781884369-519" | convert-sidtoname
```

### Resolução dos laboratórios
1. Inicie o VM Group 1 e faça login no CLIENT75 como _stephanie_ . Repita as etapas de enumeração descritas nesta seção para entender as permissões do objeto. Que tipo de entradas compõem uma ACL? R = **ACE**
2. Qual é a ACL mais poderosa que podemos ter em um objeto no Active Directory? R = **GenericAll**

## 21.3.5. Enumerando compartilhamentos de domínio
### Comandos úteis
- Usando o PowerView para listar compartilhamento de domínios `Find-DomainShare`
- listando o SYSVOL que é um compartilhamento do próprio controlador de domínio `ls \\dc1.corp.com\sysvol\corp.com\`
- comando do kali para descriptografar senhas armazenadas no GPP `gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"`, a saída deste comando revela a senha `P@$$w0rd` do **dc1.corp.com**
- possível senha de email para stephanie _HenchmanPutridBonbon11_ 
- stript para enumerar itens compartilhados entre dominios
```
# lista de domínios compartilhados
$Shares = @(
    "\\DC1.corp.com\NETLOGON",
    "\\web04.corp.com\backup",
    "\\FILES04.corp.com\docshare",
    "\\client75.corp.com\sharing"
)

# loop para procurar arquivos e diretórios recursivamente, vai gerar um erro em domínios que não tem permissão de acesso
foreach ($Share in $Shares) {
    Write-Host "Accessing $Share"
    Get-ChildItem -Path $Share -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host $_.FullName
    }
}
```

### Resolução dos laboratórios
1. Inicie o VM Group 1 e faça login no CLIENT75 como _stephanie_ . Repita as etapas de enumeração descritas nesta seção e visualize as informações nos compartilhamentos acessíveis. Qual é o nome do host do servidor que compartilha a pasta **SYSVOL** no domínio _corp.com ?_ R = **dc1.corp.com**
2. Inicie o VM Group 2 e faça login no CLIENT75 como _stephanie_ . Use o PowerView para localizar os compartilhamentos no domínio _corp.com_ modificado e enumere-os para obter o sinalizador.
#### não conseguir resolver esta

## 21.4.1. Coletando dados com SharpHound
### Pre-setup

1. Faça o download do SharpHound no kali
```
wget -O SharpHound.zip https://github.com/SpecterOps/SharpHound/releases/download/v2.5.9/SharpHound-v2.5.9.zip
```

2. Extraia o SharpHound.zip
```
mkdir SharpHound && unzip SharpHound.zip -d SharpHound
```

3. Suba um servidor para que o SharpHound.ps1 fique acessível para download na máquina alvo
```
python3 -m http.server 80
```

4. Instalando e configurando o bloodhound no kali
```
sudo apt install bloodhound
```

5. inicie o banco de dados neo4j, entre no navegador **localhost:7474** efetue o login usando **neo4j** no usuário e senha, depois modifique a senha
```
sudo neo4j start
```

6. agora quando quiser é só iniciar o bloodhound `bloodhound`

### Comandos úteis
- importa o módulo  `Import-Module .\Sharphound.ps1`
- obtém um manual `Get-Help Invoke-BloodHound`
- coleta todos os dados `Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"`
