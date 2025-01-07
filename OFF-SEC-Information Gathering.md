
# Teoria
-----
**Objetivos de Aprendizagem:**
- Compreender as etapas de um Teste de Penetração
- Aprender o papel da Coleta de Informações em cada etapa
- Entender as diferenças entre Coleta de Informações Ativa e Passiva


## Etapas Típicas de um Teste de Penetração:
### 1. Definição do Escopo 
A definição de escopo em um teste de penetração (pentest) é uma etapa crucial que determina os limites e as condições do teste. Aqui estão os pontos principais:
1. **Identificação de Alvos**: Especificar quais IPs, hosts e aplicações serão testados.
2. **Exclusões**: Definir claramente quais partes do sistema são consideradas fora do escopo e não devem ser testadas.
3. **Acordo com o Cliente**: Estabelecer um acordo sobre o escopo e o cronograma do teste com o cliente.
4. **Objetivos do Teste**: Determinar os objetivos principais do teste, como identificar vulnerabilidades específicas ou testar a resposta a incidentes.
5. **Regras de Engajamento**: Definir como o teste será conduzido, incluindo métodos de teste permitidos e qualquer limitação operacional.

A definição de escopo garante que o pentest seja focado e eficaz, evitando impactos não planejados e respeitando as limitações acordadas.

### 2. Coleta de Informações
### 3. Detecção de Vulnerabilidades

A conquista de acesso inicial (Initial Foothold) em um teste de penetração refere-se ao estágio em que o testador (ou atacante) consegue ganhar acesso ao sistema alvo pela primeira vez. Isso é essencial porque a partir desse ponto é possível explorar ainda mais o ambiente. Aqui estão alguns detalhes:

1. **Métodos Comuns**: Usar exploits conhecidos, técnicas de engenharia social, ataques de phishing, ou explorar vulnerabilidades de software ou rede.
2. **Objetivo**: Obter acesso a uma conta de usuário ou a um sistema que permita ao testador realizar ações adicionais, como escalar privilégios ou movimentar-se lateralmente dentro da rede.
3. **Ferramentas**: Utilização de ferramentas específicas de ataque, como metasploit, scripts personalizados ou ferramentas de automação de exploits.

Conseguir o acesso inicial é um marco crítico em qualquer pentest, pois permite ao testador avançar para as próximas etapas de exploração e avaliação de segurança. Se tiver mais dúvidas ou precisar de detalhes adicionais, sinta-se à vontade para perguntar!
	
### 4. Conquista de Acesso Inicial

A conquista de acesso inicial (Initial Foothold) em um teste de penetração refere-se ao estágio em que o testador (ou atacante) consegue ganhar acesso ao sistema alvo pela primeira vez. Isso é essencial porque a partir desse ponto é possível explorar ainda mais o ambiente. Aqui estão alguns detalhes:

1. **Métodos Comuns**: Usar exploits conhecidos, técnicas de engenharia social, ataques de phishing, ou explorar vulnerabilidades de software ou rede.
2. **Objetivo**: Obter acesso a uma conta de usuário ou a um sistema que permita ao testador realizar ações adicionais, como escalar privilégios ou movimentar-se lateralmente dentro da rede.
3. **Ferramentas**: Utilização de ferramentas específicas de ataque, como metasploit, scripts personalizados ou ferramentas de automação de exploits.

Conseguir o acesso inicial é um marco crítico em qualquer pentest, pois permite ao testador avançar para as próximas etapas de exploração e avaliação de segurança. Se tiver mais dúvidas ou precisar de detalhes adicionais, sinta-se à vontade para perguntar!
### 5. Escalonamento de Privilégios
### 6.  Movimento Lateral

O **movimento lateral** em um teste de penetração refere-se às ações que um atacante realiza após obter um acesso inicial a um sistema ou rede. O objetivo é explorar outros sistemas e recursos dentro do mesmo ambiente, aumentando o alcance e o impacto do ataque. Aqui estão alguns detalhes:

1. **Exploração de Vulnerabilidades**: Uma vez dentro da rede, o atacante procura por outras vulnerabilidades em diferentes sistemas que podem ser exploradas para ganhar acesso adicional.
2. **Escalonamento de Privilégios**: O atacante pode tentar aumentar seus privilégios em diferentes sistemas, passando de um usuário normal para um administrador, por exemplo.
3. **Coleta de Credenciais**: O atacante pode procurar por credenciais adicionais (senhas, chaves) que podem ser usadas para acessar outros sistemas.
4. **Mapeamento da Rede**: Identificação de outros sistemas e dispositivos na rede que podem ser alvos.
5. **Permanência na Rede**: Técnicas para manter o acesso persistente em sistemas comprometidos, permitindo ao atacante voltar mesmo se algumas vulnerabilidades forem corrigidas.

O movimento lateral é uma técnica sofisticada que demonstra a capacidade do atacante de se deslocar dentro da rede, comprometendo múltiplos sistemas e potencialmente alcançando ativos de maior valor ou dados sensíveis.

Se precisar de mais informações ou quiser saber mais sobre outras etapas do teste de penetração, estou aqui para ajudar!

### 7. Relatório/Análise
### 8. Lições Aprendidas/Remediação

**Continuidade da Coleta de Informações:**
- A Coleta de Informações não termina após a recon, ela continua conforme o teste de penetração progride, construindo conhecimento sobre a superfície de ataque.


# Hands-on
-----
## passiva

A coleta de informação passiva envolve a obtenção de dados sobre um alvo (empresa, organização, rede ou indivíduo) sem interagir diretamente com o sistema alvo. É uma etapa crítica em testes de penetração, reconhecimento de redes e avaliação de segurança, pois minimiza o risco de detecção por parte do alvo. Aqui está uma lista detalhada de técnicas, ferramentas e recursos que você pode usar para realizar essa tarefa.

**1. Coleta de Informações WHOIS**

Permite obter informações sobre domínios, como dados de registro, contatos e servidores DNS.

- **Ferramenta CLI**:
    `whois exemplo.com`
    
- **Sites Úteis**:
    - [whois.net](https://www.whois.net/)
    - whois.domaintools.com

---

**2. Consulta a DNS (Domain Name System)**

Permite descobrir subdomínios, servidores de e-mail e outros registros DNS.

- **Ferramenta CLI (`nslookup`)**:
    `nslookup exemplo.com`
    
- **Ferramenta CLI (`dig`)**:
    `dig exemplo.com ANY +noall +answer`
    
- **Sites Úteis**:
    - [DNSDumpster](https://dnsdumpster.com/)
    - [MXToolbox](https://mxtoolbox.com/)

---

**3. Coleta de Metadados em Documentos Públicos**

Extrai metadados de arquivos públicos (PDFs, DOCs, imagens, etc.), que podem revelar informações sensíveis como autor, software utilizado e data de criação.

- **Ferramenta CLI (`exiftool`)**:
    `exiftool arquivo.pdf`
    
- **Ferramenta GUI**: **FOCA** (disponível no Kali Linux).

---

**4. Pesquisa de Subdomínios**

Descobre subdomínios que podem ser alvos secundários.

- **Ferramenta CLI (`sublist3r`)**:
    `sublist3r -d exemplo.com`
    
- **Sites Úteis**:
    - [crt.sh](https://crt.sh/) (Pesquisa em certificados SSL)
    - Subdomain Finder

---

**5. Pesquisa em Motores de Busca**

Coleta informações publicamente disponíveis usando operadores avançados de busca.

- **Google Dorking**:
    `site:exemplo.com filetype:pdf "confidencial"`
    
    Exemplos de Dorks:
    
    - `intitle:"index of" "backup"`
    - `site:exemplo.com inurl:admin`
- **Sites Úteis**:
    
    - Google Advanced Search
    - Exploit Database Dorks

---

**6. Coleta de Informações em Redes Sociais**

Explora redes sociais em busca de informações sobre funcionários, parceiros e atividades da empresa.

- **Ferramentas CLI**:
    
    - **TheHarvester**:
        `theharvester -d exemplo.com -l 500 -b linkedin`
        
    - **Maltego** (ferramenta gráfica poderosa para reconhecimento passivo).
- **Sites Úteis**:
    
    - [LinkedIn](https://www.linkedin.com/)
    - [Facebook](https://www.facebook.com/)
    - [Instagram](https://www.instagram.com/)

---

**7. Pesquisa em Bancos de Dados Públicos**

Verifica vazamentos de credenciais, informações expostas e outros dados sensíveis.

- **Sites Úteis**:
    - [Have I Been Pwned](https://haveibeenpwned.com/)
    - [Leak-Lookup](https://leak-lookup.com/)
    - [Pastebin](https://pastebin.com/) (para buscar informações vazadas)

---

**8. Coleta de Informações em Sites de Monitoramento**

Monitora alterações em domínios, IPs e servidores.

- **Ferramentas**:
    - [Shodan](https://www.shodan.io/) – Motor de busca para dispositivos conectados à internet.
    - [Censys](https://censys.io/) – Busca dispositivos e certificados expostos.
    - [SecurityTrails](https://securitytrails.com/) – Explora dados de domínios e DNS.

---

**9. Análise de Certificados SSL**

Extrai informações sobre certificados SSL que podem revelar subdomínios, emissor, organização, etc.

- **Ferramenta CLI (`openssl`)**:
    `echo | openssl s_client -connect exemplo.com:443 | openssl x509 -noout -text`
    
- **Site Útil**:
    
    - [crt.sh](https://crt.sh/)

---

**10. Busca em Arquivos Robots.txt**

O arquivo `robots.txt` pode revelar áreas do site que o administrador não deseja indexar.

- **Comando**:
    `curl -s http://exemplo.com/robots.txt`
    

---

**11. Coleta de Informações em Arquivos Sitemap.xml**

Identifica URLs e páginas importantes.

- **Comando**:
    `curl -s http://exemplo.com/sitemap.xml`
    

---

**12. Análise de Registro de Emails (MX Records)**

Identifica os servidores de e-mail de um domínio.

- **Comando**:
    `dig exemplo.com MX`
    

---

**13. Coleta de Informações de Endereços IP e ASN**

Permite descobrir informações sobre a infraestrutura da rede.

- **Comando CLI**:
    `whois 192.168.1.1`
    
- **Sites Úteis**:
    
    - [IPinfo](https://ipinfo.io/)
    - [RIPE Database](https://www.ripe.net/)

---

**14. Utilização de Arquivos Públicos e Registros Históricos**

Permite buscar informações sobre versões antigas de sites e serviços.

- **Sites Úteis**:
    - Wayback Machine
    - [ViewDNS](https://viewdns.info/)

---

**15. Coleta de Informações em Fóruns e Repositórios Públicos**

Busca informações em fóruns técnicos, listas de discussão e repositórios.

- **Sites Úteis**:
    - [GitHub](https://github.com/)
    - [Stack Overflow](https://stackoverflow.com/)
    - [Reddit](https://www.reddit.com/)

---

**Ferramentas de Reconhecimento Passivo no Kali Linux**

1. **TheHarvester** – Para coleta de emails, subdomínios e nomes.
2. **Maltego** – Plataforma gráfica para visualização de informações.
3. **SpiderFoot** – Ferramenta de reconhecimento automatizada.
4. **Recon-ng** – Framework de reconhecimento.
5. **dnsenum** – Ferramenta para coleta de informações DNS.

---

**Dicas para Coleta de Informação Passiva**

1. **Evite interação direta** com o alvo para não ser detectado.
2. **Combine várias ferramentas** para obter uma visão mais ampla.
3. **Analise metadados** de documentos e imagens para obter informações detalhadas.
4. **Automatize processos repetitivos** com scripts para melhorar a eficiência.

Essas técnicas e ferramentas permitem uma abordagem eficaz para coletar informações passivas, ajudando a construir um perfil detalhado do alvo sem levantar suspeitas.


## Ativa

A **obtenção ativa de informações** é o processo de coleta de dados sobre um alvo (sistema, rede, organização ou indivíduo) por meio de interações diretas com ele. Diferentemente da coleta passiva, essa abordagem envolve o envio de requisições ao alvo, o que pode deixá-lo ciente da atividade, tornando a detecção uma possibilidade.

**Objetivo**

Obter informações detalhadas sobre a infraestrutura, serviços, portas, sistemas operacionais, vulnerabilidades e configuração de segurança do alvo.

### DNS enumeration

#### kali linux

##### host
O DNS é um banco de dados distribuído responsável por traduzir nomes de domínio amigáveis ​​ao usuário em endereços IP. É um dos sistemas mais críticos da Internet. Isso é facilitado por uma estrutura hierárquica que é dividida em várias zonas, começando com a zona raiz de nível superior. Devido à riqueza de informações contidas no DNS, ele geralmente é um alvo lucrativo para coleta ativa de informações. 

```bash
host www.megacorpone.com
```

![[Pasted image 20241127090705.png]]

Vamos demonstrar isso usando o comando host para encontrar o endereço IP de www.megacorpone.com. Por padrão, o comando host pesquisa um registro A, mas também podemos consultar outros campos, como registros MX ou TXT, especificando o tipo de registro em nossa consulta usando a opção -t. 

```bash
host -t mx megacorpone.com
```

![[Pasted image 20241127090806.png]]

Nesse caso, primeiro executamos o comando host para buscar apenas os registros MX do megacorpone.com, que retornaram quatro registros de servidor de e-mail diferentes. Cada servidor tem uma prioridade diferente e o servidor com o menor número de prioridade será usado primeiro para encaminhar e-mails endereçados ao domínio megacorpone.com. Em seguida, executamos o comando host novamente para recuperar apenas os registros TXT do megacorpone.com, que retornou duas entradas.

```bash
host -t txt megacorpone.com
```

![[Pasted image 20241127090943.png]]

Agora que coletamos alguns dados iniciais do domínio megacorpone.com, podemos continuar a usar consultas DNS adicionais para descobrir mais nomes de host e endereços IP pertencentes ao mesmo domínio. 

Por exemplo, sabemos que o domínio tem um servidor web com o nome de host “www.megacorpone.com”. 

![[Pasted image 20241127090705.png]]

Agora, vamos determinar se megacorpone.com tem um servidor com o nome de host “idontexist”. Observaremos a diferença entre as saídas da consulta. 

```bash
host idontexist.megacorpone.com
```

![[Pasted image 20241127091554.png]]

Como agora entendemos como pesquisar nomes de host válidos, podemos automatizar nossos esforços. Tendo aprendido os princípios básicos da enumeração de DNS, podemos desenvolver técnicas de força bruta de DNS para acelerar nossa pesquisa. Usando uma lista de palavras contendo nomes de host comuns, podemos tentar adivinhar registros DNS e verificar a resposta para nomes de host válidos. 

Nos exemplos até agora, usamos pesquisas de encaminhamento, que solicitam o endereço IP de um nome de host para consultar um nome de host válido e um inválido. Se o host resolver com sucesso um nome para um IP, isso pode ser uma indicação de um servidor funcional. Podemos automatizar o encaminhamento DNS-lookup de nomes de host comuns usando o comando host em um Bash one-liner. 

Primeiro, vamos construir uma lista de possíveis nomes de host: 

word list

```bash
nano list.txt # nano editor
www
ftp
mail
owa
proxy
router

# save Ctrl + x / y / Enter 
```

Consumindo a word list
```bash
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```

![[Pasted image 20241127094326.png]]

Em seguida, podemos usar um Bash one-liner para tentar resolver cada nome de host. Usando esta lista de palavras simplificada, descobrimos entradas para "www", "mail" e "router". Os nomes de host "ftp", "owa" e "proxy", no entanto, não foram encontrados. 

Com exceção do registro www, nossa enumeração de força bruta de encaminhamento de DNS revelou um conjunto de endereços IP dispersos no mesmo intervalo aproximado. Se o administrador de DNS de megacorpone.com configurasse registros PTR para o domínio, poderíamos escanear o intervalo aproximado com pesquisas reversas para solicitar o nome do host para cada IP. 

Vamos usar um loop para escanear endereços IP de 200 a 254. Filtraremos resultados inválidos mostrando apenas entradas que não contêm "não encontrado". 

```bash
for ip in $(seq 50 100); do host 167.114.21.$ip; done | grep -v "not found"
```

![[Pasted image 20241127101705.png]]

Conseguimos resolver com sucesso uma série de endereços IP para hosts válidos usando pesquisas reversas de DNS. Se estivéssemos realizando uma avaliação, poderíamos extrapolar ainda mais esses resultados, e pode procurar por "mail2", "router", etc., e resultados positivos de pesquisa reversa. Esses tipos de varreduras são frequentemente cíclicos; expandimos nossa pesquisa com base em qualquer informação que recebemos em cada rodada. 

##### DNSRecon

Agora que desenvolvemos nossas habilidades básicas de enumeração de DNS, vamos explorar como podemos automatizar o processo usando alguns aplicativos. Existem várias ferramentas no Kali Linux que podem automatizar a enumeração de DNS. Dois exemplos notáveis ​​são DNSRecon e DNSenum. DNSRecon é um script avançado de enumeração de DNS escrito em Python. Vamos executar dnsrecon em megacorpone.com, usando a opção -d para especificar um nome de domínio, e -t para especificar o tipo de enumeração a ser executada neste caso, uma varredura padrão. 

```bash
dnsrecon -d megacorpone.com -t std
```

![[Pasted image 20241127102415.png]]

Com base na saída, conseguimos executar uma varredura de DNS bem-sucedida nos principais tipos de registro no domínio megacorpone.com. Vamos tentar forçar nomes de host adicionais usando o arquivo que criamos anteriormente para pesquisas diretas. Para executar nossa tentativa de força bruta, usaremos a opção -d para especificar um domínio nome, -D para especificar um nome de arquivo contendo strings de subdomínio em potencial e -t para especificar o tipo de enumeração a ser executada, neste caso brt para força bruta. 

```bash
# -d domain
# -D file with potential subdomains
# -t type of enumeration
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
```

Nossa tentativa de força bruta foi concluída e conseguimos resolver alguns nomes de host. 

##### DNSEnum

DNSEnum é outra ferramenta popular de enumeração de DNS que pode ser usada para automatizar ainda mais a enumeração de DNS do domínio megacorpone.com. Podemos passar algumas opções para a ferramenta, mas para fins deste exemplo, passaremos apenas o parâmetro de domínio de destino.

```bash
dnsenum megacorpone.com
``` 

Agora descobrimos vários hosts anteriormente desconhecidos como resultado de nossa extensa enumeração de DNS. Conforme mencionado no início deste tópico, a coleta de informações tem um padrão cíclico, portanto, precisaremos executar todas as outras tarefas de enumeração passiva e ativa neste novo subconjunto de hosts para revelar quaisquer novos detalhes potenciais. As ferramentas de enumeração cobertas são práticas e diretas, e devemos nos familiarizar com cada um antes de continuar. 

#### Windows

##### nslookup
Tendo abordado as ferramentas Kali, vamos explorar que tipo de enumeração de DNS podemos executar de uma perspectiva do Windows. O nslookup é a principal ferramenta do Windows para enumeração de DNS. Uma vez conectado no cliente Windows 11, podemos executar uma consulta simples para resolver o registro A para o host mail.megacorptwo.com. 

```bash
nslookup mail.megacorptwo.com
```

Consultamos o servidor DNS padrão para resolver o endereço IP de mail.megacorptwo.com. O servidor DNS então respondeu com o IP. Similarmente ao comando host do Linux, o nslookup pode executar consultas mais granulares. Por exemplo, podemos consultar um determinado DNS sobre um registro TXT que pertence a um host específico. 

```bash
nslookup -type=TXT info.megacorptwo.com <address>
```

Neste exemplo, estamos consultando especificamente o servidor DNS para qualquer registro TXT relacionado ao host info.megacorptwo.com. O utilitário nslookup é tão versátil quanto o comando host do Linux e as consultas também podem ser automatizadas por meio do PowerShell ou script em lote.

### Port Scanning with Nmap

**1. Descobrir Hosts Ativos na Rede**
Estes comandos ajudam a identificar quais dispositivos estão conectados e ativos em uma rede.
- **Descobrir hosts ativos em uma rede local (varredura de ping):**
```bash  
nmap -sn 192.168.1.0/24

# -sn desabilita a varredura de portas e realiza apenas um ping.
```

- **Descobrir hosts ativos com varredura ARP (em redes locais):**
```bash
nmap -PR 192.168.1.0/24
# A varredura ARP é mais eficaz em redes locais, pois identifica dispositivos que podem ignorar pacotes ICMP.
```

---

**2. Identificar Serviços Ativos em um Host**

Estes comandos identificam quais serviços estão em execução nos hosts encontrados.
- **Varredura completa de portas TCP padrão em um host:**
```bash
nmap 192.168.1.10
# Escaneia as 1000 portas mais comuns do host `192.168.1.10`
```

- **Varredura de todas as portas TCP (1-65535):**
```
nmap -p- 192.168.1.10
```

- **Identificar serviços e suas versões:**
```bash
nmap -sV 192.168.1.10
# `-sV` identifica os serviços em execução e suas versões.
```

- **Detectar serviços em portas específicas (por exemplo, 80, 443 e 22):**
```
nmap -p 22,80,443 192.168.1.10
```

---

### **3. Identificar Sistemas Operacionais**
Estes comandos ajudam a identificar o sistema operacional e o tempo de atividade dos hosts.
- **Detectar o sistema operacional:**
```bash
nmap -O 192.168.1.10
# `-O` tenta identificar o sistema operacional remoto.
```

- **Sistema operacional com varredura agressiva (mais detalhada):**
```bash
nmap -A 192.168.1.10
# `-A` ativa a detecção de SO, versão do serviço, traceroute e scripts padrão.
```

- **Detectar o tempo de atividade do sistema remoto:**
```bash
nmap --uptime 192.168.1.10
```

---

### **4. Identificar Vulnerabilidades em Hosts**
Estes comandos ajudam a descobrir possíveis vulnerabilidades nos hosts.
- **Varredura de vulnerabilidades com scripts NSE (Nmap Scripting Engine):**
```bash
nmap --script vuln 192.168.1.10 
# Executa uma série de scripts para detectar vulnerabilidades conhecidas.
```
       
- **Varredura específica para vulnerabilidades SMB:**
```bash
nmap --script smb-vuln* 192.168.1.10
# Executa scripts para detectar vulnerabilidades SMB, como EternalBlue.
```    
 
- **Verificar se o host está vulnerável a DoS (Denial of Service):**
```bash
nmap --script dos 192.168.1.10
```

- **Varredura de vulnerabilidades web (Open ports 80 e 443):**
 ```bash
 nmap --script http-vuln* 192.168.1.10
 ```

---
### **5. Outras Técnicas Avançadas**
- **Varredura furtiva para evitar detecção (SYN Scan):**
```bash
nmap -sS 192.168.1.10
# `-sS` é um scan semi-aberto que evita conexões completas, sendo mais difícil de detectar.
```

- **Varredura UDP:**
```bash
nmap -sU 192.168.1.10
# `-sU` realiza a varredura de portas UDP (útil para serviços como DNS, NTP e DHCP).
```

- **Varredura com evasão de firewall:**
```bash
nmap -D RND:10 192.168.1.10
# `-D RND:10` usa IPs aleatórios como distração para o firewall.
```

- **Executar scripts personalizados:**
```bash
nmap --script /path/to/script.nse 192.168.1.10
```

---
### **6. Exemplos Práticos Combinados**
- **Escanear toda a rede local com detecção de SO, serviços e vulnerabilidades:**
```bash
sudo nmap -A --script vuln 192.168.1.0/24
```

- **Escanear serviços e portas e exportar para um arquivo XML:**
```bash
nmap -sV -oX output.xml 192.168.1.10
```

---
### **Referência de Scripts NSE Úteis para Vulnerabilidades**
Você pode listar todos os scripts disponíveis no Nmap com:
`ls /usr/share/nmap/scripts | grep vuln`

### SMB Enumeration 

**O que é SMB Enumeration?**

**SMB (Server Message Block)** é um protocolo de compartilhamento de arquivos, impressoras, e outros recursos em rede. É amplamente utilizado em ambientes Windows, mas também é suportado por outros sistemas operacionais, como Linux e macOS.

**SMB Enumeration** é o processo de coleta de informações detalhadas de um servidor SMB ou de recursos compartilhados, que podem incluir:

- **Compartilhamentos de arquivos e diretórios.**
- **Usuários e grupos disponíveis.**
- **Políticas de segurança e permissões.**
- **Sistemas operacionais em execução.**
- **Recursos abertos e permissões inadequadas.**

**Por que SMB Enumeration é importante?**

- A enumeração SMB é uma etapa fundamental no reconhecimento durante um teste de penetração, especialmente em ambientes corporativos.
- Ela permite encontrar vulnerabilidades de configuração ou compartilhamentos com permissões inadequadas, que podem levar a escalonamento de privilégios, roubo de informações, ou execução remota de código.

**Abordagem Mais Eficiente no Kali Linux para SMB Enumeration**
**1. Ferramentas Comuns para SMB Enumeration**

1. **Nmap (Network Mapper)**  
    Realiza uma enumeração inicial e pode ser usado com scripts NSE (Nmap Scripting Engine) específicos para SMB.
    
2. **Enum4linux**  
    Ferramenta especializada em enumeração SMB, baseada em comandos do `smbclient`.
    
3. **SMBclient**  
    Um cliente SMB similar ao FTP, que pode ser usado para explorar recursos de rede manualmente.
    
4. **Metasploit Framework**  
    Permite uma abordagem mais automatizada para enumeração e exploração SMB.
    
5. **CrackMapExec**  
    Ferramenta poderosa para enumeração, exploração e execução de código em massa em ambientes SMB.

**2. Passo a Passo de SMB Enumeration no Kali Linux**

**Passo 1: Descobrir Serviços SMB Ativos com Nmap**
Execute uma varredura Nmap para detectar servidores SMB ativos na rede e identificar informações básicas, como a versão do protocolo.

`nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users 192.168.1.10`

- `-p 139,445`: Escaneia as portas usadas pelo SMB.
- `--script smb-os-discovery`: Detecta o sistema operacional remoto.
- `--script smb-enum-shares`: Lista compartilhamentos disponíveis.
- `--script smb-enum-users`: Enumera usuários no servidor SMB.

**Passo 2: Usar Enum4linux para Obter Informações Detalhadas**
`enum4linux -a 192.168.1.10`
- `-a`: Enumeração agressiva que coleta:
    - Lista de compartilhamentos.
    - Lista de usuários.
    - Políticas de segurança.
    - Sistemas operacionais e grupos.

> **Nota**: O Enum4linux é uma ferramenta poderosa, mas pode ser detectada em ambientes protegidos por IDS/IPS.

**Passo 3: Listar Compartilhamentos com SMBclient**
Você pode usar o `smbclient` para listar e acessar compartilhamentos manualmente.
- **Listar Compartilhamentos:**
    `smbclient -L //192.168.1.10 -U "guest"`
    _Explicação:_  
    `-L` lista os compartilhamentos no servidor, `-U "guest"` tenta se conectar como usuário guest.
- **Conectar a um Compartilhamento:**
    `smbclient //192.168.1.10/shared_folder -U "guest"`
    
**Passo 4: Usar CrackMapExec para Enumeração em Massa**
Para uma abordagem mais automatizada em ambientes maiores:
`crackmapexec smb 192.168.1.0/24 --shares --users --pass-pol`
- `--shares`: Lista todos os compartilhamentos disponíveis.
- `--users`: Enumera usuários no servidor.
- `--pass-pol`: Coleta informações sobre políticas de senha.
- 
**Passo 5: Exploração Automática com Metasploit**
Abra o Metasploit e use módulos de enumeração SMB:
`msfconsole use auxiliary/scanner/smb/smb_enumshares set RHOSTS 192.168.1.10 run`

---
**3. Técnicas de Bypass de Segurança e Deteção**
Alguns servidores SMB podem estar protegidos por firewalls, políticas de segurança rígidas, ou detecção de intrusos. Para evitar isso:
- **Usar Técnicas de Evasão com Nmap:**
    `nmap -p 139,445 -f -D RND:10 192.168.1.10`
    _Explicação:_  
    `-f` fragmenta pacotes, `-D RND:10` adiciona IPs de distração para enganar firewalls.
    
- **Forçar Autenticação NTLM (em vez de NTLMv2) usando Enum4linux:**
    `enum4linux -n 192.168.1.10`

---
**4. Identificação de Vulnerabilidades SMB**
Após a enumeração, você pode verificar se o servidor SMB possui vulnerabilidades conhecidas, como:

1. **EternalBlue (CVE-2017-0144)**  
    Explorada no ataque WannaCry.

- **Verificação com Nmap:**
    `nmap --script smb-vuln-ms17-010 192.168.1.10`

2. **SMB Signing Disabled (Manipulação de Pacotes)**

- **Verificação com CrackMapExec:**
    `crackmapexec smb 192.168.1.10 --signing-check`

---
**5. Dicas de Segurança**
- Não execute essas ferramentas em redes que você não possui ou não tem permissão para testar.
- Ferramentas como `Enum4linux` e `Nmap` podem gerar muitos logs, então tenha cuidado com ambientes protegidos.
- Combine enumeração com outras ferramentas de exploração para maximizar os resultados.

---
 **Resumo: Ferramentas e Comandos Essenciais**

|**Ferramenta**|**Comando**|**Função**|
|---|---|---|
|Nmap|`nmap -p 139,445 --script smb-*`|Enumeração inicial de SMB|
|Enum4linux|`enum4linux -a 192.168.1.10`|Enumeração detalhada|
|SMBclient|`smbclient -L //192.168.1.10`|Listar compartilhamentos manualmente|
|CrackMapExec|`crackmapexec smb 192.168.1.0/24 --shares`|Enumeração automatizada|
|Metasploit|`use auxiliary/scanner/smb/smb_enumshares`|Exploração automática|

Com esses comandos e ferramentas, você estará bem equipado para realizar SMB Enumeration no Kali Linux.

### SMTP Enumeration

**SMTP Enumeration no Kali Linux**

**SMTP (Simple Mail Transfer Protocol)** é um protocolo utilizado para envio de e-mails. A enumeração de SMTP é uma técnica essencial durante a fase de reconhecimento em um teste de penetração para identificar:

- **Serviços SMTP ativos.**
- **Versão do servidor SMTP.**
- **Usuários válidos no servidor de e-mail.**
- **Vulnerabilidades de configuração.**

---

 **Objetivos da SMTP Enumeration**

1. **Verificar a presença de portas SMTP abertas (25, 465, 587).**
2. **Coletar informações sobre a versão do servidor SMTP.**
3. **Enumerar usuários válidos no servidor SMTP.**
4. **Detectar vulnerabilidades ou configurações inadequadas.**

---

**Ferramentas e Comandos Úteis para SMTP Enumeration no Kali Linux**

---

**1. Descobrir Servidores SMTP Ativos com Nmap**

Use o Nmap para verificar servidores SMTP ativos na rede e identificar versões:
`nmap -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2011-1764 192.168.1.10`

- **`smtp-commands`**: Lista os comandos SMTP disponíveis.
- **`smtp-enum-users`**: Tenta enumerar usuários válidos no servidor.
- **`smtp-open-relay`**: Verifica se o servidor é um open relay (permitindo envio de e-mails não autorizados).
- **`smtp-vuln-cve2011-1764`**: Verifica uma vulnerabilidade conhecida no Exim.

---

**2. Enumerar Versão do Servidor SMTP com Telnet**

Use o **Telnet** para se conectar manualmente e identificar o banner do servidor SMTP:
`telnet 192.168.1.10 25`
- Digite `EHLO example.com` ou `HELO example.com` para listar os comandos suportados.

---

**3. Enumerar Usuários com VRFY, EXPN e RCPT TO**

**VRFY**, **EXPN**, e **RCPT TO** são comandos SMTP usados para verificar a existência de usuários:

- **VRFY**: Verifica se o usuário existe.
- **EXPN**: Expande um alias de e-mail para revelar a lista de destinatários.
- **RCPT TO**: Verifica se o endereço de e-mail é válido.

Comandos:
`VRFY admin EXPN postmaster RCPT TO:<admin@example.com>`

> _Nota_: Alguns servidores SMTP desativam esses comandos por motivos de segurança.

---

**4. Enumerar Usuários com `smtp-user-enum`**

O **`smtp-user-enum`** é uma ferramenta no Kali Linux projetada para enumerar usuários SMTP.

- **Instalação (se necessário):**
    `sudo apt install smtp-user-enum`
    
- **Comando para Enumerar Usuários:**
    `smtp-user-enum -M VRFY -U user_list.txt -t 192.168.1.10`
    - **`-M`**: Método de enumeração (`VRFY`, `EXPN`, ou `RCPT`).
    - **`-U`**: Lista de usuários para testar.
    - **`-t`**: Alvo.

---

**5. Enumerar Usuários com Metasploit Framework**

Abra o Metasploit e use o módulo de enumeração SMTP:
`msfconsole use auxiliary/scanner/smtp/smtp_enum set RHOSTS 192.168.1.10 set USER_FILE /path/to/user_list.txt run`
- **USER_FILE**: Lista de usuários para testar.

---

**6. Verificar Relay Aberto (Open Relay) com Nmap ou Manualmente**

Um servidor SMTP configurado como open relay permite o envio de e-mails não autorizados, o que pode ser explorado por atacantes para enviar spam.

- **Nmap**:
    `nmap -p 25 --script smtp-open-relay 192.168.1.10`
    
- **Manual**:
    `telnet 192.168.1.10 25 HELO example.com MAIL FROM:<attacker@example.com> RCPT TO:<victim@example.com> DATA This is a test message. .`
    

Se o servidor aceitar a mensagem, ele está configurado como open relay.

---

**7. Coletar Informações com Nmap para Servidores Comuns**

Execute Nmap para verificar servidores SMTP mais comuns e suas versões:
`nmap -sV -p 25,465,587 192.168.1.10`

- **-sV**: Detecta a versão do serviço.

---

**8. Explorar Vulnerabilidades Conhecidas com Searchsploit**

Use o **Searchsploit** para buscar vulnerabilidades conhecidas em servidores SMTP:
`searchsploit postfix searchsploit exim`

---

**9. Bypass de Segurança com Fragmentação de Pacotes**

Tente evitar sistemas de segurança fragmentando pacotes com o Nmap:
`nmap -p 25 -f 192.168.1.10`

---

**Resumo de Comandos e Ferramentas**

|**Ferramenta**|**Comando**|**Descrição**|
|---|---|---|
|**Nmap**|`nmap -p 25,465,587 --script smtp-*`|Enumeração e detecção de vulnerabilidades|
|**Telnet**|`telnet 192.168.1.10 25`|Conexão manual para banner e comandos|
|**smtp-user-enum**|`smtp-user-enum -M VRFY -U user_list.txt -t 192.168.1.10`|Enumeração de usuários SMTP|
|**Metasploit**|`use auxiliary/scanner/smtp/smtp_enum`|Enumeração automatizada|
|**Searchsploit**|`searchsploit exim`|Busca por vulnerabilidades conhecidas|
### SNMP Enumeration
**SNMP Enumeration no Kali Linux**
O **SNMP (Simple Network Management Protocol)** é um protocolo amplamente utilizado para gerenciar dispositivos em redes, como roteadores, switches, servidores e impressoras. A enumeração de SNMP permite coletar informações críticas sobre a infraestrutura de rede, incluindo:

- Versão do sistema operacional.
- Interfaces de rede.
- Uptime do dispositivo.
- Tabela ARP.
- Informações de usuários, grupos e configurações.
- Serviços e processos em execução.

O Kali Linux oferece diversas ferramentas para realizar SNMP Enumeration de forma eficiente.

---

**Objetivos da SNMP Enumeration**

1. Identificar dispositivos e serviços SNMP ativos na rede.
2. Coletar informações do sistema e da rede.
3. Explorar tabelas ARP, rotas e interfaces de rede.
4. Identificar vulnerabilidades no serviço SNMP.

---

**1. Identificar Dispositivos com SNMP Ativo Usando Nmap**

O Nmap oferece scripts de detecção SNMP que podem ser utilizados para descobrir hosts com SNMP ativo:
`nmap -sU -p 161 --script=snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr 192.168.1.0/24`

- **`-sU`**: Realiza varredura UDP, já que o SNMP usa a porta UDP 161.
- **`snmp-info`**: Coleta informações gerais do dispositivo.
- **`snmp-interfaces`**: Lista as interfaces de rede.
- **`snmp-processes`**: Lista os processos em execução.
- **`snmp-sysdescr`**: Exibe a descrição do sistema.

---

**2. Enumerar Informações com `snmpwalk`**

O **`snmpwalk`** é uma ferramenta poderosa para enumerar objetos SNMP a partir de um agente SNMP.

**Instalação (se necessário):**
`sudo apt install snmp`

**Exemplo de Uso:**
`snmpwalk -v2c -c public 192.168.1.10`

- **`-v2c`**: Especifica a versão do SNMP (SNMPv2c).
- **`-c public`**: Define a string de comunidade (public é a padrão).

---

**3. Coletar Informações Específicas com `snmpwalk`**

- **Informações do Sistema:**
    `snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.1`
    
    (OID 1.3.6.1.2.1.1 retorna informações sobre o sistema, como nome, descrição e tempo de atividade).
    
- **Tabela de Roteamento:**
    `snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.4.21`
    
- **Tabela ARP:**
    `snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.4.22`
    
- **Interfaces de Rede:**
    `snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.2`
    

---

**4. Enumerar SNMP com `snmp-check`**

O **`snmp-check`** é uma ferramenta integrada ao Kali Linux que coleta informações detalhadas sobre o sistema via SNMP.

**Comando:**
`snmp-check -t 192.168.1.10 -c public`

---

**5. Enumerar SNMP com `onesixtyone`**

O **`onesixtyone`** é uma ferramenta rápida para escanear redes em busca de dispositivos SNMP ativos e strings de comunidade.

**Instalação (se necessário):**
`sudo apt install onesixtyone`

**Comando:**
`onesixtyone -c community_list.txt 192.168.1.0/24`

- **`community_list.txt`**: Lista de strings de comunidade conhecidas.

---

**6. Obter Informações de SNMP com `snmpbulkwalk`**

O **`snmpbulkwalk`** é usado para coletar grandes quantidades de dados SNMP de forma mais eficiente que o `snmpwalk`.

**Comando:**
`snmpbulkwalk -v2c -c public 192.168.1.10`

---

**7. Coletar Informações Completas com `snmpenum`**

O **`snmpenum`** é uma ferramenta específica para enumerar informações SNMP, disponível no Kali Linux.

**Comando:**
`snmpenum -t 192.168.1.10 -c public`

---

**8. Explorar Vulnerabilidades SNMP com Metasploit**

O Metasploit Framework possui módulos específicos para explorar SNMP.

**Comando:**
`msfconsole use auxiliary/scanner/snmp/snmp_login set RHOSTS 192.168.1.0/24 set THREADS 10 run`

Esse módulo tenta encontrar strings de comunidade válidas.

---

**9. Detectar Strings de Comunidade Fracas**

Você pode usar o **Nmap** para detectar strings de comunidade fracas ou padrão:
`nmap -sU -p 161 --script=snmp-brute 192.168.1.10`

---

**10. Bypass de Segurança e Fragmentação de Pacotes**

Tente contornar firewalls ou sistemas de detecção fragmentando pacotes com o Nmap:
`nmap -p 161 -f 192.168.1.10`

---

**Principais OIDs Utilizados no SNMP Enumeration**

|**OID**|**Descrição**|
|---|---|
|1.3.6.1.2.1.1|Informações gerais do sistema|
|1.3.6.1.2.1.2|Informações de interfaces de rede|
|1.3.6.1.2.1.4.21|Tabela de roteamento IP|
|1.3.6.1.2.1.4.22|Tabela ARP|
|1.3.6.1.2.1.25.1.1|Informações detalhadas do sistema|