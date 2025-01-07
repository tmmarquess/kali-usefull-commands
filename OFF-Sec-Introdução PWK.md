#off-sec/importante
# Nota importante
![[Pasted image 20241119113557.png]]
Alguns exercícios do Módulo têm uma pergunta e resposta simples, onde o aluno é encarregado de recuperar a solução do texto. Outros exercícios do Módulo podem ter três componentes: uma pergunta, uma máquina (ou um grupo de máquinas) e um sinalizador. Nesses casos, a pergunta pede que você execute uma ação específica ou um conjunto de ações na máquina fornecida. Depois de concluir o objetivo, você receberá um sinalizador no formato **OS{random-hash}** . Você pode então enviar o sinalizador para o _OffSec Learning Portal_ (OLP), que informará se você inseriu o sinalizador correto ou não. O OLP salvará seu progresso e rastreará o número de seus envios corretos fornecidos até o momento.

Vale a pena notar que os sinalizadores são gerados dinamicamente na inicialização da máquina e expiram no desligamento da máquina. Se a solução para uma questão for obtida e a máquina for revertida, e somente após a reversão a resposta original for enviada, o OLP não aceitará o sinalizador.

A sinalização deve ser enviada antes de reverter ou desligar a máquina.

Como uma nota adicional, a maneira como os exercícios do Módulo são implementados nos permite usar o mesmo IP remoto e porta várias vezes. Ao acessar VMs do Exercício do Módulo que exigem uma conexão SSH, sugerimos usar o comando SSH com algumas opções extras, como a seguir:

```
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52
```

# Obs.

[_Common Vulnerability Scoring System_](https://nvd.nist.gov/vuln-metrics/cvss) (CVSS)