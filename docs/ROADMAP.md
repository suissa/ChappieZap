# Roadmap

## Módulos

### 1. **Segurança (Anti-Ban, Isolação e Criptografia Superior)**

Bibliotecas tradicionais focam em *fazer funcionar*, mas ignoram padrões comportamentais que disparam os filtros da Meta.

* **Motor Antidetecção de Comportamento (Anti-Ban Engine):**
* **Simulação de digitação/presença humana:** Gerenciamento nativo de *typing indicators* (`composing`) e intervalos de digitação baseados no tamanho do texto, além de distribuição estatística de *jitter* entre requisições.
* **Rotação e Spoofing de User-Agent / Device Specs:** Impressão digital do cliente (*client fingerprint*) configurável de forma dinâmica para emular diferentes versões de navegadores ou apps desktop oficiais sem disparar heurísticas de segurança da Meta.


* **Isolação Zero-Memory / Secure Erasure:**
* Em Zig, utilize `std.mem.secureZero` para apagar chaves de sessão da memória RAM assim que o *handshake* ou a descriptografia da mensagem for concluída, evitando vazamento via *memory dumps* ou *buffer overflows*.


* **Criptografia NAtiva Hardware-Accelerated (Noise Protocol):**
* Tirar proveito de instruções nativas de CPU (`AES-NI`, `NEON`, etc.) via Zig para realizar o handshake do *Noise Protocol* e cifra *Signal* com overhead virtualmente zero.


* **Armazenamento Seguro de Sessão por Padrão (Encrypted Vault):**
* Em vez de salvar chaves em arquivos JSON planos ou SQLite aberto, ter suporte nativo a SQLite encriptado (ex: via SQLCipher) ou integração direta com chaves do sistema de arquivos/OS Keyring (Keychain no macOS, Secret Service no Linux, DPAPI no Windows).



---

### 2. **Funcionalidades Avançadas (Diferenciais que Outras Libs Não Tem)**

* **TUI (Terminal User Interface) Embutida / Debugger em Tempo Real:**
* Aproveite a velocidade do Zig para criar uma interface no terminal (usando `ncurses` ou uma biblioteca TUI leve) embutida na própria CLI do projeto.
* Permite visualizar mensagens chegando, depurar tráfego de *Frames Protobuf* e ver o status das chaves de criptografia em tempo real.


* **FFI First-Class (Exportação C ABI Nativa):**
* Crie bindings automáticos de alto nível para **Python, Rust, C/C++, Go e Node.js** via Zig C-ABI. O whatszig pode rodar como uma *shared library* (`.so` / `.dll` / `.dylib`) ultraleve que qualquer linguagem pode consumir sem precisar de um processo daemon pesado ou Node.js/Go rodando de fundo.


* **Gerenciador de Estado do Canal em Memória (Lightweight Cache State):**
* As bibliotecas atuais costumam delegar a gestão de histórico totalmente para a aplicação. O whatszig pode implementar uma estrutura *RingBuffer* em memória para armazenar as últimas $N$ mensagens e estados de presença dos contatos com retenção configurável e sem vazamento de memória.


* **Suporte Completo a WASM (WebAssembly):**
* Graças à excelente integração do Zig com WASM, o whatszig pode ser compilado diretamente para WebAssembly sem dependências externas, permitindo rodar o cliente diretamente no navegador ou em edge workers (Cloudflare Workers, Fastly).



---

### 3. **Simplicidade de Uso (DevEx & Ergonomia)**

Bibliotecas em linguagens de baixo nível costumam ser verbosas. Simplificar a API sem perder controle de memória é a chave:

* **Gerenciamento Transparente de Alocação de Memória:**
* Fornecer instâncias de "Default Allocator" pré-configuradas para casos comuns (por exemplo, `GeneralPurposeAllocator` auto-gerenciado para projetos rápidos e alocador customizado para produção avançada).


* **API Orientada a Eventos Limpa (Event-Driven API):**
* Sistema de eventos usando *Tagged Unions* nativas do Zig para tratar reconexões, atualização de estado de chamada, recebimento de mídia e mensagens de forma estritamente tipada e segura em tempo de compilação.


* **QR Code Nativo no Terminal & Servidor HTTP Integrado:**
* Renderização direta de QR code em formato UTF-8 / ANSI no terminal sem dependências externas de pacotes de terceiros.
* Opção de subir um micro-servidor HTTP local embutido para expor uma rota `/qr` em SVG/PNG ou `/metrics` (Prometheus) de forma imediata.



---

### Exemplo de Visão da API (Zig Ergômico)

```zig
const std = @import("std");
const whatszig = @import("whatszig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Configuração com opções seguras por padrão (Anti-ban ativo, Encrypted Vault)
    var client = try whatszig.Client.init(allocator, .{
        .session_store = .{ .encrypted_file = "session.vault", .passphrase = "master_key" },
        .anti_ban = .strict, // Ativa delays humanos, rotação de fingerprint e jitter
        .print_qr_in_terminal = true,
    });
    defer client.deinit();

    // Handler de Eventos Tipado
    client.onEvent(struct {
        pub fn handle(event: whatszig.Event) void {
            switch (event) {
                .message => |msg| std.debug.print("Mensagem de {s}: {s}\n", .{ msg.from, msg.body }),
                .connection_state => |state| std.debug.print("Status: {}\n", .{state}),
                else => {},
            }
        }
    }.handle);

    try client.connect();
}

```

O projeto **Linus-Salamander-enclave** tem uma proposta excelente: construir um enclave/cofre de segurança (*Vault*) com foco em isolamento forte e proteção de dados sensitivos.

Analisando a arquitetura clássica de Enclaves de Segurança modernos (como AWS Nitro Enclaves, HashiCorp Vault ou Intel SGX), a ideia de combinar um cofre com execução isolada é o caminho ideal para lidar com credenciais, chaves criptográficas e workloads sensíveis.

Abaixo, dividi a análise em três pilares: **O que está ótimo no projeto**, **Sugestões de Segurança** e **Funcionalidades para Evolução**.

---

### 1. O que é muito forte na arquitetura

* **Conceito de Enclave Dedicado:** Trazer a ideia de *enclave* para a aplicação impede que processos normais do sistema operacional acessem a memória do cofre diretamente.
* **Separação de Privilégios:** Manter a execução isolada reduz significativamente a superfície de ataque em caso de RCE (*Remote Code Execution*) na aplicação principal.
* **Modelo Enclave-Driven:** O cofre não expõe chaves abertas; em vez disso, o consumo de segredos é feito dentro do próprio ambiente protegido ou entregue via tokens temporários.

---

### 2. Sugestões de Segurança e Hardening (Melhorias de Baixo Nível)

Se o foco do projeto é ser um *Vault/Enclave* de alta fidelidade para produção, vale a pena implementar as seguintes proteções:

#### A. Proteção de Memória em Tempo de Execução (RAM Hardening)

1. **Paging/Swap Locking (`mlock` / `VirtualLock`):**
* Garanta que as chaves mestre ou dados descriptografados em memória nunca sejam gravados em disco via arquivo de *Swap* ou *Paging* do sistema operacional. O uso do `mlock` impede que o SO faça *dump* dessas páginas de memória.


2. **Zeroização Estrita (Secure Erasure):**
* Apague buffers de chave da memória com instruções de *zeroing* volátil (que não são otimizadas/removidas pelo compilador, como `explicit_bzero` em C/Rust).


3. **Páginas Guardiãs (Guard Pages & Seccomp Filters):**
* Restrinja as syscalls do processo do enclave usando `seccomp-bpf` (no Linux). Impeça chamadas como `ptrace` para que outros processos (mesmo rodando no mesmo usuário) não consigam inspecionar ou debugar a memória do enclave.



#### B. Modelo de Atestação Remota / Hardware Root of Trust

* **Atestação de Integridade:** Implemente um mecanismo onde o enclave valida o hash/assinatura do seu próprio binário na inicialização.
* **Integração com TPM / KMS / Secure Enclave Nativo:** Permitir que a *Master Key* do Vault fique celada (*sealed*) em hardware como o **TPM 2.0** do host ou via **AWS KMS / Apple Secure Enclave**. Dessa forma, mesmo que o disco seja roubado, a chave não pode ser extraída sem a validação do chip físico.

---

### 3. Funcionalidades Avançadas para Adicionar (Roadmap)

Para tornar o **Linus-Salamander-enclave** um projeto diferencial em relação a soluções comuns de mercado:

* **Dynamic Secrets (Segredos Dinâmicos com TTL):**
* Em vez de apenas salvar senhas estáticas, adicione suporte para gerar credenciais temporárias para bancos de dados ou serviços em nuvem (ex: gera uma chave AWS válida por apenas 15 minutos e revoga automaticamente).


* **Criptografia como Serviço (Transit Encryption API):**
* O enclave assume o papel de HSM (*Hardware Security Module*) lógico. A aplicação cliente envia o texto plano para o enclave e recebe o texto cifrado, **sem que a aplicação cliente precise possuir ou ver a chave de criptografia**.


* **Mecanismo de Unseal Distribuído (Shamir's Secret Sharing):**
* Para inicializar o enclave em ambiente de alta segurança, exija $K$ de $N$ chaves de administradores diferentes para "desbloquear" o cofre (Split-Key).


* **Audit Trail Imutável (Append-Only Log):**
* Log de auditoria criptograficamente assinado com *Hash Chain* (estilo Merkle Tree). Cada operação de leitura/escrita gera uma entrada encadeada na anterior, tornando impossível para um atacante apagar os rastros de um vazamento sem quebrar a cadeia.



---

### 4. Simplicidade e DevEx (Experiência do Desenvolvedor)

* **CLI Interativa & Daemon Modeless:** Fornecer um modo local rápido para desenvolvimento onde o enclave roda em memória compartilhada sem necessitar de permissões de *root* ou dependências complexas.
* **SDK Lightweight:** Desenvolver bibliotecas de conexão finas (Zero-Dependency) para Python, Go e Node.js para que aplicações consumam o enclave com poucas linhas de código.
* **Health Checks e Métricas Anonimizadas:** Expor um endpoint de telemetria apenas para leitura do estado do enclave (se está *sealed* ou *unsealed*), facilidades vitais para orquestradores como Kubernetes.
