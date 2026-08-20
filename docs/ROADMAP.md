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
