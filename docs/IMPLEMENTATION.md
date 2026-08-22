# Plano de Implementação: Persistência de Sessão WhatsApp com SQLite (Compatível com whatsmeow)

Este plano descreve como implementar a persistência de sessão e chaves criptográficas em banco de dados SQLite (`whatsapp.db` / `store.db`), compatível com o schema do [whatsmeow](https://github.com/tulir/whatsmeow/blob/main/store/sqlstore/upgrades/00-latest-schema.sql), permitindo que `./zig-out/bin/whatszig 5515991957645` inicialize diretamente utilizando a sessão salva sem necessidade de novo pareamento.

---

## 1. Schema do Banco de Dados (`whatsmeow`)

Utilizaremos o schema oficial do `whatsmeow` no SQLite:

1. **`whatsmeow_device`**:
   - `jid TEXT PRIMARY KEY` (ex: `5515991957645:56@s.whatsapp.net`)
   - `lid TEXT` (ex: `124953718435910:56@lid`)
   - `registration_id BIGINT NOT NULL`
   - `noise_key bytea NOT NULL` (32 bytes - private key do Noise)
   - `identity_key bytea NOT NULL` (32 bytes - private key do Identity)
   - `signed_pre_key bytea NOT NULL` (32 bytes - private key)
   - `signed_pre_key_id INTEGER NOT NULL`
   - `signed_pre_key_sig bytea NOT NULL` (64 bytes - assinatura)
   - `adv_key bytea NOT NULL` (32 bytes - secret key do ADV)
   - `adv_details bytea NOT NULL` (bytes serializados de ADVSignedDeviceIdentity)
   - `adv_account_sig bytea NOT NULL` (64 bytes)
   - `adv_account_sig_key bytea NOT NULL` (32 bytes)
   - `adv_device_sig bytea NOT NULL` (64 bytes)
   - `platform TEXT NOT NULL DEFAULT 'whatszig'`
   - `push_name TEXT NOT NULL DEFAULT 'whatszig'`
   - `companion_meta_nonce TEXT NOT NULL DEFAULT ''`

2. **`whatsmeow_identity_keys`**:
   - `our_jid TEXT`, `their_id TEXT`, `identity bytea`

3. **`whatsmeow_sessions`**:
   - `our_jid TEXT`, `their_id TEXT`, `session bytea`

4. **`whatsmeow_pre_keys`**:
   - `jid TEXT`, `key_id INTEGER`, `key bytea`, `uploaded BOOLEAN`

5. **`whatsmeow_lid_map`**:
   - `lid TEXT PRIMARY KEY`, `pn TEXT UNIQUE NOT NULL`

---

## 2. Componentes a Implementar

### A. Integração com SQLite no Zig (`Planes/Storage`)
- Baixar o `sqlite3.c` e `sqlite3.h` (amalgamation) para inclusão nativa no build (`build.zig`), sem dependência de pacotes externos do sistema.
- Criar wrapper Zig idiomático para SQLite:
  - `Database.open(path)`
  - `Database.exec(sql)`
  - `Statement.bind(...)`, `Statement.step()`, `Statement.columnBlob(...)`, etc.

### B. Módulo de Armazenamento de Sessão (`src/storage/store.zig`)
- `saveDevice(client)`: salva/atualiza os dados da sessão em `whatsmeow_device`.
- `loadDevice(phone_number)`: busca em `whatsmeow_device` onde `jid LIKE '<phone>:%' OR jid = '<phone>@s.whatsapp.net'`.
- `saveSession(our_jid, their_id, session_bytes)` e `loadSession(our_jid, their_id)`.
- `saveIdentity(our_jid, their_id, identity_key)` e `loadIdentity(our_jid, their_id)`.
- `saveLidMapping(lid, pn)` e `loadLidMapping(lid)`.

### C. Ajuste no Fluxo de Inicialização do `whatszig`
- Ao executar `./zig-out/bin/whatszig 5515991957645`:
  1. Abre `whatsapp.db`.
  2. Executa `loadDevice("5515991957645")`.
  3. **Se encontrar a sessão salva**:
     - Preenche as chaves (`static_keypair`, `identity`, `signed_prekey`, `adv_secret_key`, `phone_jid`, `lid`, `device_id`, `account_device_identity`).
     - Executa o login diretamente (`connectWithPayload(.login)` e `readUntilLogin`).
     - **NÃO inicia pareamento** nem solicita novo código!
  4. **Se não encontrar a sessão**:
     - Inicia pareamento via `paircode`.
     - Ao concluir o pareamento com sucesso, salva imediatamente o dispositivo no SQLite.

---

## 3. Plano de Verificação

### Testes Automatizados
- Testes unitários para:
  1. Criação das tabelas do SQLite compatíveis com whatsmeow.
  2. Salvar e recuperar chaves (`Device`, `Identity`, `PreKey`, `Session`).
  3. Serialização e deserialização do estado de chave estática e do Signal.
- Execução no WSL via:
  ```bash
  zig build test --cache-dir /tmp/whatszig-cache --global-cache-dir /tmp/whatszig-global-cache
  ```

### Validação Manual
- Executar `./zig-out/bin/whatszig 5515991957645`:
  - Primeira vez (se ainda não salvo no sqlite): pareia e salva no `whatsapp.db`.
  - Execução subsequente com `./zig-out/bin/whatszig 5515991957645`: loga diretamente sem nenhum pareamento novo, mantendo a conexão ativa e enviando/recebendo mensagens.

