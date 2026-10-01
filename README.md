# Crowsi Local Control Bridge

CoelaなどのローカルWorkloadとCrowsiのPolicy Enforcement経路を接続する、
Unix IPC専用の認証・認可境界です。HTTP、Bearer token、Cookie、任意Header、
loopback到達性、環境変数を権限として扱いません。

## 保証する境界

- `SO_PEERCRED`から得たPID・UID・GIDと、PID start time、実行ファイルSHA-256を照合
- PA署名済みAuthorization V2をpairwise Subject、Service、Device、端末proof key、
  posture revision、Workload、Profile、Action、Resource、Purpose、Body digestへ完全束縛
- Phishing-resistant authenticationとUser Verification、compliant deviceを必須化
- PAが束縛したsender公開鍵によるrequest署名を検証し、PA鍵とのrole reuseを拒否
- 60秒以下のauthorization、subject/service/device/session別のmonotonic
  revocation epoch、trusted monotonic clockを強制
- SQLiteの一回利用reservation、成功操作のhash-chain監査、subject別rate limit
- 64 KiB以下・未知フィールド拒否のIPC envelope
- SQLiteは絶対Path、所有者専用Directory、0600 regular file、symlink不可
- application ID、schema version、STRICT schemaを完全照合し、時刻watermarkを永続化
- iHATの`CurrentDeviceStatusV1`をclosed decodeし、固定したidentity鍵・key ID・issuer・
  audience・Service、trusted time、pairwise Subject・Device・proof keyの完全一致を検証
- status nonceのdigestとscope別watermarkを同一SQLite transactionで永続化し、再起動後の
replayも拒否
- SQLite v4だけをcurrent stateとして受理し、v2/v3やschema不一致は暗黙移行せず拒否する。
  用途別daemonは新しい署名済みstatusを適用するまでsocketを公開しない

公開する操作認可APIは`authorize_unix_stream`です。IPC frameと同じUnix streamから
crate内部でkernel peer evidenceを取得するため、呼出元はpeer identityを生成・再利用・
差し替えできません。Identity同期用の`apply_current_device_status`は署名済みwireだけを
受け、`BridgeTrust`へ注入した`IdentityStatusTrust`が固定するtrust contextと、呼出側が
指定する`CurrentStatusBinding`の双方へ一致しなければstateを変更しません。Clock実装も
sealedで、本番コードから手動時刻を注入できません。

Bridgeが返すのは対象とCommand digestを含む`DispatchTicket`です。Provider秘密、
PA Grant、sender秘密鍵は返しません。Ticket自体はPEPの認可ではなく、別途
PA発行のfencing付きCommandとPEP側CASが必要です。

## 検証

```bash
# WONDERLAND_ROOT is the workspace checkout root.
"$WONDERLAND_ROOT/bin/verify-repositories" --rust --tier standard
cargo run --offline --quiet -- sample-readiness
```

`sample-readiness`は物理配備を行わず、`external_actions=false`かつ
`unavailable`の閉じたJSONだけを出力します。
ライブラリ単体の`readiness`も配備検証器ではないため常に`unavailable`です。

## Purpose-specific daemon composition

`PrivateUnixListener`と`LocalControlServer`は、Credential Agentなどの
用途別daemonがBridgeを同一Process内で合成するためのruntime部品です。
socketはowner-onlyのcanonical directoryにだけ作成し、mode `0600`へ固定します。
用途別daemonは`bind_recovering_stale`を明示的に選ぶことで、同一UID・mode 0600・
接続拒否・inode再照合をすべて満たす停止済みsocketだけを回収できます。active socket、
symlink、regular file、差替え、公開permissionは削除せず拒否します。
終了時は作成時と同じinodeである場合に限って削除するため、path差替えで別Fileを
削除しません。各接続には最大30秒の有限I/O deadlineを設定し、認可をdurableに
消費した後でだけ用途別handlerへ同じUnix streamを渡します。
用途別daemonはsignal handlerから`AtomicBool`だけを更新し、`serve_until`で
最大10ms以内にaccept loopを抜けてsocket inodeを安全に片付けられます。

Bridge単体のbinaryは操作内容や秘密値を知らないため、汎用relay daemonには
しません。`DispatchTicket`に追加したpairwise Subject、Service、Device、proof-key参照、
Workload、Profile、sender key、scoped revocation epochはProcess内のhandlerだけが参照でき、Serialize時には
除外され、`Debug`も識別子をredactします。用途別daemonは`body_sha256`、action、
resource、purposeを後続frameへ
再束縛してから処理します。

旧Authorization V1、単一`revocation_epoch`、caller生成のunsigned revocation snapshotは
受理しません。identity authorityの短命な署名済み`CurrentDeviceStatusV1`だけがscope別
watermarkを単調増加させます。端末Aのdevice/posture/session scopeを進めても端末Bの
device grantは失効しません。watermarkと使用済みstatus nonceはSQLiteへ永続化され、
再起動や古い署名済みAuthorization/statusで巻き戻せません。subjectまたはservice scopeの
失効は明示的に全端末へ作用する操作であり、device失効の代替として使いません。

SQLite v2/v3からcurrent v4への切替は再enrollment境界です。旧unsigned epochや旧DBを
in-place移行せず、installerが新しいowner-only v4 stateを作成します。identity authorityから
対象端末用のfresh statusを再発行できない場合は切替を完了せず、旧DBを手動編集して
回避しません。

`BridgeAction::UseCredential`は、独立したCredential Runtimeへ認証済みの
Credential Useだけを渡す予約済み操作です。Bridgeは認可をdurableに消費しますが、
Credential値の読取りやProvider呼出しは行いません。

このruntime部品が存在することはproduction配備完了を意味しません。専用UID、
root管理socket directory、PA鍵、hardware-backed trust、trusted clockを
配備・検証するまでは`sample-readiness`とCoela UIを`unavailable`のまま維持します。

## 本番配備条件

専用の非root service user、root管理のUnix socket directory、TPM/HSMで保護した
PA trust material、iHAT status署名鍵・key ID・issuer・audience・Service pin、信頼時刻源、0700
state directory、署名済みartifact digest、起動時のpeer attestation試験が揃うまで
本番readyにしてはいけません。
