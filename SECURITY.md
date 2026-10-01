# Security policy

このcrateは認証境界であり、一般用途のHTTP serverやshell runnerではありません。

- 秘密値、Grant、Authorization envelopeをbrowserへ渡さない
- `BridgeTrust`はweak Ed25519 key、root caller、曖昧なWorkload IDを拒否する
- PA authorization鍵とsender proof鍵に同じ公開鍵materialを使用しない
- Kernel peer credential取得不能時は`PeerAttestation`として拒否する
- SQLite stateを削除・巻き戻した場合は外部anchorとの不一致として運用停止する
- `DispatchTicket`をProvider操作の最終認可として使用しない
- `UseCredential`は後段Runtimeの操作だけを認可し、Bridge自身はCredential値を
  読取り、Serialize、Log、または返却しない
- stale socket回収は同一UID・0600・非symlink・接続拒否・inode不変の場合だけ許可する
- 端末失効はdevice-scoped watermarkだけを進める。subject/service epochを端末失効の
  近道として更新せず、影響を受けない端末のauthorizationを維持する
- `BridgeTrust`にはPA鍵とは別に、iHAT status用の公開鍵・key ID・issuer・audience・Serviceを
  `IdentityStatusTrust`として固定する。未設定時はstatus更新をfail-closeする
- identity statusは`apply_current_device_status`だけで受け、closed contract、署名、
  issuer、audience、trusted time、pairwise Subject・Service・Device・proof keyを検証する
- status nonce digestのdurable一回利用とscope watermark更新を同一transactionに置き、
  replayや途中失敗で一部だけを反映しない
- v2からv3へのmanaged migrationでは旧unsigned revocation watermarkを破棄し、freshな
  signed current statusを再enrollmentする。未知tableや改変schemaは移行せず停止する

鍵漏えい、replay、clock rollback、監査chain破損を検出した場合は、該当scopeの
revocation epochを先に進め、Bridgeを停止し、Rescue Consoleからcontainまたは
credential revokeだけを実行します。

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
