# レビュー指摘対応の実装修正 ExecPlan


このExecPlanは生きたドキュメントであり、作業の進行に合わせて Progress、Surprises & Discoveries、Decision Log、Outcomes & Retrospective を必ず最新状態に保つ。

このリポジトリには .agent/PLANS.md が含まれており、本ExecPlanはその要件に従って保守されなければならない。

## Purpose / Big Picture


この変更で、レビューで指摘された要件齟齬と安全性の穴が解消され、Webhook通知とWorkerの挙動が要件定義書（docs/requirements.md）に整合する。利用者は、配信が開始前に終了したケースでも stream.ended を受け取れ、Webhookの再送間隔が仕様通りであることをログやテストで確認できる。運用者は、Webhook送信がDNSリバインディングに強くなり、設定やコード品質の小さな不一致が減ることを確認できる。確認はユニットテストと簡易的なHTTPリクエストで再現可能にする。

## Progress


- [x] (2026-02-02 00:00Z) docs/reviews-20260203.md を読み、ExecPlanの対象範囲と優先度を整理した。
- [x] 要件齟齬2件（Waiting Modeの stream.ended 未送信、Webhookリトライ間隔1秒欠落）を修正する。
- [x] Webhook送信の安全性を強化し、テストで検証できる状態にする。
- [x] レビューで挙げられた正確性・保守性の改善を適用する。
- [ ] テストと手動検証手順を整備し、受け入れ条件を満たすことを確認する。

## Surprises & Discoveries


現時点ではなし。実装中に想定外の挙動や影響が判明した場合は、証拠とともに追記する。

## Decision Log


- Decision: 本ExecPlanは「要件齟齬・安全性・正確性の修正」に焦点を当て、Kubernetes Job化やWebhook送信の完全なOutbox化など大規模アーキテクチャ変更は別の計画に分離する。
  Rationale: これらは要件上の必須差分ではなく、設計影響が大きいため段階的に進めた方がリスクが低い。
  Date/Author: 2026-02-02 / GPT-5.2
- Decision: DASHは実装せず、マニフェスト取得段階で明示的に拒否する方針とする。
  Rationale: 現実の運用はHLS中心であり、既存コードがDASHを解析できないため、早期エラーで誤動作を防ぐ。
  Date/Author: 2026-02-02 / GPT-5.2
- Decision: セグメントの読み込みは現状のサイズ上限付き io.ReadAll を維持する。
  Rationale: 既に10MB上限があり、実害よりも実装コストが高い。性能改善は別途測定結果が出た場合に対応する。
  Date/Author: 2026-02-02 / GPT-5.2

## Outcomes & Retrospective


ここにはマイルストーン完了時または全完了時に成果と残課題を記録する。

## Context and Orientation


本リポジトリはAPI GatewayとWorkerの2サービス構成で、Gatewayが外部APIとKubernetesのPod管理、Workerが配信解析とWebhook通知を担当する。Workerの状態遷移やWebhook送信は internal/worker/worker.go にあり、WebhookのHTTP送信処理は internal/webhook/webhook.go にある。URL検証と安全なHTTPクライアントは internal/validation/url.go にあり、内部APIは internal/api/handlers.go と internal/worker/callback.go に実装される。Kubernetes再整合は internal/k8s/reconcile.go、DB操作は internal/db/monitor_repository.go と internal/db/db.go にある。要件は docs/requirements.md に、レビュー結果は docs/reviews-20260203.md にある。

「Waiting Mode」はWorkerが配信開始を待機する状態であり、「Monitoring Mode」は配信セグメントを解析する状態を指す。「Webhook」は外部システムへ送信するHTTP POST通知のことで、「DNSリバインディング」はDNS解決結果がリクエスト前後で変化し、内部IPへ接続できてしまう攻撃を指す。

## Plan of Work


### Milestone 1: 要件齟齬とWebhook送信の安全性を是正する


この段階では、Waiting Modeで配信が終了していた場合に stream.ended を必ず送信し、Webhook再送の間隔が1秒、2秒、4秒になるよう修正する。同時に、Webhook送信に使うHTTPクライアントを安全なDial時検証付きクライアントへ置き換え、リダイレクトがあれば検証して拒否する。対象ファイルは internal/worker/worker.go と internal/webhook/webhook.go、internal/validation/url.go であり、修正後はユニットテストでイベント送信と再送間隔を確認できるようにする。期待される成果は、Waiting Modeの終了検知時に data を含む stream.ended が送信され、Webhook送信ログやテストで1秒の待機が確認できること、そしてURL検証がDial時とリダイレクト時に行われることだ。

### Milestone 2: 正確性と保守性の指摘事項を解消する


この段階では、graceful shutdownのコンテキスト扱いを安全にし、monitor.Config の上書きバグを取り除き、manifest更新間隔を設定可能にする。さらに、statusバリデーションの重複を統合し、healthzHandlerの未使用引数を削除し、containsの独自実装を標準関数に置き換える。対象は internal/worker/worker.go、internal/k8s/reconcile.go、internal/config/config.go、internal/api/handlers.go、cmd/gateway/main.go、internal/db/monitor_repository.go である。期待される成果は、挙動の明確化と変更点がテストや静的確認で説明できることだ。

### Milestone 3: 運用設計上の残課題を明確化し、必要な最小修正を施す


この段階では、マイグレーション管理の改善を最小限の実装で行い、DASHの未対応を明示的なエラーとして扱う。マイグレーションは schema_migrations テーブルを追加し、既存の internal/db/migrations 配下のSQLをバージョン順に実行した後に適用済みを記録する方式にする。DASHについては、manifest URL が .mpd である場合に早期にエラーを返し、Workerが監視を継続しないことを明確にする。Kubernetes Job化やWebhook送信のOutbox化などの大規模変更は、このExecPlanでは扱わず、別の設計資料に切り出す。

## Concrete Steps


作業開始時に状況を記録する。

    pwd
    git status

要件とレビューの該当箇所を再確認する。

    sed -n '240,360p' docs/requirements.md
    sed -n '120,200p' docs/reviews-20260203.md

対象コードを読み、変更箇所を特定する。

    sed -n '150,260p' internal/worker/worker.go
    sed -n '40,140p' internal/webhook/webhook.go
    sed -n '1,120p' internal/validation/url.go
    sed -n '220,280p' internal/k8s/reconcile.go
    sed -n '330,520p' internal/api/handlers.go
    sed -n '430,480p' internal/db/monitor_repository.go
    sed -n '150,190p' cmd/gateway/main.go

修正後はテストを実行する。

    go test ./...

テスト出力はすべてのパッケージがPASSになることを期待する。失敗した場合は、どの変更が影響したかを特定し、ProgressとDecision Logに記録する。

## Validation and Acceptance


Waiting Modeで stream.ended が送信されることは、Workerのユニットテストで ytdlp の live_status が was_live または not_live を返したケースを再現し、Webhook送信の記録が残ることで確認する。Webhookのリトライ間隔は、再送の待機時間が1秒、2秒、4秒になるようテストかログで確認し、1秒が欠落しないことを確認する。Webhook送信の安全性は、URL検証がDial時に再評価されることと、リダイレクト時に不正URLが拒否されることをユニットテストまたは簡易HTTPサーバで確認する。manifest更新間隔は新しい環境変数が反映されることをテストし、設定値を変えたときに更新周期が変わることを確認する。DASHの拒否は、.mpd のURLを与えると明示的なエラーが返ることを確認する。

## Idempotence and Recovery


修正は安全に繰り返せるようにし、migrationsの実行は schema_migrations により二重適用されないようにする。テストや設定変更は何度実行しても同じ結果になるように、時間依存の処理には短い待機時間と明示的なタイムアウトを用いる。万一、Webhook送信の安全化で外部送信が止まった場合は、CheckRedirectや検証条件を一時的に緩和できるようにコメントで再現手順を残す。

## Artifacts and Notes


作業中に得られた重要な出力は短い抜粋としてここに残す。例として、go test のPASS行や、Webhookリトライが1秒で行われるログ断片などを数行だけ記録する。

## Interfaces and Dependencies


internal/webhook/webhook.go の NewSender は validation.NewSafeHTTPClient を使うこと。HTTPリダイレクト時には Location を検証するため、http.Client の CheckRedirect を設定し、validation.ValidateOutboundURL で許可されないURLはエラーにする。リトライ待機時間は attempt から導出できる小さな関数に分離し、テストで1秒が含まれることを保証する。

internal/worker/worker.go は Waiting Mode の was_live / not_live 分岐で w.sendWebhook を必ず呼び、data には reason を含める。sendWebhook をテストできるように、Workerの依存をインターフェース化し、テスト用のスタブを注入できるコンストラクタを追加する。以下のような形を想定する。

    type WebhookSender interface {
        Send(ctx context.Context, url string, payload *webhook.Payload) *webhook.SendResult
    }

    type YtDlpClient interface {
        IsStreamLive(ctx context.Context, streamURL string) (bool, *ytdlp.StreamInfo, error)
        GetManifestURL(ctx context.Context, streamURL string) (string, error)
    }

internal/config/config.go には manifest更新間隔を表すフィールドを追加し、環境変数 MANIFEST_REFRESH_INTERVAL を読み取る。internal/worker/worker.go はこの値で ticker を作成する。cmd/gateway/main.go の healthzHandler は未使用の引数を削除し、呼び出し側も合わせる。internal/db/monitor_repository.go の contains 実装は strings.Contains に置き換え、ユニットテストがある場合はそのまま通ることを確認する。internal/k8s/reconcile.go の Config 上書きブロックは削除し、monitor.Config が常にそのまま Worker に渡るようにする。DASH拒否は internal/manifest/manifest.go または internal/ytdlp/ytdlp.go の manifest URL 判定で .mpd を検出して明示的にエラーにする。

Change note: 2026-02-02 / GPT-5.2 - docs/reviews-20260203.md を基に初版のExecPlanを作成した。
