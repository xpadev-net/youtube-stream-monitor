# Webhook失敗時の監視削除とDASH対応・Graceful Shutdown整備


This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This repository includes `.agent/PLANS.md`, and this document must be maintained in accordance with that file.

## Purpose / Big Picture


この変更により、Webhook送信が全リトライ失敗した場合に監視ジョブが確実に削除され、監視が安全に終了します。さらに、DASH（MPD）マニフェストが返るYouTube配信でも最新セグメントを取得して解析できるようになり、HLSと同じ品質監視が可能になります。SIGTERMなどの終了シグナルを受けた際も、解析中のセグメント処理を完了し、未送信の通知を漏らさずに送信し、最後に一時ファイルをクリーンアップして停止することが確認できます。動作確認は、ユニットテストとローカルHTTPサーバを使った最小E2Eシナリオで「削除が実際に起きる」「DASHでも解析ループが回る」ことを人間が目視できる形で示します。

## Progress


- [x] (2026-02-03 21:50Z) ExecPlanの指摘事項（体裁/記述/作業ディレクトリ）を修正した。
- [x] (2026-02-03 00:00Z) ExecPlanの初版を作成し、要件差分と実装対象を確定した。
- [x] (2026-02-03 22:12Z) Webhook失敗時の監視削除フローを設計し、内部API・Worker・Gatewayの責務分担を明確化する。
- [x] (2026-02-03 22:12Z) DASHマニフェストの解析実装とテストフィクスチャを追加する。
- [x] (2026-02-03 22:12Z) Graceful Shutdownの手順を要件通りに整備し、停止時の挙動テストを追加する。
- [x] (2026-02-03 22:12Z) 追加テストと簡易E2E手順を実行し、観察結果をArtifactsに記録する。

## Surprises & Discoveries


- Observation: manifestテストではSafeHTTPClientがローカルアドレスを拒否したため、テストでhttp.DefaultClientを使用する必要があった。
  Evidence: `GetLatestSegment error: fetch manifest: Get "http://127.0.0.1:41133/manifest.mpd": no allowed ip to dial for host 127.0.0.1`

## Decision Log


- Decision: Webhook失敗時の「監視ジョブ削除」は、Gatewayの内部APIを通じてDBレコード削除とPod削除を行う。
  Rationale: WorkerはKubernetesの権限を持たないため、削除はGatewayに集約するのが安全であり、要件の「監視ジョブ削除」を明示的に達成できる。
  Date/Author: 2026-02-03 / Codex

- Decision: Internal APIに `POST /internal/v1/monitors/{monitor_id}/terminate` を追加し、理由（reason）をJSONで渡す。
  Rationale: 外部APIと経路を分離し、内部キーのみで確実に削除を実行できる。DELETEにボディを持たせる曖昧さを避け、実装とテストの可読性を高める。
  Date/Author: 2026-02-03 / Codex

- Decision: DASH対応は `encoding/xml` によるMPDの最小実装で行い、YouTubeで一般的な `SegmentTemplate + SegmentTimeline` と `SegmentTemplate + duration/timescale` をまず対応範囲とする。
  Rationale: 新規依存を増やさず、必要な機能だけを実装して可観測性のあるテストを作りやすくするため。
  Date/Author: 2026-02-03 / Codex

- Decision: Graceful Shutdownは「新規取得停止」「進行中解析完了」「Webhook送信完了」「クリーンアップ」の順で、Worker内部のshutdownフラグと待機ロジックで実現する。
  Rationale: 現行コードはctxキャンセルで即終了するため解析途中の切断が発生する。安全な停止を優先して要件順序に合わせる。
  Date/Author: 2026-02-03 / Codex

- Decision: DASHテストはSafeHTTPClientの制約を避けるため、ParserのhttpClientをテスト内でhttp.DefaultClientに差し替える。
  Rationale: ループバックアクセスの禁止は本番安全性に必要だが、テストではローカルサーバからMPDを取得するために許可が必要。
  Date/Author: 2026-02-03 / Codex

## Outcomes & Retrospective


Webhook失敗時の削除フロー、DASH解析、Graceful Shutdownの一連の改善が完了した。追加テストで削除要求・DASH解析・shutdown時の解析完了が確認できた。残課題はなし。

## Context and Orientation


このリポジトリはAPI GatewayとWorkerの二つのサービスで構成されます。Gatewayは外部REST APIを提供し、PostgreSQLに監視状態を保存し、KubernetesのPodを作成・削除します。WorkerはYouTube配信のマニフェストから最新セグメントを取得し、FFmpegで映像・音声を解析して異常を検出し、Webhookを送信します。Webhookは外部URLにHTTP POSTで通知する仕組みです。DASHはMPDというXMLのマニフェストを使う動画配信方式で、HLSの`.m3u8`と同様にセグメントURLを列挙する構造を持ちます。

この変更で触れる主要ファイルは次の通りです。`internal/worker/worker.go`はWorkerの状態遷移とセグメント解析を実装しています。`internal/webhook/webhook.go`はWebhook送信の署名とリトライを扱います。`internal/api/handlers.go`はGatewayの外部・内部APIのHTTPハンドラを持ちます。`internal/worker/callback.go`はWorkerからGateway内部APIを呼ぶクライアントです。`internal/manifest/manifest.go`はHLS/DASHマニフェストの解析を行うパーサです。`internal/db/monitor_repository.go`はDBのCRUDです。`docs/requirements.md`は要件定義であり、本変更では「Webhook失敗時の削除」「DASH対応」「Graceful Shutdown手順」が特に重要です。

「監視ジョブ削除」とは、DB上のmonitorレコードの削除（関連するmonitor_statsとmonitor_eventsの削除を含む）と、該当Worker Podの削除を意味します。これによりGET /api/v1/monitors/{id}が404になることを以て削除が確認できます。

## Plan of Work


### Milestone 1: Webhook失敗時の監視削除フローを確立する


この段階では、Webhookが全リトライ失敗した時にWorkerがGatewayに「監視削除」を依頼し、GatewayがDB削除とPod削除を行うまでの一本道を作ります。まず `internal/api/handlers.go` に内部API `POST /internal/v1/monitors/{monitor_id}/terminate` を追加し、リクエストボディには `reason`（例: `webhook_delivery_failed`）を含め、Validationはmonitor_idの形式のみで構いません。処理順序は、monitor_idが存在しない場合はHTTP 404ではなくHTTP 200で終了して内部呼び出しの冪等性を保ち、次に `repo.Delete(ctx, monitor_id)` でDBから監視ジョブを削除し、削除に失敗した場合は500を返します。その後、Reconcilerが存在する場合は `DeleteMonitorPod` を呼び出してPod削除を試み、失敗はログに残すがHTTPレスポンスは成功のままにします。

次に `internal/worker/callback.go` に `TerminateMonitor` メソッドを追加します。既存の `CallbackClient` をインターフェース化し、Workerから注入できるようにします。`TerminateMonitor(ctx, monitorID, reason)` は上記内部APIを呼び出し、非2xxはエラーとします。

最後に `internal/worker/worker.go` の `sendWebhook` で、送信失敗が確定した時に `TerminateMonitor` を呼びます。Webhook失敗時に`monitor.error`を送信しない要件を守るため、削除を優先し、通知は送らないことを明示します。失敗時の流れは「stateをErrorにし、内部APIで削除依頼を送る。削除依頼が成功すればWorkerは終了する」という形で統一します。

このマイルストーン完了時点で、Webhook失敗が監視削除に直結することをユニットテストで証明できる状態にします。

### Milestone 2: DASH（MPD）マニフェストの解析を実装する


この段階では、MPDを読み取り最新セグメントを得る最小実装を `internal/manifest/manifest.go` に追加します。新しい関数 `getLatestDASHSegment` を実装し、MPDはXMLなので `encoding/xml` を用いて構造体に読み込みます。対応範囲は `MPD > Period > AdaptationSet > Representation` における `SegmentTemplate` を前提とし、`SegmentTemplate` に `SegmentTimeline` がある場合はtimelineの最後のSエントリを計算して最後のセグメントの開始時刻（t）と継続時間（d）を求め、`r`（繰り返し回数）があれば最後の繰り返し分を含めて最後の開始時刻を計算します。`SegmentTimeline` が無い場合は `duration` と `timescale` と `startNumber` を使い、MPDの `mediaPresentationDuration` から総セグメント数を求めて最後の番号を算出し、durationが無い場合はエラーにします。

`SegmentTemplate` の `media` パターン文字列に含まれるプレースホルダは `$Number$`, `$Time$`, `$RepresentationID$`, `$Bandwidth$` の最低限に対応し、`$Number$` と `$Time$` のどちらを使うかはテンプレートに含まれるプレースホルダに従います。

BaseURLの解決は `MPD` または `Representation` の `BaseURL` が存在する場合にそれを優先し、なければMPDのURLからディレクトリ部分を基準に `net/url` で解決します。代表となるRepresentationは `bandwidth` が最大のものを選び、bandwidthが全て0の場合は最初のRepresentationを使います。返す `Segment` は `MediaType` を `dash` にし、`Duration` は秒単位のfloat64で設定します。

合わせて `internal/manifest/mpd_test.go` を追加し、`httptest.Server` でMPDサンプル（SegmentTimelineあり・なし）を返し、最新セグメントURLとdurationが期待値になることを確認します。MPDサンプルはテスト内の文字列で保持します。

### Milestone 3: Graceful Shutdownを要件通りに整備する


この段階では、SIGTERM時に「新規取得停止」「解析完了」「未送信Webhook送信」「クリーンアップ」の順序が成立するようにWorkerを修正します。`worker.Run` はコンテキストキャンセルを直接終了条件にせず、「shutdownRequested」フラグを立てる方式に変更します。`waitingMode` と `monitoringMode` のループはこのフラグを確認し、次の新規取得（マニフェスト更新やセグメント取得）を開始する前にループを抜けるようにします。一方、現在の解析サイクルが進行中であれば最後まで完了し、その中で発生したWebhookは通常通り送信されます。`gracefulShutdown` では、ステータス報告（`StatusStopped`）を一度送信し、Webhook送信中であれば完了を待つ短い待機（例: 5秒）を行い、最後に `CleanupMonitor` を実行します。

このマイルストーンの終了時点で、SIGTERMを送ると新規取得が止まり、進行中解析が完了してから停止することを確認できるようにします。ユニットテストでは、モックされた解析が完了するまでWorkerが戻らないことを確認します。

### Milestone 4: ドキュメントとテストの整合を取る


内部APIに新しいterminateエンドポイントを追加したため、`docs/requirements.md` の「Worker → API Gateway 状態同期」セクションに、削除要求の内部APIが存在することを追記します。DASH対応に関しては要件に沿っているため追記は不要ですが、サポート範囲（SegmentTemplateベース）を短く補足します。

テストは `go test ./...` を主とし、Webhook失敗削除のテストは `internal/worker/worker_test.go` に追加してWebhook送信が失敗した時に `TerminateMonitor` が呼ばれることをアサートします。DASH解析のテストは `internal/manifest` に追加してMPDサンプルから期待URLが生成されることを確認します。Graceful Shutdownのテストは `internal/worker` に追加してshutdown要求後に解析が完了することを確認します。

## Concrete Steps


作業ディレクトリは `/home/runner/work/youtube-stream-tracker/youtube-stream-tracker` とします。まず対象ファイルを確認します。

    pwd
    sed -n '1,240p' internal/worker/worker.go
    sed -n '1,200p' internal/worker/callback.go
    sed -n '1,240p' internal/api/handlers.go
    sed -n '1,260p' internal/manifest/manifest.go
    sed -n '1,200p' docs/requirements.md

Milestone 1の実装後、次のテストを実行します。

    go test ./internal/worker -run TestWebhookFailureDeletesJob

期待する出力は `ok   github.com/xpadev-net/youtube-stream-tracker/internal/worker` を含むことです。

Milestone 2の実装後、DASH解析テストを実行します。

    go test ./internal/manifest -run TestGetLatestSegmentDASH

期待する出力は `ok   github.com/xpadev-net/youtube-stream-tracker/internal/manifest` を含むことです。

Milestone 3の実装後、Worker全体のテストを実行します。

    go test ./internal/worker

最後に全体テストを行います。

    go test ./...

## Validation and Acceptance


Webhook失敗時の削除は、以下のユニットテストで人間が確認できる形にします。テストでは、Webhook送信が失敗するスタブSenderを使い、`CallbackClient` の `TerminateMonitor` が呼ばれたことをアサートします。テスト名は `TestWebhookFailureDeletesJob` とし、修正前は失敗し、修正後は成功することを示します。

DASH対応は、MPDサンプルを返す `httptest.Server` を使い、`GetLatestSegment` が `media` テンプレートから正しいURLを生成することを確認します。サンプルには `SegmentTimeline` を含め、最後のセグメントが選ばれることを検証します。

Graceful Shutdownは、解析に時間がかかるモックAnalyzerを使い、shutdown要求があっても進行中の解析が完了した後に停止することを確認します。ログには「shutdown requested」「analysis completed」「cleanup complete」が順に出るようにします。

受け入れ条件は次の3点です。Webhook全失敗後に監視ジョブが削除されること、DASHマニフェストが解析され最新セグメントを取得できること、SIGTERM後も解析完了とWebhook送信が行われた後にクリーンアップされることです。

## Idempotence and Recovery


内部APIのterminateは冪等にします。monitor_idが存在しない場合でも成功として扱い、再送しても安全です。DB削除はトランザクション内で行い、途中失敗時はログに残して再実行できるようにします。DASH解析はサンプルテストで固定入力を使うため、繰り返し実行しても同じ結果になります。Graceful Shutdownの待機は時間上限を設け、待機超過時はログを残して終了することで停止がぶら下がらないようにします。

## Artifacts and Notes


成功時に残すべき短い証拠は以下の通りです。

    go test ./internal/worker -run TestWebhookFailureDeletesJob
    ok   github.com/xpadev-net/youtube-stream-tracker/internal/worker 0.0xs

    go test ./internal/manifest -run TestGetLatestSegmentDASH
    ok   github.com/xpadev-net/youtube-stream-tracker/internal/manifest 0.0xs

    go test ./internal/worker -run TestGracefulShutdownCompletesAnalysis
    ok   github.com/xpadev-net/youtube-stream-tracker/internal/worker 0.0xs

    go test ./...
    ok   github.com/xpadev-net/youtube-stream-tracker/internal/api 0.0xs
    ok   github.com/xpadev-net/youtube-stream-tracker/internal/worker 0.0xs

## Interfaces and Dependencies


`internal/api/handlers.go` に新しいハンドラを定義します。ルートは `POST /internal/v1/monitors/{monitor_id}/terminate` で、認証は `X-Internal-API-Key` を必須とし、リクエストボディは `{"reason":"webhook_delivery_failed"}` を受け取ります。振る舞いはDBレコード削除（`repo.Delete`）とPod削除（`reconciler.DeleteMonitorPod`）を行い、成功時はHTTP 200を返す構成にします。

`internal/worker/callback.go` に `func (c *CallbackClient) TerminateMonitor(ctx context.Context, monitorID string, reason string) error` を追加します。

`internal/worker/worker.go` では、`WebhookSender` に失敗した場合 `TerminateMonitor` を呼び出す関数を挿入し、失敗時にstateをErrorにして即終了する流れを定義します。`CallbackClient` はインターフェース化し、ユニットテストでスタブを注入できるようにします。

`internal/manifest/manifest.go` では `getLatestDASHSegment` を実装し、`SegmentTemplate` と `SegmentTimeline` を最小対応します。XMLパース用の構造体は `internal/manifest/mpd.go` に追加し、`encoding/xml` を使用して実装します。外部ライブラリは追加しない方針です。

Change note: 2026-02-03 / Codex - ユーザー要望（Webhook失敗時の監視削除、DASH対応、Graceful Shutdown整備）に基づく新規ExecPlanを作成。
Change note: 2026-02-03 / GitHub Copilot - PLANS.mdの形式要件に合わせて見出し直後の空行、箇条書きの文章化、作業ディレクトリの記述を修正した。
Change note: 2026-02-03 / GitHub Copilot - 実装完了に伴いProgress/Decision/Artifacts/Outcomesを更新し、DASHテストをinline MPDに変更した旨を反映した。
