# 仕様準拠・安全性改善の実装修正 ExecPlan

このExecPlanは生きたドキュメントであり、作業の進行に合わせて Progress、Surprises & Discoveries、Decision Log、Outcomes & Retrospective を必ず最新状態に保つ。

このリポジトリには .agent/PLANS.md が含まれており、本ExecPlanはその要件に従って保守されなければならない。

## Purpose / Big Picture

この変更で、要件定義書（docs/requirements.md）に沿ったAPIとWorkerの挙動が完全に一致し、Kubernetes上のPod仕様、Webhookペイロード、内部API、レート制限などの仕様差分が解消される。加えて、セキュリティ上の重要リスク（SSRF、秘密情報の平文露出、タイミング攻撃、無制限読み込みなど）を抑止し、安定運用に必要な安全策が揃う。動作確認は、HTTP API のレスポンス形式、Webhookの署名検証、K8s Pod仕様、ユニットテストの追加を通して、人間が再現・目視できる形で確認できるようにする。

## Progress

- [x] (2026-02-02 00:00Z) z/reviews.md の指摘事項を整理し、ExecPlanのスコープを確定した。
- [ ] 実装対象の仕様差分とセキュリティ修正をファイル単位で洗い出し、変更点を計画に明記する。
- [ ] DBマイグレーション、内部API、K8s Pod仕様、Webhookペイロードの仕様差分を解消する。
- [ ] Workerの解析ループ、ポーリング、終了検出、リトライ、サーキットブレーカー等の挙動を要件通りに整える。
- [ ] セキュリティ修正（SSRF対策、Secret化、定数時間比較、読み込み制限）と安全性修正（FFmpegエラー、updated_at）を実装する。
- [ ] テストと手動検証を追加し、受け入れ条件を満たすことを確認する。

## Surprises & Discoveries

作業中に想定外の挙動や要件の解釈に影響する発見があれば、ここに証拠と共に短く記録する。

## Decision Log

- Decision: monitors.id のカラム長を 40 に修正し、requirements の該当箇所も同一値に整合させる。
  Rationale: monitor_id が mon- + UUID（ハイフン付き36文字）である以上、37は要件内で矛盾しており、実運用の実長は40であるため。
  Date/Author: 2026-02-02 / GPT-5.2

## Outcomes & Retrospective

ここにはマイルストーン完了時または全完了時に成果と残課題を記録する。

## Context and Orientation

このリポジトリは API Gateway と Worker に分かれており、Gateway が外部REST APIとKubernetes Pod管理を担当し、Workerが配信解析とWebhook送信を担当する。Gateway の外部APIは internal/api/handlers.go にあり、内部APIは同じ handlers.go の internal エンドポイントで実装されている。Kubernetes Podの作成と再整合は internal/k8s/k8s.go と internal/k8s/reconcile.go にある。Worker の主要な挙動は internal/worker/worker.go にあり、マニフェスト解析は internal/manifest/manifest.go、FFmpeg実行は internal/ffmpeg/ffmpeg.go、Webhook送信は internal/webhook/webhook.go、内部API呼び出しは internal/worker/callback.go にある。設定は internal/config/config.go、HTTPミドルウェアは internal/httpapi/middleware.go、エラーコードは internal/httpapi/errors.go に定義される。

ここで用いる「Webhook」とは、異常検知や状態遷移を外部に通知するHTTP POSTを指す。「内部API」とは Worker が Gateway に状態を送るための認証付きHTTP API を指す。「SSRF」とはユーザー入力のURLに対して内部ネットワークへアクセスできてしまう脆弱性を指す。

## Plan of Work

まず仕様差分を要件に合わせる。DBマイグレーションで monitors.id のカラム長を 40 に修正し、internal/api/handlers.go の内部APIのリクエストボディを health と statistics を含むネスト構造に変更する。statistics と health のフィールド名は requirements に合わせる。Kubernetes Pod仕様は internal/k8s/k8s.go で修正し、emptyDir の volume と /tmp/segments へのマウント、resources requests/limits、terminationGracePeriodSeconds、コンテナ名、Probeのタイムアウトと失敗閾値を明示する。PodのSecretは環境変数直書きをやめ、Secret参照で注入する設計に変更し、HelmのSecretテンプレートとvaluesにも反映する。

次に設定・エラーコード・レート制限を要件通りに整える。internal/config/config.go の環境変数名を DB_DSN と GATEWAY_RECONCILE_TIMEOUT に合わせつつ、既存の DATABASE_URL と RECONCILE_TIMEOUT は後方互換として読み取り可能にする。internal/httpapi/errors.go で INVALID_CONFIG, RATE_LIMIT_EXCEEDED, MAX_MONITORS_EXCEEDED を追加し、使用箇所を差し替える。レート制限は internal/httpapi/middleware.go で導入し、作成エンドポイントは 10/分、状態照会は 100/分の制限をかける。Goのレート制限ライブラリを利用し、IP単位またはAPI Key単位での制限を明記する。

Workerの挙動を要件通りに揃える。Waiting Mode のポーリング間隔を配信開始前30秒、予定時刻超過後10秒に切り替えるロジックを internal/worker/worker.go に実装し、設定値として外部化する。Monitoring Modeでは EXT-X-ENDLIST を最優先で終了検出し、5分間隔の is_live チェックを必ず実行する。解析ループのバックプレッシャーは、解析が完了するまで次のマニフェスト取得を行わない構造に修正する。alert.segment_error は一度だけ送るよう状態フラグを持ち、同一状態で再送しない。blackout/silence のWebhookペイロードに segment_info を追加し、stream.ended に data を付与する。再整合の monitor.error ペイロードは reconciliation_action, previous_status, observed_state を含む要件形にする。

安全性とセキュリティを修正する。internal/worker/worker.go の mutex unlock/re-lock を解消し、Webhook送信はロック外で実行する構造に改める。internal/manifest/manifest.go の FetchSegment は io.LimitReader を使って上限サイズを設け、サイズは設定可能とする。internal/httpapi/middleware.go の API Key 比較は crypto/subtle の定数時間比較に置き換える。SSRF対策として、monitor作成時の callback_url に対してホスト解決とIPレンジ検査を行い、予約済みアドレス帯を拒否する。さらに internal/webhook/webhook.go と internal/worker/callback.go の送信直前でも再検証し、DNSリバインディングに備える。internal/ffmpeg/ffmpeg.go は cmd.Run のエラーを評価し、失敗時は検出結果をエラーとして扱う。internal/db/monitor_repository.go の UpdateStatus は updated_at を更新する。internal/api/handlers.go の callback_url バリデーションは http/https のみに限定する。

上記変更に合わせて tests を追加する。internal/api/handlers_test.go に内部APIペイロードとcallback_urlの検証、internal/httpapi/middleware のレート制限と定数時間比較の動作、internal/manifest のサイズ上限、internal/worker のsegment_error単発送信、internal/k8s の Pod spec 生成（volume, resources, probe）をテストする。必要に応じてモックを追加し、再現可能な範囲でユニットテストと統合テストを増やす。

## Concrete Steps

作業前に現状を確認する。

    pwd
    git status

要件との差分を再確認する。

    sed -n '1,260p' docs/requirements.md
    sed -n '1,240p' internal/api/handlers.go
    sed -n '1,240p' internal/k8s/k8s.go
    sed -n '1,240p' internal/worker/worker.go
    sed -n '1,220p' internal/httpapi/middleware.go
    sed -n '1,220p' internal/manifest/manifest.go

ユニットテストを実行する。

    go test ./...

期待する観察結果は、既存テストが通ることと、追加テストの失敗が要件差分の未対応箇所に限定されること。

## Validation and Acceptance

受け入れ条件は以下の動作確認で満たす。

外部APIと内部APIのJSON形式が要件通りであること。具体的には、内部APIのボディが health と statistics を含むネスト構造であり、フィールド名が要件通りであることをテストで確認する。

Kubernetes Pod仕様が要件に一致すること。Pod の volume と volumeMount が /tmp/segments に付与され、resources が requests/limits を持ち、terminationGracePeriodSeconds が 30 であること。Probe の timeout と failureThreshold が設定されていること。コンテナ名が monitor であること。

Waiting Mode と Monitoring Mode の挙動が要件通りであること。Waiting Mode のポーリング間隔が 30秒と10秒で切り替わること、Monitoring Mode で 5分ごとの is_live チェックが行われること、EXT-X-ENDLIST が最優先で終了検出されること。解析ループで解析中に次のマニフェスト取得を行わないこと。

Webhookの署名とpayloadが要件に一致すること。blackout/silence で segment_info が含まれ、stream.ended が data を持つこと。再整合の monitor.error が reconciliation_action, previous_status, observed_state を含むこと。alert.segment_error が同一状態で1回のみ送信されること。

セキュリティ要件が満たされること。SSRF対策として private/reserved IP が拒否され、API Key 比較が定数時間であること。Webhook Signing Key と Internal API Key が Secret 経由で Pod に注入されること。

## Idempotence and Recovery

DBマイグレーションは再実行しても安全であることを確認する。Pod作成は既存Podがある場合に失敗してもGateway側で扱えるよう、再試行や削除が可能な手順を用意する。Webhook送信や内部API更新が失敗した場合も、次回ループで再送できるよう状態管理を壊さない。

## Artifacts and Notes

作業中に確認したログ、HTTPレスポンス例、kubectl get pod の抜粋などは短くここに残す。長いログは避け、成功判定に必要な数行だけを示す。

## Interfaces and Dependencies

internal/api/handlers.go では Internal Status Update の入力構造を requirements に一致させ、health と statistics の型を明示する。internal/httpapi/middleware.go では API Key 比較とレート制限を導入し、rate limiter は golang.org/x/time/rate か同等の標準的実装を使う。internal/manifest/manifest.go の FetchSegment は最大サイズを引数または config 経由で受け取れるようにする。internal/k8s/k8s.go は Secret参照を含む PodSpec を構築し、Helmテンプレートと values で Secret が生成されることを前提にする。internal/webhook/webhook.go と internal/worker/callback.go では SSRF対策のURL検証関数を共通化し、送信前に再検証する。

Change note: 2026-02-02 / GPT-5.2 - z/reviews.md の指摘事項を全て含む修正計画として初版を作成した。