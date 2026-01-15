# YouTube配信監視システム（API Gateway + Worker + PostgreSQL + Webhook）の実装 ExecPlan

このExecPlanは「生きたドキュメント」である。作業の進行に合わせて `Progress`、`Surprises & Discoveries`、`Decision Log`、`Outcomes & Retrospective` を必ず最新状態に保つ。

このリポジトリには `.agent/PLANS.md` が含まれており、本ExecPlanはその要件に従って保守されなければならない。

## Purpose / Big Picture

この変更で、利用者は YouTube の watch URL を1つ渡すだけで「配信開始忘れ」「黒画面」「無音」「セグメント取得エラー」を自動検出し、指定した Webhook に署名付きで通知できるようになる。システムは Kubernetes 上のマイクロサービスとして動作し、API Gateway が監視ジョブ（monitor）を作成・管理し、Worker が実際のストリーム取得と解析を行う。動作確認はローカル（Docker/Compose など）と Kubernetes（Kind/Minikube など）で再現でき、HTTP API と Webhook 送信ログにより人間が目視で「動いている」ことを確かめられる状態にする。

## Progress

- [ ] (2026-01-16) リポジトリの現状把握（既存コード・ビルド手順・CI有無・ディレクトリ構成）を行い、ExecPlan内の前提を確定する。
- [ ] (2026-01-16) Goプロジェクトの骨組み（`cmd/gateway`, `cmd/worker`, `internal/...`）と基本設定（ログ、設定読み込み、エラーハンドリング規約）を追加する。
- [ ] (2026-01-16) PostgreSQL スキーマとマイグレーションを追加し、監視状態（monitors / monitor_stats / monitor_events）が永続化されるようにする。
- [ ] (2026-01-16) API Gateway の外部REST API（要件: `/api/v1/monitors` CRUD、API Key認証、エラーレスポンス統一）を実装し、簡易E2Eで確認する。
- [ ] (2026-01-16) API Gateway の内部API（Worker→Gateway 状態同期）を実装し、署名/認証（`INTERNAL_API_KEY`）を含めて確認する。
- [ ] (2026-01-16) Worker の「Waiting Mode / Monitoring Mode」状態機械を実装し、yt-dlp と（フォールバックとして）streamlink でマニフェストURL取得ができることを確認する。
- [ ] (2026-01-16) Worker のセグメント取得と FFmpeg による blackdetect / silencedetect を実装し、検出結果が内部状態と統計に反映されることを確認する。
- [ ] (2026-01-16) Webhook 送信（HMAC署名、タイムスタンプ、指数バックオフ最大3回、タイムアウト10秒）を実装し、イベント履歴（monitor_events）を保存しながら確認する。
- [ ] (2026-01-16) Kubernetes 統合（GatewayがPodを create/delete/list/watch、Pod名/ラベル/環境変数の要件準拠）を実装し、Kind等で動作確認する。
- [ ] (2026-01-16) Helmチャート雛形とRBACを追加し、`helm install` でデプロイできる状態にする。
- [ ] (2026-01-16) 起動時再整合（ReconcileStartup）を実装し、DBとPodの不整合を解消できることをログとWebhookで確認する。
- [ ] (2026-01-16) 最低限のテスト（ユニット + 重要パスの統合）と、ローカル/Kindでの検証手順をこのExecPlanの「Concrete Steps」「Validation and Acceptance」に確定させる。

## Surprises & Discoveries

このセクションには、実装中に見つかった「想定外の挙動」や「要件解釈に影響する発見」を、証拠（ログ/テスト出力の抜粋）とセットで短く記録する。

記載例（テンプレート）:

Observation: （何が想定外だったかを1文で）
Evidence: （ログ/テスト出力を1〜5行で。長くしない）

## Decision Log

このセクションには、要件の曖昧さを解消するために行った意思決定を「決定内容・理由・日付/著者」の形で必ず残す。後から別の実装者が読んでも、なぜその選択になったのかが1回で理解できることをゴールにする。

記載例（テンプレート）:

Decision: （何を決めたか）
Rationale: （なぜその決定が要件と整合するのか）
Date/Author: （例: 2026-01-16 / GPT-5.2）

## Outcomes & Retrospective

（主要マイルストーン到達時または完了時に、何ができるようになったか・残課題・学びを追記）

## Context and Orientation

このリポジトリは現時点で要件定義書 `docs/requirements.md` が中心で、実装コードはこれから追加する前提とする。要件で定義された主要概念は以下。

監視ジョブ（monitor）とは、特定の YouTube watch URL 1件を継続的に解析し、異常（配信開始遅延、黒画面、無音、セグメント取得エラー）を検出して Webhook に通知する単位である。monitor には `monitor_id`（`mon-` + UUIDv7。ここでUUIDv7とは「時刻順ソートしやすい」UUIDの派生で、生成結果は英数字とハイフンからなる文字列）を割り当てる。`monitor_id` は Kubernetes のDNS-1123制約（ここでは「名前に使える記号はハイフンのみ」という制約）に合わせ、APIレスポンス、Pod名、環境変数、DBキーの全てで同一表記を使う。

API Gateway は外部クライアントからの REST API を提供し、PostgreSQL に状態を保存し、Kubernetes API を介して Worker Pod の作成・削除を行う。ここで Pod とは Kubernetes 上で動く最小の実行単位で、この計画では「1監視 = 1Pod」で Worker を動かす。Worker は yt-dlp/streamlink によりライブ配信のマニフェストURLを取得し、最新セグメントのみをダウンロードして FFmpeg で映像（blackdetect）と音声（silencedetect）を順次解析する（要件により並列実行しない）。異常発生時は Webhook にイベントを送信し、同時に内部APIで Gateway に状態を報告して DB の状態を一元化する。

実装上、要件で指定された外部ツールが必要になる。yt-dlp は「YouTube URL からストリーム（HLS/DASH）の再生リストURLを引く」ために使い、FFmpeg は「黒画面/無音を機械的に検出する」ために使う。streamlink は yt-dlp が失敗した場合のフォールバックとして使う。

このExecPlanでは、まずローカルで「Gateway + Worker + Postgres + Webhook受信デモ」が動くところまで作り、その後Kubernetes（Kind/MinikubeなどのローカルK8s環境）で同じ振る舞いを再現し、最後にHelm（Kubernetesリソースをまとめて配布する仕組み）/RBAC（権限設定）/再整合など運用要件を満たしていく。

## Plan of Work

この計画は「作っても動かない」状態を避けるため、常に人間が観察できる成果物を先に作る。各マイルストーンは独立に検証可能であることを必須とし、マイルストーンごとに「起動コマンド」「HTTPリクエスト例」「期待されるレスポンス/ログ」をこの文書に追記・更新する。ここで言う検証可能とは、テスト結果またはHTTPレスポンス、あるいはログのいずれかで第三者が確認できることを指す。

なお本書では、E2E（end-to-end）という用語を使う場合は「HTTPリクエスト等の入力から、永続化やWebhook送信等の出力までを通しで確認する最小の動作確認」を意味する。

### Milestone 1: プロジェクト土台（Goモジュール、共通設定、ログ、エラー形式）を作る

この段階のゴールは、Gateway と Worker がそれぞれ `go run` で起動し、`/healthz` と `/readyz` がHTTP 200を返すこと、そしてログがJSON形式で出ること。まだYouTube解析やDBは不要だが、後の拡張を見据えて `internal/` 配下に共通パッケージ（設定、ロガー、HTTPレスポンス、ID生成）を用意する。

このマイルストーンで、`cmd/gateway/main.go` と `cmd/worker/main.go` を追加し、共通部品として `internal/config`（環境変数の読み込み）、`internal/log`（zap等でJSONログ）、`internal/httpapi`（統一エラーレスポンス: `{"error":{"code":"...","message":"..."}}`）、`internal/ids`（`mon-` + UUIDv7生成。UUIDv7のライブラリ選定もここで確定）を定義する。

### Milestone 2: PostgreSQL スキーマと永続化（monitors / monitor_stats / monitor_events）を作る

この段階のゴールは、DBに monitor を作成/更新/一覧/取得できることを、Gateway のHTTP API から確認できることだ。要件のスキーマ（`docs/requirements.md` の「9. データストア仕様」）に準拠し、マイグレーションで再現可能にする。

ここで特に重要なのは、monitors.id が `mon-` + UUIDv7 であること、`idx_monitors_stream_url_active` 相当の「アクティブ監視のみ重複禁止」をDB制約として担保すること、そして monitor_events に Webhook 送信履歴（pending/sent/failed、試行回数、最後のエラー）が残ることだ。ここで「部分インデックス相当」とは、`status IN ('initializing','waiting','monitoring')` の行だけを対象にユニーク制約をかける、という意味である（要件のSQL例に合わせる）。

### Milestone 3: 外部REST API（作成/停止/状態取得/一覧）を実装する

この段階のゴールは、要件のAPI仕様（`POST /api/v1/monitors`, `DELETE /api/v1/monitors/{monitor_id}`, `GET /api/v1/monitors/{monitor_id}`, `GET /api/v1/monitors`）が動き、API Key認証が効き、重複監視で409が返り、エラーレスポンス形式が統一されていること。

ここではKubernetes Podはまだ作らなくてよい。まずDB上でステータス遷移（initializing/waiting/monitoring/completed/stopped/error）と、レスポンスのJSON形を固める。Pod管理を始めるのは次のマイルストーンにする。

### Milestone 4: 内部API（Worker→Gateway 状態同期）を実装する

この段階のゴールは、Worker が `PUT /internal/v1/monitors/{monitor_id}/status` を叩くと、Gateway が monitors / monitor_stats を更新できること。内部API Key（`INTERNAL_API_KEY`）を必須にし、外部API Keyとは別に運用できるようにする。

Worker はこの時点では「ダミーの状態報告」をするだけでよい。実際の解析結果を入れるのは後続のマイルストーンで行う。

### Milestone 5: Worker の Waiting Mode（配信開始待機）を実装する

この段階のゴールは、Worker に `STREAM_URL` を渡すと、yt-dlp で `--dump-json` 等を使って `is_live` を判定し、配信開始前は waiting として一定間隔でポーリングし、予定時刻を過ぎて許容時間を超えたら `stream.delayed` を送ること。

このマイルストーンでは「本物のYouTube URLでの検証」が難しい場合があるため、まずは yt-dlp 実行結果をモックできる薄い抽象（例: `internal/ytdlp`）を作り、ユニットテストで状態遷移を固定できるようにする。そのうえで、実環境検証は任意のURLで手順化する。

### Milestone 6: Worker の Monitoring Mode（最新セグメント解析）を実装する

この段階のゴールは、マニフェスト（HLS .m3u8 または DASH .mpd）を取得し、最新セグメントだけをダウンロードして、FFmpeg の blackdetect / silencedetect を順次実行し、連続時間を集計してしきい値超過でイベントを発火できること。要件どおり「並列実行しない」「解析がintervalを超えたら待機なしで次へ」を守る。

ここでの具体挙動は要件に固定される。ブラックアウトは連続黒画面時間が `blackout_threshold_sec` 以上で `alert.blackout` を発火し、復旧時に `alert.blackout_recovered` を発火する。無音は連続無音時間が `silence_threshold_sec` 以上で `alert.silence` を発火し、復旧時に `alert.silence_recovered` を発火する。セグメント取得失敗が60秒継続した場合は `alert.segment_error` を発火するが、`is_live=true` のときのみエラーとして扱い、`is_live=false` なら配信終了として扱う。一時ファイルは `/tmp/segments/{monitor_id}/` に置き、解析後に即削除する。

### Milestone 7: Webhook送信（署名・リトライ・履歴保存）を実装する

この段階のゴールは、異常イベントが Webhook に送られ、`X-Signature-256` と `X-Timestamp` が付与され、受信側で検証可能であること。失敗時は最大3回の指数バックオフで再試行し、最終失敗時は「監視ジョブを削除（monitor.errorは発火しない）」という要件どおりの挙動になること。併せて `monitor_events` に payload と送信状態が保存されること。

ここではローカル検証を確実にするため、リポジトリ内に「Webhook受信デモ（署名検証してログ出すだけの小さなHTTPサーバ）」を用意し、送受信が手元で観察できるようにする。本番のHelmデプロイには含めない想定だが、検証用としてリポジトリには残す。

### Milestone 8: Kubernetes 統合（GatewayがWorker Podを作成・削除）を実装する

この段階のゴールは、`POST /api/v1/monitors` を呼ぶと Gateway が Kubernetes API を通して Worker Pod を作り、`DELETE /api/v1/monitors/{monitor_id}` で Pod を削除できること。Pod仕様は要件の `8.1 Pod仕様` に準拠し、Pod名とラベル、環境変数が一致していることを確認する。

ここで満たすべき要件は明確に固定される。Pod名は `stream-monitor-{monitor_id}` の形式にし、ラベルは `app=stream-monitor` と `monitor-id={monitor_id}` を付ける。環境変数として `MONITOR_ID`, `STREAM_URL`, `CALLBACK_URL`, `CONFIG_JSON` を必須で渡し、`HTTP_PROXY/HTTPS_PROXY` は任意で渡せるようにする。Podの `restartPolicy` は `OnFailure` とする。

### Milestone 9: Helm/RBAC と、起動時再整合（ReconcileStartup）を実装する

この段階のゴールは、Helmチャートで Gateway（Deployment）と必要リソース（Service, ConfigMap/Secret, ServiceAccount, Role/RoleBinding）が作成できること、そして Gateway 再起動時に DB の `monitoring` と K8s 上の Pod の不整合を検知して解消できること。

再整合の要件（`docs/requirements.md` 10.4）で重要なのは「冪等」「タイムアウト」「Missing/Zombie/Orphaned の扱い」「部分失敗でもGateway起動をブロックしない」。

このマイルストーンで、再整合時の `monitor.error` Webhook ペイロード（reasonやobserved_state含む）も要件に沿って送れるようにする。ただし「Webhook送信先が無効な場合は errorイベントも飛ばさずジョブ削除」という別要件との整合も必要なので、再整合の error 通知は「送れたら送るが、送れない場合の振る舞い」を明確に決め、Decision Log に記録する。

## Concrete Steps

このセクションは、実装が進むたびに「その時点で動く最短コマンド」に更新する。現時点ではリポジトリに実装コードが無い前提のため、まず Milestone 1 完了後に以下の形が成立する状態を目指す。

Gateway はリポジトリルートから次のコマンドで起動できるようにする。

    (cd /Users/xpadev/IdeaProjects/youtube-stream-tracker && go run ./cmd/gateway)

期待する観察結果は、標準出力にJSONログが出て、`GET /healthz` が 200 を返すことだ。

Worker（ダミー実装の段階）は、リポジトリルートから次のコマンドで起動できるようにする。

    (cd /Users/xpadev/IdeaProjects/youtube-stream-tracker && MONITOR_ID=mon-... STREAM_URL=... CALLBACK_URL=... go run ./cmd/worker)

期待する観察結果は、起動ログが出て、内部APIへの状態送信（Milestone 4以降）が観察できることだ。

Milestone 2 以降は、`docker compose up`（Postgres + Gateway + webhook-demo）や `kind create cluster` 等の具体コマンドをここに追記し、期待するHTTPレスポンス例（`curl`）を短く添える。出力例はこの文書内にインデントで示し、複数のコードフェンスは使わない（この文書自体がExecPlanであり、`.agent/PLANS.md` の指示に従う）。

## Validation and Acceptance

受け入れ条件は「人間が観察できる挙動」で定義する。

Milestone 3（外部API）完了の受け入れ例。

API Key なしの `POST /api/v1/monitors` が 401 を返すこと。正しいAPI Key で `POST /api/v1/monitors` を呼ぶと 201（または200）相当で `monitor_id` と `status=initializing` を返すこと。同一 `stream_url` でアクティブ監視がある場合は 409 を返し、エラーボディは要件の形式（`error.code=DUPLICATE_MONITOR` 等）であること。`GET /api/v1/monitors/{monitor_id}` で health/statistics が返り、JSON形が要件の例に整合すること。

Milestone 7（Webhook）完了の受け入れ例。

ローカルの webhook-demo が `X-Signature-256` と `X-Timestamp` を検証し、成功ログを出すこと。Webhook送信失敗時に最大3回のリトライが行われ、`monitor_events.webhook_attempts` が増えること。全リトライ失敗時に、要件通り「ジョブ削除（monitor.errorは発火しない）」が行われること。なお、この“削除”が DBのレコード削除なのか、`stopped/error` への状態遷移なのかは実装で決め、Decision Log に理由付きで固定する（要件文言と矛盾しないことを必須とする）。

Milestone 8/9（K8s/Helm/再整合）完了の受け入れ例。

Kind（またはMinikube）にデプロイし、`POST /api/v1/monitors` で Pod が作られ、Pod の env/labels が要件通りであること。Gateway を再起動しても、DBが `monitoring` なのにPodが無い状態を検出し、要件の `monitor.error` を送れること（送れない場合の扱いはDecision Logで明確化し、少なくともGateway起動がブロックされないこと）。

## Idempotence and Recovery

この計画で行う全コマンドは、原則として複数回実行しても安全である必要がある。特に `POST /api/v1/monitors` の重複防止（DBの「アクティブ監視のみユニーク」制約と、アプリ側の409整形）、Kubernetes Pod の create/delete（既に存在/既に削除済みを安全に扱う）、Gateway 起動時の再整合（途中失敗しても次回起動で再実行できる）は繰り返し実行されやすいため、冪等性（同じ操作を何度やっても最終状態が同じである性質）を設計に組み込む。

リカバリ方針。

マイグレーションは「適用済みなら何もしない」方式にする。Webhook 送信は retry を持つが、最終失敗時に監視を削除するため、失敗が連鎖しないようにする。Worker 停止（SIGTERM）時は「新規取得停止→解析完了→未送信Webhook送信→一時ファイル削除→終了」を守る（要件 8.3）。

## Artifacts and Notes

実装が進んだら、このセクションに「最小の証拠」を残す。たとえば、`curl` で monitor を作成した時のレスポンス抜粋、webhook-demo が署名検証に成功したログ1行、Kind上で作成された Pod の `kubectl get pod -o yaml` の必要部分（名前、labels、env）だけ、のように「人間が見て動作を確かめられる断片」を短く貼る。

## Interfaces and Dependencies

外部I/Fは要件に固定される。外部REST APIは `POST /api/v1/monitors`（監視開始）、`DELETE /api/v1/monitors/{monitor_id}`（監視停止）、`GET /api/v1/monitors/{monitor_id}`（状態取得）、`GET /api/v1/monitors`（一覧）からなる。内部API（Worker→Gateway）は `PUT /internal/v1/monitors/{monitor_id}/status` とし、ヘッダ `X-Internal-API-Key: {INTERNAL_API_KEY}` を必須とする。Webhook送信時は `X-Signature-256: sha256=<hex>` と `X-Timestamp: <unix seconds>` を付与し、署名は `HMAC-SHA256(WEBHOOK_SIGNING_KEY, "{timestamp}.{request_body}")` により生成する。送信失敗時は最大3回、1秒・2秒・4秒の指数バックオフで再試行し、1回のHTTPタイムアウトは10秒とする。

依存関係は、要件に明記されたGoライブラリを初期採用とする。HTTPフレームワークは `github.com/gin-gonic/gin v1.10.0`、PostgreSQLクライアントは `github.com/jackc/pgx/v5 v5.7.2`、Kubernetesクライアントは `k8s.io/client-go v0.32.0`、ログは `go.uber.org/zap v1.27.0` を使う。HLSマニフェスト解析は `github.com/grafov/m3u8 v0.12.1` を使い、DASH解析は必要になった時点で追加する。

最後に、このExecPlanは実装が進むたびに更新されるべき「生きた仕様書」である。各マイルストーンの完了時に Progress を更新し、決定事項は Decision Log に残し、想定外の挙動は Surprises & Discoveries に証拠付きで記録する。

（変更履歴: 2026-01-16 / GPT-5.2: 初版を `docs/requirements.md` に基づき作成。ローカルで観察可能な成果を先に作る方針でマイルストーン化。）
